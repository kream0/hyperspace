//! One WebSocket link to the relay: connect (DNS, TCP, TLS, upgrade),
//! authenticate, and the writer that empties the outgoing queue and pings.

use std::time::Duration;

use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use hyperspace_proto::relay::{self, refused, Msg, Role, RoomKey};
use tokio::net::TcpStream;
use tokio::time::{timeout, MissedTickBehavior};
use tokio_tungstenite::tungstenite::error::ProtocolError;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::{self, Bytes, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::errors;
use crate::queue::Rx;
use crate::url::RelayUrl;

pub type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// For each step of opening a link: DNS, each TCP connect, TLS, upgrade.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// For the relay's challenge and its answer to HELLO.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// A write the relay does not take within this time ends the link.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Relay messages are at most [`relay::MAX_MESSAGE`] bytes; anything much
/// larger is not from a relay.
const MAX_WS_MESSAGE: usize = 64 * 1024;
/// Messages written before each flush.
const BATCH: usize = 64;

/// Waits and limits of the reconnect loops; tests shorten them.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    /// After a refusal that will not go away by itself, or after another host
    /// took the room.
    pub refused_wait: Duration,
    /// The bridge pings the relay this often, whatever else it sends, so that
    /// every proxy on the way sees traffic both ways.
    pub ping_interval: Duration,
    /// Nothing at all from the relay (data, ping or pong) for this long: the
    /// link is dead, even if TCP has not noticed. The relay answers each ping
    /// and pings every 20 s itself.
    pub idle_timeout: Duration,
    /// A link that stayed up this long resets the backoff.
    pub stable: Duration,
}

impl Timing {
    /// The host keeps one link up for days: no hurry, and no storm of
    /// reconnects from many hosts after a relay restart.
    pub fn host() -> Timing {
        Timing {
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
            refused_wait: Duration::from_secs(60),
            ping_interval: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(35),
            stable: Duration::from_secs(30),
        }
    }

    /// The client has a live session waiting on the link: 0.25 s, 0.5 s,
    /// 1 s, 2 s, 4 s, then every 5 s.
    pub fn client() -> Timing {
        Timing {
            backoff_min: Duration::from_millis(250),
            backoff_max: Duration::from_secs(5),
            refused_wait: Duration::from_secs(60),
            ping_interval: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(35),
            stable: Duration::from_secs(10),
        }
    }
}

/// `35 s`, `742 s`, `0.6 s`: for log lines and close reasons.
pub fn secs(d: Duration) -> String {
    let s = d.as_secs_f64();
    if s >= 10.0 {
        format!("{s:.0} s")
    } else {
        let text = format!("{s:.1}");
        format!("{} s", text.strip_suffix(".0").unwrap_or(&text))
    }
}

/// Exponential backoff with jitter, so that hosts and clients cut off at the
/// same moment do not all come back at the same moment.
pub struct Backoff {
    min: Duration,
    max: Duration,
    next: Duration,
}

impl Backoff {
    pub fn new(t: &Timing) -> Backoff {
        Backoff { min: t.backoff_min, max: t.backoff_max, next: t.backoff_min }
    }

    pub fn next(&mut self) -> Duration {
        let base = self.next;
        self.next = (self.next * 2).min(self.max);
        jitter(base)
    }

    pub fn reset(&mut self) {
        self.next = self.min;
    }
}

/// `d` plus or minus up to 20 %.
pub fn jitter(d: Duration) -> Duration {
    let mut b = [0u8; 2];
    let r = if getrandom::fill(&mut b).is_ok() { u16::from_le_bytes(b) } else { 0x8000 };
    spread(d, r)
}

/// `d` times a factor that goes from 0.8 (`r` = 0) to 1.2 (`r` = 65535),
/// rounded to the nanosecond. In integers, so that the bounds are exact.
pub(crate) fn spread(d: Duration, r: u16) -> Duration {
    const STEPS: u128 = u16::MAX as u128;
    let den = 5 * STEPS;
    let nanos = (d.as_nanos() * (4 * STEPS + 2 * u128::from(r)) + den / 2) / den;
    let secs = u64::try_from(nanos / 1_000_000_000).unwrap_or(u64::MAX);
    Duration::new(secs, (nanos % 1_000_000_000) as u32)
}

/// Why a link could not be set up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// DNS, TCP, TLS, HTTP or the relay protocol: one line saying which.
    Unreachable(String),
    /// The relay answered the upgrade with HTTP 503: it has as many links as
    /// it takes. Retried with backoff.
    Busy,
    /// The relay answered REFUSED with this reason.
    Refused(u8),
}

impl From<String> for Failure {
    fn from(why: String) -> Failure {
        Failure::Unreachable(why)
    }
}

/// DNS, TCP (each address in turn), TLS for wss://, then the WebSocket
/// upgrade. Each step has its own timeout and its own error text. Never
/// [`Failure::Refused`].
pub async fn open(url: &RelayUrl) -> Result<Ws, Failure> {
    let host = url.host();
    let port = url.port();
    let addrs: Vec<_> = match timeout(CONNECT_TIMEOUT, tokio::net::lookup_host((host, port))).await {
        Ok(Ok(a)) => a.collect(),
        Ok(Err(e)) => return Err(format!("cannot resolve {host}: {}", errors::plain(e)).into()),
        Err(_) => return Err(format!("cannot resolve {host}: no answer within {} s", CONNECT_TIMEOUT.as_secs()).into()),
    };
    if addrs.is_empty() {
        return Err(format!("cannot resolve {host}: no address found").into());
    }
    let mut last = String::new();
    let mut tcp = None;
    for addr in &addrs {
        match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                tcp = Some(s);
                break;
            }
            Ok(Err(e)) => last = errors::connect_error(host, port, addr, &e.to_string()),
            Err(_) => last = errors::connect_error(host, port, addr, "timed out"),
        }
    }
    let Some(tcp) = tcp else { return Err(last.into()) };
    let _ = tcp.set_nodelay(true);

    let stream = if url.tls() {
        let connector = tokio_native_tls::native_tls::TlsConnector::new().map_err(|e| {
            let detail = errors::detail(&e.to_string(), &format!("{e:?}"));
            format!("cannot set up secure connections on this computer{detail}")
        })?;
        let connector = tokio_native_tls::TlsConnector::from(connector);
        match timeout(CONNECT_TIMEOUT, connector.connect(host, tcp)).await {
            Ok(Ok(tls)) => MaybeTlsStream::NativeTls(tls),
            Ok(Err(e)) => return Err(errors::tls_error(host, port, &e.to_string(), &format!("{e:?}")).into()),
            Err(_) => return Err(format!("secure connection to {host} timed out").into()),
        }
    } else {
        MaybeTlsStream::Plain(tcp)
    };

    let config = WebSocketConfig::default().max_message_size(Some(MAX_WS_MESSAGE)).max_frame_size(Some(MAX_WS_MESSAGE));
    match timeout(CONNECT_TIMEOUT, tokio_tungstenite::client_async_with_config(url.to_string(), stream, Some(config))).await {
        Ok(Ok((ws, _))) => Ok(ws),
        Ok(Err(tungstenite::Error::Http(response))) if response.status().as_u16() == 503 => Err(Failure::Busy),
        Ok(Err(tungstenite::Error::Http(response))) => Err(errors::http_answer(url, response.status()).into()),
        Ok(Err(e)) => Err(format!("WebSocket upgrade with {host} failed: {}", errors::clean(&e.to_string())).into()),
        Err(_) => Err(format!("WebSocket upgrade with {host} timed out").into()),
    }
}

/// A read error, in a line a user can act on.
pub fn read_error(e: &tungstenite::Error) -> String {
    match e {
        tungstenite::Error::Protocol(ProtocolError::ResetWithoutClosingHandshake) => {
            "the connection was cut without a close frame".into()
        }
        tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => {
            "the relay closed the connection".into()
        }
        tungstenite::Error::Io(e) => format!("network error: {}", errors::clean(&e.to_string())),
        e => format!("connection to the relay failed: {}", errors::clean(&e.to_string())),
    }
}

fn write_error(e: &tungstenite::Error) -> String {
    format!("cannot write to the relay: {}", errors::clean(&e.to_string()))
}

/// The next binary message; pings, pongs and text are skipped.
pub async fn next_binary(ws: &mut Ws) -> Result<Bytes, String> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(b))) => return Ok(b),
            Some(Ok(Message::Close(frame))) => return Err(format!("the relay closed the connection{}", close_text(&frame))),
            Some(Ok(_)) => {}
            Some(Err(e)) => return Err(read_error(&e)),
            None => return Err("the relay closed the connection".into()),
        }
    }
}

/// Reads the relay's CHALLENGE; returns its nonce.
pub async fn challenge(ws: &mut Ws) -> Result<[u8; relay::NONCE_LEN], String> {
    let first = next_binary(ws).await?;
    match Msg::decode(&first) {
        Some(Msg::Challenge { version, nonce }) if version == relay::VERSION => Ok(nonce),
        Some(Msg::Challenge { version, .. }) => {
            Err(format!("the relay speaks protocol v{version}, this program speaks v{}", relay::VERSION))
        }
        _ => Err("the server did not send a relay challenge (is this a hyperspace relay?)".into()),
    }
}

/// Opens a link and authenticates as `role` in the room of `room`.
pub async fn connect(url: &RelayUrl, room: &RoomKey, role: Role) -> Result<Ws, Failure> {
    let mut ws = open(url).await?;
    let auth = async {
        let nonce = challenge(&mut ws).await.map_err(Failure::Unreachable)?;
        let hello = Msg::Hello(room.hello(role, &nonce)).encode();
        ws.send(Message::binary(hello))
            .await
            .map_err(|e| Failure::Unreachable(write_error(&e)))?;
        let answer = next_binary(&mut ws).await.map_err(Failure::Unreachable)?;
        match Msg::decode(&answer) {
            Some(Msg::Ok) => Ok(()),
            Some(Msg::Refused(reason)) => Err(Failure::Refused(reason)),
            _ => Err(Failure::Unreachable("the relay answered HELLO with something unexpected".into())),
        }
    };
    let answer = timeout(AUTH_TIMEOUT, auth).await;
    match answer {
        Ok(Ok(())) => Ok(ws),
        Ok(Err(f)) => Err(f),
        Err(_) => Err(Failure::Refused(refused::TIMEOUT)),
    }
}

/// Writes queued messages in batches, and a ping every `ping`, until a
/// write fails or stalls; returns why it stopped.
pub async fn writer(mut sink: SplitSink<Ws, Message>, rx: Rx, ping: Duration) -> String {
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + ping, ping);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        // Only the waits race; whatever was taken off the queue is written.
        let first = tokio::select! {
            msg = rx.recv() => Some(msg),
            _ = tick.tick() => None,
        };
        let batch = async {
            let Some(first) = first else {
                return sink.send(Message::Ping(Bytes::new())).await;
            };
            sink.feed(Message::binary(first)).await?;
            for _ in 1..BATCH {
                match rx.try_recv() {
                    Some(msg) => sink.feed(Message::binary(msg)).await?,
                    None => break,
                }
            }
            sink.flush().await?;
            Ok::<(), tungstenite::Error>(())
        };
        match timeout(WRITE_TIMEOUT, batch).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return write_error(&e),
            Err(_) => return format!("the relay took no data for {} s", WRITE_TIMEOUT.as_secs()),
        }
    }
}

/// `" (code 1008: refused)"`, or nothing without a close frame.
pub fn close_text(frame: &Option<CloseFrame>) -> String {
    match frame {
        Some(f) if f.reason.is_empty() => format!(" (code {})", u16::from(f.code)),
        Some(f) => format!(" (code {}: {})", u16::from(f.code), sanitize(f.reason.as_str())),
        None => String::new(),
    }
}

/// Text from the network, made safe for a log line.
pub fn sanitize(s: &str) -> String {
    s.chars().take(120).map(|c| if c.is_control() { '?' } else { c }).collect()
}

/// True if the close frame says another host took the room.
pub fn is_replaced(frame: &Option<CloseFrame>) -> bool {
    matches!(frame, Some(f) if u16::from(f.code) == relay::close::REPLACED)
}

/// True if the close frame says the host let this client go (1000 "closed by
/// the host", sent to clients only). Another normal close, from a proxy say,
/// is a lost link.
pub fn is_closed_by_host(frame: &Option<CloseFrame>) -> bool {
    matches!(frame, Some(f) if u16::from(f.code) == relay::close::CLOSED_BY_HOST
        && f.reason.as_str() == relay::close::CLOSED_BY_HOST_REASON)
}

/// Errors on a UDP socket that do not mean the socket is broken: an ICMP
/// "port unreachable" reported on the next call (Windows), or no data.
pub fn transient(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(e.kind(), ConnectionReset | ConnectionRefused | WouldBlock | Interrupted)
}

/// Remembers the last message logged so a loop that keeps failing the same
/// way logs it once.
#[derive(Default)]
pub struct Quiet(Option<String>);

impl Quiet {
    /// True if `line` differs from the last one (and remembers it).
    pub fn changed(&mut self, line: &str) -> bool {
        if self.0.as_deref() == Some(line) {
            return false;
        }
        self.0 = Some(line.to_string());
        true
    }

    pub fn clear(&mut self) {
        self.0 = None;
    }
}
