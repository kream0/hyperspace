//! One WebSocket link to the relay: connect (DNS, TCP, TLS, upgrade),
//! authenticate, and the writer that empties the outgoing queue.

use std::time::Duration;

use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use hyperspace_proto::relay::{self, refused, Msg, Role, RoomKey};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::{self, Bytes, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

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
    /// The relay pings an idle link every 20 s: a link silent for this long
    /// is dead.
    pub idle_timeout: Duration,
    /// A link that stayed up this long resets the backoff.
    pub stable: Duration,
}

impl Default for Timing {
    fn default() -> Timing {
        Timing {
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
            refused_wait: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(60),
            stable: Duration::from_secs(30),
        }
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
    // 0.8 .. 1.2
    let factor = 0.8 + 0.4 * (f64::from(r) / f64::from(u16::MAX));
    d.mul_f64(factor)
}

/// Why a link could not be set up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// DNS, TCP, TLS, HTTP or the relay protocol: one line saying which.
    Unreachable(String),
    /// The relay answered REFUSED with this reason.
    Refused(u8),
}

/// DNS, TCP (each address in turn), TLS for wss://, then the WebSocket
/// upgrade. Each step has its own timeout and its own error text.
pub async fn open(url: &RelayUrl) -> Result<Ws, String> {
    let host = url.host();
    let port = url.port();
    let addrs: Vec<_> = match timeout(CONNECT_TIMEOUT, tokio::net::lookup_host((host, port))).await {
        Ok(Ok(a)) => a.collect(),
        Ok(Err(e)) => return Err(format!("cannot resolve {host}: {e}")),
        Err(_) => return Err(format!("cannot resolve {host}: no answer within {} s", CONNECT_TIMEOUT.as_secs())),
    };
    if addrs.is_empty() {
        return Err(format!("cannot resolve {host}: no address found"));
    }
    let mut last = String::new();
    let mut tcp = None;
    for addr in &addrs {
        match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                tcp = Some(s);
                break;
            }
            Ok(Err(e)) => last = format!("cannot connect to {host} port {port} ({}): {e}", addr.ip()),
            Err(_) => last = format!("cannot connect to {host} port {port} ({}): timed out", addr.ip()),
        }
    }
    let Some(tcp) = tcp else { return Err(last) };
    let _ = tcp.set_nodelay(true);

    let stream = if url.tls() {
        let connector = tokio_native_tls::native_tls::TlsConnector::new()
            .map_err(|e| format!("cannot set up TLS on this machine: {e}"))?;
        let connector = tokio_native_tls::TlsConnector::from(connector);
        match timeout(CONNECT_TIMEOUT, connector.connect(host, tcp)).await {
            Ok(Ok(tls)) => MaybeTlsStream::NativeTls(tls),
            Ok(Err(e)) => return Err(format!("TLS handshake with {host} failed: {e}")),
            Err(_) => return Err(format!("TLS handshake with {host} timed out")),
        }
    } else {
        MaybeTlsStream::Plain(tcp)
    };

    let config = WebSocketConfig::default().max_message_size(Some(MAX_WS_MESSAGE)).max_frame_size(Some(MAX_WS_MESSAGE));
    match timeout(CONNECT_TIMEOUT, tokio_tungstenite::client_async_with_config(url.to_string(), stream, Some(config))).await {
        Ok(Ok((ws, _))) => Ok(ws),
        Ok(Err(tungstenite::Error::Http(response))) => {
            Err(format!("the server at {url} answered HTTP {} instead of opening a WebSocket", response.status()))
        }
        Ok(Err(e)) => Err(format!("WebSocket upgrade with {host} failed: {e}")),
        Err(_) => Err(format!("WebSocket upgrade with {host} timed out")),
    }
}

/// The next binary message; pings, pongs and text are skipped.
pub async fn next_binary(ws: &mut Ws) -> Result<Bytes, String> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(b))) => return Ok(b),
            Some(Ok(Message::Close(frame))) => return Err(format!("the relay closed the connection{}", close_text(&frame))),
            Some(Ok(_)) => {}
            Some(Err(e)) => return Err(format!("connection to the relay failed: {e}")),
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
    let mut ws = open(url).await.map_err(Failure::Unreachable)?;
    let auth = async {
        let nonce = challenge(&mut ws).await.map_err(Failure::Unreachable)?;
        let hello = Msg::Hello(room.hello(role, &nonce)).encode();
        ws.send(Message::binary(hello))
            .await
            .map_err(|e| Failure::Unreachable(format!("cannot write to the relay: {e}")))?;
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

/// Writes queued messages in batches until a write fails or stalls; returns
/// why it stopped.
pub async fn writer(mut sink: SplitSink<Ws, Message>, rx: Rx) -> String {
    loop {
        let first = rx.recv().await;
        let batch = async {
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
            Ok(Err(e)) => return format!("cannot write to the relay: {e}"),
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
