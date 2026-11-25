//! The client's end: a loopback UDP address that stands for the host. What
//! the client sends there goes through the relay to the host, and the host's
//! answers come back from it.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::StreamExt;
use hyperspace_proto::log;
use hyperspace_proto::relay::{self, refused, Msg, Role, RoomKey};
use hyperspace_proto::secure::Key;
use tokio::net::UdpSocket;
use tokio::sync::{watch, Notify};
use tokio_tungstenite::tungstenite::{self, Message};

use crate::errors;
use crate::link::{self, jitter, secs, Backoff, Failure, Stop, Timing, Ws};
use crate::queue;
use crate::RelayUrl;

const UDP_BUFFER: usize = 1 << 20;
/// Refusals that usually clear up soon (TIMEOUT, ROOM_FULL, RELAY_FULL) are
/// retried with the backoff this many times in a row, then slowly.
const QUICK_RETRIES: u32 = 5;
/// How long the line saying that a host which was online went offline waits
/// before it is printed (the status changes at once). A host that ends the
/// session goes offline at the relay right after its goodbye, and a client
/// that is exiting closes the link within this time: printed then, the line
/// would read like the start of a reconnect. Longer than the client's pause
/// before it closes the link after a relayed session.
const OFFLINE_LINE_HOLD: Duration = Duration::from_secs(1);

/// Where the link to the relay stands, in words a user can act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// First attempt under way, or a new one after [`ClientBridge::reconnect`].
    Connecting,
    /// DNS, TCP, TLS, the HTTP upgrade, or a link that was lost: one line
    /// saying which. Retried with backoff.
    CannotReach(String),
    /// The relay answered HTTP 503: it has as many connections as it takes.
    /// Retried with backoff.
    RelayBusy,
    /// The relay refused this client (a [`refused`] reason). Retried: soon
    /// for a full room or relay or a slow authentication (every minute after
    /// five of those in a row), every minute otherwise.
    Refused(u8),
    /// Connected; the host is not connected to the relay.
    HostOffline,
    /// Connected, and the host is too.
    HostOnline,
    /// The host closed this client's connection through the relay. Not
    /// retried until [`ClientBridge::reconnect`] is called.
    ClosedByHost,
    /// The bridge stopped for good (its local socket failed).
    Closed(String),
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Status::Connecting => f.write_str("connecting to the relay"),
            Status::CannotReach(why) => write!(f, "cannot reach the relay: {why}"),
            Status::RelayBusy => f.write_str("the relay is busy; retrying"),
            Status::Refused(reason) => write!(f, "the relay refused the connection: {}", refused::describe(*reason)),
            Status::HostOffline => f.write_str("connected to the relay; the host is offline"),
            Status::HostOnline => f.write_str("connected to the relay; the host is online"),
            Status::ClosedByHost => f.write_str("the host closed this connection through the relay"),
            Status::Closed(why) => write!(f, "relay link stopped: {why}"),
        }
    }
}

/// Counters of the link to the relay, for diagnostics. Datagram counts and
/// bytes are the client's own datagrams (not the relay's framing), and they
/// add up across reconnects.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkStats {
    /// When the current link came up (authenticated); None while it is down.
    pub connected_since: Option<Instant>,
    /// Links that came up after the first one.
    pub reconnects: u64,
    /// Datagrams (and their bytes) the relay brought from the host.
    pub datagrams_in: u64,
    pub bytes_in: u64,
    /// Datagrams (and their bytes) the client sent that went onto the link.
    pub datagrams_out: u64,
    pub bytes_out: u64,
    /// Datagrams dropped while the link was up: from the client, over
    /// [`relay::MAX_PAYLOAD`] or with the queue to the relay full; to the
    /// client, with its socket buffer full. Also, link up or not, every
    /// datagram from a socket other than the first one that sent to the
    /// bridge.
    pub dropped: u64,
    /// Datagrams the client sent while there was no link (connecting, or
    /// waiting to reconnect). Lost too, but to an outage, not congestion.
    pub discarded_while_down: u64,
    /// Why the last link that was up ended, in one line: a close code and
    /// reason, "no traffic for 35 s", a network or TLS error, and so on.
    pub last_close: Option<String>,
}

#[derive(Default)]
struct Counters {
    datagrams_in: AtomicU64,
    bytes_in: AtomicU64,
    datagrams_out: AtomicU64,
    bytes_out: AtomicU64,
    dropped: AtomicU64,
    discarded_while_down: AtomicU64,
}

fn bump(counter: &AtomicU64, by: u64) {
    counter.fetch_add(by, Ordering::Relaxed);
}

#[derive(Default)]
struct LinkState {
    connected_since: Option<Instant>,
    reconnects: u64,
    last_close: Option<String>,
}

struct Shared {
    status: Mutex<Status>,
    hosts_seen: AtomicU64,
    link: Mutex<LinkState>,
    counters: Counters,
    /// Calls to [`ClientBridge::reconnect`], and the wakeup for them.
    reconnects_asked: AtomicU64,
    reconnect: Notify,
    /// The status lines printed and when, for the tests.
    #[cfg(test)]
    lines: Mutex<Vec<(Instant, String)>>,
}

impl Shared {
    fn lock_status(&self) -> MutexGuard<'_, Status> {
        self.status.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock_link(&self) -> MutexGuard<'_, LinkState> {
        self.link.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Sets the status, logging it if it changed.
    fn set(&self, status: Status) {
        let mut s = self.lock_status();
        if *s != status {
            self.note(&status);
            *s = status;
        }
    }

    /// Logs a status line.
    fn note(&self, status: &Status) {
        log!("relay: {status}");
        #[cfg(test)]
        self.lines.lock().unwrap_or_else(|e| e.into_inner()).push((Instant::now(), format!("relay: {status}")));
    }

    /// Sets the status without a log line (the caller logged why).
    fn set_quietly(&self, status: Status) {
        *self.lock_status() = status;
    }

    fn link_up(&self, first: bool) {
        let mut l = self.lock_link();
        l.connected_since = Some(Instant::now());
        if !first {
            l.reconnects += 1;
        }
    }

    fn link_down(&self, why: &str) {
        let mut l = self.lock_link();
        l.connected_since = None;
        l.last_close = Some(why.to_string());
    }

    /// Returns once [`ClientBridge::reconnect`] has been called more than
    /// `asked` times in all.
    async fn reconnect_asked(&self, asked: u64) {
        while self.reconnects_asked.load(Ordering::SeqCst) == asked {
            self.reconnect.notified().await;
        }
    }
}

/// Runs while it lives. Dropping it closes the link the clean way (a close
/// frame, then the relay's answer: a second at most) and the local socket.
pub struct ClientBridge {
    shared: Arc<Shared>,
    local: SocketAddr,
    stop: Option<watch::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl ClientBridge {
    /// Connects to the relay at `url` as a client of `key`'s room. Returns the
    /// bridge and the loopback address to send the host's datagrams to; it
    /// stays the same across reconnects, so a session going through it
    /// survives a cut of the link. Fails only if the URL is invalid or the
    /// local socket or thread cannot be set up.
    pub fn start(url: &str, key: &Key) -> Result<(ClientBridge, SocketAddr), String> {
        ClientBridge::start_with(RelayUrl::parse(url)?, key, Timing::client())
    }

    pub(crate) fn start_with(url: RelayUrl, key: &Key, timing: Timing) -> Result<(ClientBridge, SocketAddr), String> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("cannot start the relay link: {}", errors::plain(e)))?;
        let no_socket = |e: io::Error| format!("cannot open a loopback UDP socket: {}", errors::plain(e));
        let std_sock = local_socket().map_err(no_socket)?;
        let local = std_sock.local_addr().map_err(no_socket)?;
        let sock = {
            let _inside = rt.enter();
            UdpSocket::from_std(std_sock).map_err(no_socket)?
        };
        let shared = Arc::new(Shared {
            status: Mutex::new(Status::Connecting),
            hosts_seen: AtomicU64::new(0),
            link: Mutex::new(LinkState::default()),
            counters: Counters::default(),
            reconnects_asked: AtomicU64::new(0),
            reconnect: Notify::new(),
            #[cfg(test)]
            lines: Mutex::new(Vec::new()),
        });
        let room = RoomKey::derive(key);
        let (stop, stopped) = watch::channel(());
        let state = shared.clone();
        let thread = std::thread::Builder::new()
            .name("relay".into())
            .spawn(move || {
                rt.block_on(link::drive(run(url, room, sock, state, timing, stopped.clone()), stopped));
                rt.shutdown_background();
            })
            .map_err(|e| format!("cannot start the relay link: {}", errors::plain(e)))?;
        Ok((ClientBridge { shared, local, stop: Some(stop), thread: Some(thread) }, local))
    }

    pub fn status(&self) -> Status {
        self.shared.lock_status().clone()
    }

    /// Rises each time the relay reports a host the client may not have a
    /// session with: the first host, a host that came online after being
    /// offline, one that replaced another with the same pairing key (the
    /// status stays [`Status::HostOnline`]), and the host after a
    /// [`ClientBridge::reconnect`]. The client should then start a new
    /// handshake. It does not rise when the bridge's own link was cut and
    /// came back to a host that was online before the cut, so the session
    /// carries on. A host that restarted or was replaced during such a cut
    /// goes unnoticed here: it drops the old session's datagrams, so the
    /// client relies on its existing silence timeout, which re-handshakes.
    pub fn hosts_seen(&self) -> u64 {
        self.shared.hosts_seen.load(Ordering::Relaxed)
    }

    /// The link's counters.
    pub fn stats(&self) -> LinkStats {
        let c = &self.shared.counters;
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let l = self.shared.lock_link();
        LinkStats {
            connected_since: l.connected_since,
            reconnects: l.reconnects,
            datagrams_in: get(&c.datagrams_in),
            bytes_in: get(&c.bytes_in),
            datagrams_out: get(&c.datagrams_out),
            bytes_out: get(&c.bytes_out),
            dropped: get(&c.dropped),
            discarded_while_down: get(&c.discarded_while_down),
            last_close: l.last_close.clone(),
        }
    }

    /// After [`Status::ClosedByHost`], connects to the relay again. In any
    /// other state it does nothing.
    pub fn reconnect(&self) {
        self.shared.reconnects_asked.fetch_add(1, Ordering::SeqCst);
        self.shared.reconnect.notify_one();
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Closes the link as dropping the bridge does, without waiting: the
    /// bridge's thread closes it (within a second) and ends by itself.
    pub fn close_in_background(mut self) {
        drop(self.stop.take());
        drop(self.thread.take());
    }
}

impl Drop for ClientBridge {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// 127.0.0.1, or ::1 on a machine without IPv4 loopback.
fn local_socket() -> io::Result<StdUdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let open = |addr: SocketAddr| -> io::Result<StdUdpSocket> {
        let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let s = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        let _ = s.set_send_buffer_size(UDP_BUFFER);
        let _ = s.set_recv_buffer_size(UDP_BUFFER);
        s.bind(&addr.into())?;
        s.set_nonblocking(true)?;
        Ok(s.into())
    };
    open(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).or_else(|_| open(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))))
}

/// The local end: the socket, and the client's address once it has sent
/// something (answers go there).
struct Local {
    sock: UdpSocket,
    app: Option<SocketAddr>,
    buf: Vec<u8>,
}

impl Local {
    /// Whether a datagram from `from` is the client's. The first sender is
    /// the client for as long as the bridge lives, across reconnects: any
    /// other local program could otherwise take the host's answers just by
    /// sending one datagram.
    fn is_app(&mut self, from: SocketAddr) -> bool {
        *self.app.get_or_insert(from) == from
    }
}

/// How a link that was up came down.
enum End {
    /// Lost or closed by the relay: reconnect, with backoff.
    Lost(String),
    /// The host closed this client's connection: wait for a reconnect call.
    ByHost(String),
    /// The local socket failed: the bridge stops, and closes the link first.
    Fatal(String),
}

/// Refusals in a row that usually clear up soon (TIMEOUT, ROOM_FULL,
/// RELAY_FULL): a seat the relay has not freed yet (a link cut without its
/// noticing) or a slow moment.
#[derive(Default)]
pub(crate) struct Refusals(u32);

impl Refusals {
    /// How long to wait after the relay refused with `reason`: the backoff
    /// for the first [`QUICK_RETRIES`] such refusals in a row, about
    /// `refused_wait` after more of them and after any other reason
    /// (NOT_ALLOWED, PROTOCOL, BAD_SIGNATURE, VERSION_MISMATCH and reasons
    /// this program does not know do not go away by themselves). Another
    /// reason also ends the series.
    pub(crate) fn wait(&mut self, reason: u8, t: &Timing, backoff: &mut Backoff) -> Duration {
        if matches!(reason, refused::TIMEOUT | refused::ROOM_FULL | refused::RELAY_FULL) {
            self.0 = self.0.saturating_add(1);
            if self.0 <= QUICK_RETRIES {
                return backoff.next();
            }
        } else {
            self.0 = 0;
        }
        jitter(t.refused_wait)
    }

    /// Anything but a refusal (a link, a busy relay, an unreachable one)
    /// ends the series.
    pub(crate) fn clear(&mut self) {
        self.0 = 0;
    }
}

async fn run(url: RelayUrl, room: RoomKey, sock: UdpSocket, shared: Arc<Shared>, t: Timing, mut stop: Stop) {
    let mut local = Local { sock, app: None, buf: vec![0u8; 64 * 1024] };
    let mut backoff = Backoff::new(&t);
    // Whether the host was online when the last link ended.
    let mut host_online = false;
    let mut first = true;
    let mut refusals = Refusals::default();
    loop {
        let connect = draining(link::connect(&url, &room, Role::Client), &mut local, &shared);
        let Some(attempt) = link::unless_stopped(connect, &mut stop).await else { return };
        if !matches!(attempt, Err(Failure::Refused(_))) {
            refusals.clear();
        }
        let wait = match attempt {
            Ok(ws) => {
                log!("relay: connected to {url}");
                shared.link_up(first);
                first = false;
                let began = Instant::now();
                // None: the bridge was dropped, and the link is closed.
                let Some(end) = session(ws, &mut local, &shared, &t, &mut host_online, &mut stop).await else { return };
                let lived = began.elapsed();
                if lived >= t.stable {
                    backoff.reset();
                }
                match end {
                    End::Lost(why) => {
                        let wait = backoff.next();
                        log!("{}", link::closed_line(lived, &why, &format!("reconnecting in {}", secs(wait))));
                        shared.link_down(&why);
                        shared.set_quietly(Status::CannotReach(format!("connection to the relay lost: {why}")));
                        wait
                    }
                    End::ByHost(why) => {
                        log!("{}", link::closed_line(lived, &why, "not reconnecting until asked"));
                        shared.link_down(&why);
                        // Read before the status changes: only calls made
                        // after the client saw ClosedByHost count.
                        let asked = shared.reconnects_asked.load(Ordering::SeqCst);
                        shared.set_quietly(Status::ClosedByHost);
                        let asking = draining(shared.reconnect_asked(asked), &mut local, &shared);
                        if link::unless_stopped(asking, &mut stop).await.is_none() {
                            return;
                        }
                        shared.set(Status::Connecting);
                        // The host ended that session: the next host seen
                        // needs a new handshake.
                        host_online = false;
                        backoff.reset();
                        continue;
                    }
                    End::Fatal(why) => {
                        shared.link_down(&why);
                        shared.set(Status::Closed(why));
                        return;
                    }
                }
            }
            Err(Failure::Refused(reason)) => {
                shared.set(Status::Refused(reason));
                refusals.wait(reason, &t, &mut backoff)
            }
            Err(Failure::Busy) => {
                shared.set(Status::RelayBusy);
                backoff.next()
            }
            Err(Failure::Unreachable(why)) => {
                shared.set(Status::CannotReach(why));
                backoff.next()
            }
        };
        let pause = draining(tokio::time::sleep(wait), &mut local, &shared);
        if link::unless_stopped(pause, &mut stop).await.is_none() {
            return;
        }
    }
}

/// Runs `fut` while the link is down, reading and discarding what the client
/// sends meanwhile (stale datagrams are worse than lost ones) but noting its
/// address if it is the first datagram.
async fn draining<F: Future>(fut: F, local: &mut Local, shared: &Shared) -> F::Output {
    tokio::pin!(fut);
    let mut broken = false;
    loop {
        let read = tokio::select! {
            out = &mut fut => return out,
            r = local.sock.recv_from(&mut local.buf), if !broken => r,
        };
        match read {
            Ok((_, from)) if local.is_app(from) => bump(&shared.counters.discarded_while_down, 1),
            Ok(_) => bump(&shared.counters.dropped, 1),
            Err(e) if link::transient(&e) => {}
            // The session that follows reports it.
            Err(_) => broken = true,
        }
    }
}

enum Event {
    Relay(Option<Result<Message, tungstenite::Error>>),
    Local(io::Result<(usize, SocketAddr)>),
    WriterDone(String),
    Idle,
    /// The held line saying the host went offline is due.
    OfflineLine,
    /// The bridge was dropped.
    Stop,
}

/// One link that is up, until it ends, or None: until the bridge is
/// dropped. The link is closed the clean way then, and when the bridge
/// stops on a failure of its own. `host_online` is whether the host was
/// online when the last link ended, and is kept up to date.
async fn session(
    ws: Ws,
    local: &mut Local,
    shared: &Shared,
    t: &Timing,
    host_online: &mut bool,
    stop: &mut Stop,
) -> Option<End> {
    let (mut sink, mut stream) = ws.split();
    let end = carry(&mut sink, &mut stream, local, shared, t, host_online, stop).await;
    match &end {
        // The relay is still there: say goodbye (a second at most).
        None | Some(End::Fatal(_)) => link::close(&mut sink, &mut stream).await,
        // The link is gone, or the host closed it.
        Some(End::Lost(_) | End::ByHost(_)) => {}
    }
    end
}

/// The datagrams both ways, until the link ends (or None: until the bridge
/// is dropped).
async fn carry(
    sink: &mut SplitSink<Ws, Message>,
    stream: &mut SplitStream<Ws>,
    local: &mut Local,
    shared: &Shared,
    t: &Timing,
    host_online: &mut bool,
    stop: &mut Stop,
) -> Option<End> {
    let (tx, rx) = queue::queue(queue::MAX_COUNT, queue::MAX_BYTES);
    let writer = link::writer(sink, rx, t.ping_interval);
    tokio::pin!(writer);
    let idle = tokio::time::sleep(t.idle_timeout);
    tokio::pin!(idle);
    let counters = &shared.counters;
    let mut first_status = true;
    // The line saying the host went offline, while it waits.
    let held = tokio::time::sleep(OFFLINE_LINE_HOLD);
    tokio::pin!(held);
    let mut holding = false;

    let end = loop {
        let event = tokio::select! {
            why = &mut writer => Event::WriterDone(why),
            _ = &mut idle => Event::Idle,
            _ = &mut held, if holding => Event::OfflineLine,
            _ = link::stopped(stop) => Event::Stop,
            msg = stream.next() => Event::Relay(msg),
            r = local.sock.recv_from(&mut local.buf) => Event::Local(r),
        };
        match event {
            // The client is done with the link: a held line goes unsaid.
            Event::Stop => break None,
            Event::WriterDone(why) => break Some(End::Lost(why)),
            Event::Idle => break Some(End::Lost(format!("no traffic for {}", secs(t.idle_timeout)))),
            Event::OfflineLine => {
                holding = false;
                shared.note(&Status::HostOffline);
            }
            Event::Local(Ok((_, from))) if !local.is_app(from) => bump(&counters.dropped, 1),
            Event::Local(Ok((n, _))) => {
                // Over the relay's limit: dropped, as on a path with a smaller
                // MTU. A full queue drops it too.
                if n <= relay::MAX_PAYLOAD && tx.push(Msg::ClientData(&local.buf[..n]).encode()) {
                    bump(&counters.datagrams_out, 1);
                    bump(&counters.bytes_out, n as u64);
                } else {
                    bump(&counters.dropped, 1);
                }
            }
            Event::Local(Err(e)) if link::transient(&e) => {}
            Event::Local(Err(e)) => break Some(End::Fatal(format!("the local UDP socket failed: {}", errors::plain(e)))),
            Event::Relay(msg) => {
                idle.as_mut().reset(tokio::time::Instant::now() + t.idle_timeout);
                let data = match msg {
                    Some(Ok(Message::Binary(b))) => b,
                    Some(Ok(Message::Close(frame))) if link::is_closed_by_host(&frame) => {
                        break Some(End::ByHost(format!("the host closed this connection{}", link::close_text(&frame))))
                    }
                    Some(Ok(Message::Close(frame))) => {
                        break Some(End::Lost(format!("the relay closed the connection{}", link::close_text(&frame))))
                    }
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => break Some(End::Lost(link::read_error(&e))),
                    None => break Some(End::Lost("the relay closed the connection".into())),
                };
                match Msg::decode(&data) {
                    Some(Msg::ClientData(payload)) => {
                        bump(&counters.datagrams_in, 1);
                        bump(&counters.bytes_in, payload.len() as u64);
                        // Non-blocking: a full socket buffer drops it.
                        let sent = local.app.is_some_and(|app| local.sock.try_send_to(payload, app).is_ok());
                        if !sent {
                            bump(&counters.dropped, 1);
                        }
                    }
                    Some(Msg::Status { host_online: true }) => {
                        // The first status of a link that came back to a host
                        // online before the cut: most likely the same host, and
                        // the session carries on.
                        if !(first_status && *host_online) {
                            shared.hosts_seen.fetch_add(1, Ordering::Relaxed);
                        }
                        first_status = false;
                        *host_online = true;
                        // The host came back within the hold: both lines, in order.
                        if std::mem::take(&mut holding) {
                            shared.note(&Status::HostOffline);
                        }
                        shared.set(Status::HostOnline);
                    }
                    Some(Msg::Status { host_online: false }) => {
                        first_status = false;
                        *host_online = false;
                        let mut status = shared.lock_status();
                        if *status == Status::HostOnline {
                            // Said later, unless the client closes the link first.
                            *status = Status::HostOffline;
                            drop(status);
                            holding = true;
                            held.as_mut().reset(tokio::time::Instant::now() + OFFLINE_LINE_HOLD);
                        } else {
                            drop(status);
                            shared.set(Status::HostOffline);
                        }
                    }
                    _ => {}
                }
            }
        }
    };
    // The link ended by itself: a held line comes before the line saying so.
    if end.is_some() && holding {
        shared.note(&Status::HostOffline);
    }
    end
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};

    use hyperspace_proto::secure::Key;
    use hyperspace_relay::{Allow, Config};

    use super::{ClientBridge, Shared, Status, OFFLINE_LINE_HOLD};
    use crate::link::Timing;
    use crate::{HostBridge, RelayUrl, RelayedPeers};

    const OFFLINE_LINE: &str = "relay: connected to the relay; the host is offline";

    fn fast() -> Timing {
        Timing {
            backoff_min: Duration::from_millis(50),
            backoff_max: Duration::from_millis(200),
            refused_wait: Duration::from_millis(200),
            ping_interval: Duration::from_millis(200),
            idle_timeout: Duration::from_secs(10),
            stable: Duration::from_secs(1),
        }
    }

    /// A relay on its own runtime: shutting the runtime down drops every link.
    fn relay() -> (tokio::runtime::Runtime, RelayUrl) {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
        let url = RelayUrl::parse(&format!("ws://{}", listener.local_addr().unwrap())).unwrap();
        let mut config = Config::new(Allow::Open);
        config.rate = None;
        rt.spawn(async move {
            let _ = hyperspace_relay::serve(listener, config).await;
        });
        (rt, url)
    }

    fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The status lines printed from `since` on.
    fn lines_since(shared: &Shared, since: Instant) -> Vec<(Instant, String)> {
        let lines = shared.lines.lock().unwrap();
        lines.iter().filter(|(at, _)| *at >= since).cloned().collect()
    }

    fn offline_lines(shared: &Shared) -> Vec<Instant> {
        let lines = shared.lines.lock().unwrap();
        lines.iter().filter(|(_, line)| line == OFFLINE_LINE).map(|(at, _)| *at).collect()
    }

    fn host(url: &RelayUrl, key: &Key, app: &UdpSocket) -> HostBridge {
        HostBridge::start_with(url.clone(), key, app.local_addr().unwrap(), RelayedPeers::new(), fast()).unwrap()
    }

    /// Timers may round to the millisecond.
    const SLACK: Duration = Duration::from_millis(50);

    #[test]
    fn the_line_saying_a_host_left_waits_a_second_and_an_exit_drops_it() {
        let (rt, url) = relay();
        let key = Key::generate();
        let (client, _) = ClientBridge::start_with(url.clone(), &key, fast()).unwrap();
        let shared = client.shared.clone();

        // No host yet: the line comes with the status.
        wait_for("the host to be reported offline", || client.status() == Status::HostOffline);
        assert_eq!(offline_lines(&shared).len(), 1);

        // A host that was online and left: the status changes at once, the
        // line a second later.
        let app = UdpSocket::bind("127.0.0.1:0").unwrap();
        let first = host(&url, &key, &app);
        wait_for("the host to come online", || client.status() == Status::HostOnline);
        let left = Instant::now();
        drop(first);
        wait_for("the host to be reported offline again", || client.status() == Status::HostOffline);
        wait_for("the held line", || offline_lines(&shared).len() == 2);
        let said = offline_lines(&shared)[1];
        assert!(said + SLACK >= left + OFFLINE_LINE_HOLD, "said {:?} after the host left", said - left);

        // A client that stops within that second never says it.
        let second = host(&url, &key, &app);
        wait_for("the host to come back", || client.status() == Status::HostOnline);
        drop(second);
        wait_for("the host to be reported offline once more", || client.status() == Status::HostOffline);
        let stopping = Instant::now();
        drop(client);
        let late = lines_since(&shared, stopping);
        assert!(late.is_empty(), "printed while stopping: {late:?}");
        assert_eq!(offline_lines(&shared).len(), 2);
        rt.shutdown_background();
    }

    #[test]
    fn a_link_that_ends_says_the_held_line_first() {
        let (rt, url) = relay();
        let key = Key::generate();
        let (client, _) = ClientBridge::start_with(url.clone(), &key, fast()).unwrap();
        let shared = client.shared.clone();
        let app = UdpSocket::bind("127.0.0.1:0").unwrap();
        let only = host(&url, &key, &app);
        wait_for("the host to come online", || client.status() == Status::HostOnline);
        let left = Instant::now();
        drop(only);
        wait_for("the host to be reported offline", || client.status() == Status::HostOffline);

        // The relay goes away within the second: the held line is said then,
        // before the line about the lost link.
        rt.shutdown_background();
        wait_for("a status line after the offline one", || {
            let lines = lines_since(&shared, left);
            lines.len() >= 2
        });
        let lines = lines_since(&shared, left);
        assert_eq!(lines[0].1, OFFLINE_LINE, "{lines:?}");
        assert!(lines[0].0 < left + OFFLINE_LINE_HOLD, "said {:?} after the host left", lines[0].0 - left);
        assert_ne!(lines[1].1, OFFLINE_LINE, "{lines:?}");
        drop(client);
    }
}
