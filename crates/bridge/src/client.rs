//! The client's end: a loopback UDP address that stands for the host. What
//! the client sends there goes through the relay to the host, and the host's
//! answers come back from it.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use futures_util::StreamExt;
use hyperspace_proto::log;
use hyperspace_proto::relay::{self, refused, Msg, Role, RoomKey};
use hyperspace_proto::secure::Key;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::{self, Message};

use crate::link::{self, Backoff, Failure, Timing, Ws};
use crate::queue;
use crate::RelayUrl;

const UDP_BUFFER: usize = 1 << 20;

/// Where the link to the relay stands, in words a user can act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// First attempt under way.
    Connecting,
    /// DNS, TCP, TLS, the HTTP upgrade, or a link that was lost: one line
    /// saying which. Retried with backoff.
    CannotReach(String),
    /// The relay refused this client (a [`refused`] reason). Retried, slowly.
    Refused(u8),
    /// Connected; the host is not connected to the relay.
    HostOffline,
    /// Connected, and the host is too.
    HostOnline,
    /// The bridge stopped for good (its local socket failed).
    Closed(String),
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Status::Connecting => f.write_str("connecting to the relay"),
            Status::CannotReach(why) => write!(f, "cannot reach the relay: {why}"),
            Status::Refused(reason) => write!(f, "the relay refused the connection: {}", refused::describe(*reason)),
            Status::HostOffline => f.write_str("connected to the relay; the host is offline"),
            Status::HostOnline => f.write_str("connected to the relay; the host is online"),
            Status::Closed(why) => write!(f, "relay link stopped: {why}"),
        }
    }
}

struct Shared {
    status: Mutex<Status>,
    hosts_seen: AtomicU64,
}

impl Shared {
    fn set(&self, status: Status) {
        let mut s = self.status.lock().unwrap_or_else(|e| e.into_inner());
        if *s != status {
            log!("relay: {status}");
            *s = status;
        }
    }
}

/// Runs while it lives; dropping it closes the link and the local socket.
pub struct ClientBridge {
    shared: Arc<Shared>,
    local: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl ClientBridge {
    /// Connects to the relay at `url` as a client of `key`'s room. Returns the
    /// bridge and the loopback address to send the host's datagrams to; it
    /// stays the same across reconnects. Fails only if the URL is invalid or
    /// the local socket or thread cannot be set up.
    pub fn start(url: &str, key: &Key) -> Result<(ClientBridge, SocketAddr), String> {
        ClientBridge::start_with(RelayUrl::parse(url)?, key, Timing::default())
    }

    pub(crate) fn start_with(url: RelayUrl, key: &Key, timing: Timing) -> Result<(ClientBridge, SocketAddr), String> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("cannot start the relay link: {e}"))?;
        let std_sock = local_socket().map_err(|e| format!("cannot open a loopback UDP socket: {e}"))?;
        let local = std_sock.local_addr().map_err(|e| format!("cannot open a loopback UDP socket: {e}"))?;
        let sock = {
            let _inside = rt.enter();
            UdpSocket::from_std(std_sock).map_err(|e| format!("cannot open a loopback UDP socket: {e}"))?
        };
        let shared = Arc::new(Shared { status: Mutex::new(Status::Connecting), hosts_seen: AtomicU64::new(0) });
        let room = RoomKey::derive(key);
        let (stop, stopped) = oneshot::channel::<()>();
        let state = shared.clone();
        let thread = std::thread::Builder::new()
            .name("relay".into())
            .spawn(move || {
                rt.block_on(async move {
                    tokio::select! {
                        _ = run(url, room, sock, state, timing) => {}
                        _ = stopped => {}
                    }
                });
                rt.shutdown_background();
            })
            .map_err(|e| format!("cannot start the relay link: {e}"))?;
        Ok((ClientBridge { shared, local, stop: Some(stop), thread: Some(thread) }, local))
    }

    pub fn status(&self) -> Status {
        self.shared.status.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// How many times the relay said the host is online. It also rises when
    /// a host replaces another one with the same pairing key without the
    /// status changing: the client should then start a new handshake.
    pub fn hosts_seen(&self) -> u64 {
        self.shared.hosts_seen.load(Ordering::Relaxed)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
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

async fn run(url: RelayUrl, room: RoomKey, sock: UdpSocket, shared: Arc<Shared>, t: Timing) {
    let mut local = Local { sock, app: None, buf: vec![0u8; 64 * 1024] };
    let mut backoff = Backoff::new(&t);
    loop {
        let attempt = draining(link::connect(&url, &room, Role::Client), &mut local).await;
        let wait = match attempt {
            Ok(ws) => {
                log!("relay: connected to {url}");
                let began = Instant::now();
                let end = session(ws, &mut local, &shared, &t).await;
                if began.elapsed() >= t.stable {
                    backoff.reset();
                }
                match end {
                    Ok(why) => {
                        shared.set(Status::CannotReach(format!("connection to the relay lost: {why}")));
                        backoff.next()
                    }
                    Err(fatal) => {
                        shared.set(Status::Closed(fatal));
                        return;
                    }
                }
            }
            Err(Failure::Refused(reason)) => {
                shared.set(Status::Refused(reason));
                if reason == refused::TIMEOUT {
                    backoff.next()
                } else {
                    t.refused_wait
                }
            }
            Err(Failure::Unreachable(why)) => {
                shared.set(Status::CannotReach(why));
                backoff.next()
            }
        };
        draining(tokio::time::sleep(wait), &mut local).await;
    }
}

/// Runs `fut` while the link is down, reading and discarding what the client
/// sends meanwhile (stale datagrams are worse than lost ones) but noting its
/// address.
async fn draining<F: Future>(fut: F, local: &mut Local) -> F::Output {
    tokio::pin!(fut);
    let mut broken = false;
    loop {
        let read = tokio::select! {
            out = &mut fut => return out,
            r = local.sock.recv_from(&mut local.buf), if !broken => r,
        };
        match read {
            Ok((_, from)) => local.app = Some(from),
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
}

/// One link that is up. Ok(why) when it ends, Err(why) if the local socket
/// failed (the bridge then stops).
async fn session(ws: Ws, local: &mut Local, shared: &Shared, t: &Timing) -> Result<String, String> {
    let (sink, mut stream) = ws.split();
    let (tx, rx) = queue::queue(queue::MAX_COUNT, queue::MAX_BYTES);
    let writer = link::writer(sink, rx);
    tokio::pin!(writer);
    let idle = tokio::time::sleep(t.idle_timeout);
    tokio::pin!(idle);

    loop {
        let event = tokio::select! {
            why = &mut writer => Event::WriterDone(why),
            _ = &mut idle => Event::Idle,
            msg = stream.next() => Event::Relay(msg),
            r = local.sock.recv_from(&mut local.buf) => Event::Local(r),
        };
        match event {
            Event::WriterDone(why) => return Ok(why),
            Event::Idle => return Ok(format!("nothing from the relay for {} s", t.idle_timeout.as_secs())),
            Event::Local(Ok((n, from))) => {
                local.app = Some(from);
                // Over the relay's limit: dropped, as on a path with a smaller
                // MTU. A full queue drops it too.
                if n <= relay::MAX_PAYLOAD {
                    let _ = tx.push(Msg::ClientData(&local.buf[..n]).encode());
                }
            }
            Event::Local(Err(e)) if link::transient(&e) => {}
            Event::Local(Err(e)) => return Err(format!("the local UDP socket failed: {e}")),
            Event::Relay(msg) => {
                idle.as_mut().reset(tokio::time::Instant::now() + t.idle_timeout);
                let data = match msg {
                    Some(Ok(Message::Binary(b))) => b,
                    Some(Ok(Message::Close(frame))) => {
                        return Ok(format!("the relay closed the connection{}", link::close_text(&frame)))
                    }
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => return Ok(e.to_string()),
                    None => return Ok("the relay closed the connection".into()),
                };
                match Msg::decode(&data) {
                    Some(Msg::ClientData(payload)) => {
                        if let Some(app) = local.app {
                            // Non-blocking: a full socket buffer drops it.
                            let _ = local.sock.try_send_to(payload, app);
                        }
                    }
                    Some(Msg::Status { host_online: true }) => {
                        shared.hosts_seen.fetch_add(1, Ordering::Relaxed);
                        shared.set(Status::HostOnline);
                    }
                    Some(Msg::Status { host_online: false }) => shared.set(Status::HostOffline),
                    _ => {}
                }
            }
        }
    }
}
