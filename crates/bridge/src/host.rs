//! The host's end: keeps one link to the relay open and, for each client the
//! relay announces, a loopback UDP socket that talks to the host's server on
//! that client's behalf.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Instant;

use futures_util::StreamExt;
use hyperspace_proto::log;
use hyperspace_proto::relay::{self, refused, Msg, Role, RoomKey};
use hyperspace_proto::secure::Key;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::{self, Bytes, Message};

use crate::link::{self, secs, Backoff, Failure, Quiet, Timing, Ws};
use crate::queue::{self, Tx};
use crate::{RelayUrl, RelayedPeers};

/// Far above what a relay lets into one room; a relay that announces more is
/// told to drop them.
const MAX_PEERS: usize = 32;
/// Socket buffers of each loopback socket, as for the server's own socket.
const UDP_BUFFER: usize = 1 << 20;

/// Runs while it lives; dropping it closes the link and the loopback sockets.
pub struct HostBridge {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl HostBridge {
    /// Connects to the relay at `url` as the host of `key`'s room, and serves
    /// each client through a loopback socket that sends to `target` (the
    /// host's server). Each such socket's address is in `peers` while it is
    /// open. Fails only if the URL is invalid or the thread cannot start; the
    /// relay being down is retried for as long as the bridge lives.
    pub fn start(url: &str, key: &Key, target: SocketAddr, peers: RelayedPeers) -> Result<HostBridge, String> {
        HostBridge::start_with(RelayUrl::parse(url)?, key, target, peers, Timing::host())
    }

    pub(crate) fn start_with(
        url: RelayUrl,
        key: &Key,
        target: SocketAddr,
        peers: RelayedPeers,
        timing: Timing,
    ) -> Result<HostBridge, String> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("cannot start the relay link: {e}"))?;
        let room = RoomKey::derive(key);
        let (stop, stopped) = oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("relay".into())
            .spawn(move || {
                rt.block_on(async move {
                    tokio::select! {
                        _ = run(url, room, target, peers, timing) => {}
                        _ = stopped => {}
                    }
                });
                rt.shutdown_background();
            })
            .map_err(|e| format!("cannot start the relay link: {e}"))?;
        Ok(HostBridge { stop: Some(stop), thread: Some(thread) })
    }
}

impl Drop for HostBridge {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// How a link that was up came down.
enum End {
    /// Another host with the same pairing key took the room.
    Replaced,
    Lost(String),
}

impl End {
    fn why(&self) -> &str {
        match self {
            End::Replaced => "another host with this pairing key took the room",
            End::Lost(why) => why,
        }
    }
}

async fn run(url: RelayUrl, room: RoomKey, target: SocketAddr, peers: RelayedPeers, t: Timing) {
    let mut backoff = Backoff::new(&t);
    let mut quiet = Quiet::default();
    let wait_secs = t.refused_wait.as_secs();
    loop {
        let wait = match link::connect(&url, &room, Role::Host).await {
            Ok(ws) => {
                log!("relay: connected to {url}");
                quiet.clear();
                let began = Instant::now();
                let end = session(ws, target, &peers, &t).await;
                let lived = began.elapsed();
                if lived >= t.stable {
                    backoff.reset();
                }
                // Backs off at length when replaced, so that two hosts with
                // one key do not take the room from each other forever.
                let wait = match end {
                    End::Replaced => t.refused_wait,
                    End::Lost(_) => backoff.next(),
                };
                log!("relay link closed after {}: {}; reconnecting in {}", secs(lived), end.why(), secs(wait));
                wait
            }
            Err(Failure::Refused(refused::NOT_ALLOWED)) => {
                if quiet.changed("not allowed") {
                    log!(
                        "relay: the relay at {url} does not serve this host yet: its operator must add relay id {}",
                        room.id().hex()
                    );
                }
                t.refused_wait
            }
            Err(Failure::Refused(refused::TIMEOUT)) => {
                let wait = backoff.next();
                if quiet.changed("timeout") {
                    log!("relay: {}; retrying", refused::describe(refused::TIMEOUT));
                }
                wait
            }
            Err(Failure::Refused(reason)) => {
                if quiet.changed(refused::describe(reason)) {
                    log!("relay: refused by {url}: {}; retrying every {wait_secs} s", refused::describe(reason));
                }
                t.refused_wait
            }
            Err(Failure::Busy) => {
                let wait = backoff.next();
                if quiet.changed("busy") {
                    log!("relay: the relay at {url} is busy (HTTP 503); retrying");
                }
                wait
            }
            Err(Failure::Unreachable(e)) => {
                let wait = backoff.next();
                if quiet.changed(&e) {
                    log!("relay: {e}; retrying");
                }
                wait
            }
        };
        tokio::time::sleep(wait).await;
    }
}

/// What woke the session up.
enum Event {
    Relay(Option<Result<Message, tungstenite::Error>>),
    WriterDone(String),
    Idle,
}

async fn session(ws: Ws, target: SocketAddr, peers: &RelayedPeers, t: &Timing) -> End {
    let (sink, mut stream) = ws.split();
    let (tx, rx) = queue::queue(queue::MAX_COUNT, queue::MAX_BYTES);
    let writer = link::writer(sink, rx, t.ping_interval);
    tokio::pin!(writer);
    let idle = tokio::time::sleep(t.idle_timeout);
    tokio::pin!(idle);
    // Dropping a peer closes its socket and takes its address out of `peers`,
    // so every return below also forgets every client.
    let mut open: HashMap<u32, Peer> = HashMap::new();

    loop {
        let event = tokio::select! {
            why = &mut writer => Event::WriterDone(why),
            _ = &mut idle => Event::Idle,
            msg = stream.next() => Event::Relay(msg),
        };
        let data: Bytes = match event {
            Event::WriterDone(why) => return End::Lost(why),
            Event::Idle => return End::Lost(format!("no traffic for {}", secs(t.idle_timeout))),
            Event::Relay(Some(Ok(Message::Binary(b)))) => b,
            Event::Relay(Some(Ok(Message::Close(frame)))) => {
                if link::is_replaced(&frame) {
                    return End::Replaced;
                }
                return End::Lost(format!("the relay closed the connection{}", link::close_text(&frame)));
            }
            Event::Relay(Some(Ok(_))) => {
                idle.as_mut().reset(tokio::time::Instant::now() + t.idle_timeout);
                continue;
            }
            Event::Relay(Some(Err(e))) => return End::Lost(link::read_error(&e)),
            Event::Relay(None) => return End::Lost("the relay closed the connection".into()),
        };
        idle.as_mut().reset(tokio::time::Instant::now() + t.idle_timeout);

        match Msg::decode(&data) {
            Some(Msg::HostData { peer, payload }) => {
                // Non-blocking: a full socket buffer drops the datagram.
                if let Some(p) = open.get(&peer) {
                    let _ = p.sock.try_send(payload);
                }
            }
            Some(Msg::PeerOpen(id)) => {
                // A reused id is a new client: close the old socket first.
                if open.remove(&id).is_none() && open.len() >= MAX_PEERS {
                    tx.push_control(Msg::PeerClose(id).encode());
                    continue;
                }
                match Peer::open(id, target, peers, &tx) {
                    Ok(p) => {
                        log!("relay: client {id} joined through the relay");
                        open.insert(id, p);
                    }
                    Err(e) => {
                        log!("relay: cannot open a loopback socket for client {id}: {e}");
                        tx.push_control(Msg::PeerClose(id).encode());
                    }
                }
            }
            Some(Msg::PeerClose(id)) => {
                if open.remove(&id).is_some() {
                    log!("relay: client {id} left the relay");
                }
            }
            _ => {}
        }
    }
}

/// One client seen through the relay: a loopback UDP socket connected to the
/// host's server.
struct Peer {
    local: SocketAddr,
    sock: Arc<UdpSocket>,
    reader: tokio::task::JoinHandle<()>,
    peers: RelayedPeers,
}

impl Peer {
    fn open(id: u32, target: SocketAddr, peers: &RelayedPeers, tx: &Tx) -> io::Result<Peer> {
        let std_sock = loopback_socket(target)?;
        let local = std_sock.local_addr()?;
        let sock = Arc::new(UdpSocket::from_std(std_sock)?);
        // Registered before the first datagram can reach the server.
        peers.insert(local);
        let reader = tokio::spawn(peer_reader(id, sock.clone(), tx.clone()));
        Ok(Peer { local, sock, reader, peers: peers.clone() })
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.reader.abort();
        self.peers.remove(self.local);
    }
}

/// A non-blocking UDP socket on `target`'s address, connected to `target`.
fn loopback_socket(target: SocketAddr) -> io::Result<StdUdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if target.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let s = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    let _ = s.set_send_buffer_size(UDP_BUFFER);
    let _ = s.set_recv_buffer_size(UDP_BUFFER);
    s.bind(&SocketAddr::new(target.ip(), 0).into())?;
    s.connect(&target.into())?;
    s.set_nonblocking(true)?;
    Ok(s.into())
}

/// The server's datagrams for client `id`, onto the link.
async fn peer_reader(id: u32, sock: Arc<UdpSocket>, tx: Tx) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match sock.recv(&mut buf).await {
            // Over the relay's limit: dropped, as on a path with a smaller MTU.
            Ok(n) if n > relay::MAX_PAYLOAD => {}
            // A full queue drops it too.
            Ok(n) => {
                let _ = tx.push(Msg::HostData { peer: id, payload: &buf[..n] }.encode());
            }
            Err(e) if link::transient(&e) => {}
            Err(e) => {
                log!("relay: loopback socket for client {id} failed: {e}");
                return;
            }
        }
    }
}
