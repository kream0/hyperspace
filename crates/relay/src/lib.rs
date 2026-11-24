//! hyperspace relay: pairs a host and its clients when they cannot reach each
//! other over UDP, and forwards their datagrams.
//!
//! Peers connect with a WebSocket to [`proto::PATH`] and speak the protocol in
//! [`hyperspace_proto::relay`]. The relay only sees ciphertext: it checks that
//! a peer holds the room key (a signature over a fresh nonce), then moves
//! opaque datagrams between the room's host and its clients.
//!
//! Plain HTTP only. In production TLS ends at a reverse proxy in front of the
//! relay, which listens on loopback.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{close_code, CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::serve::ListenerExt;
use axum::Router;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use hyperspace_proto::relay::{self as proto, mt, refused, Hello, Msg, Role, RoomId};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Notify};

/// Where the relay listens unless told otherwise (loopback: a reverse proxy
/// in front of it terminates TLS).
pub const DEFAULT_LISTEN: &str = "127.0.0.1:47800";

/// Largest WebSocket message or frame accepted. A relay message is at most
/// [`proto::MAX_MESSAGE`] bytes; anything bigger closes the link.
pub const MAX_WS_MESSAGE: usize = 16 * 1024;

/// Datagrams queued per link before new ones are dropped.
const DATA_QUEUE: usize = 256;
/// Queue slots only control messages may use, so a link full of datagrams
/// still gets its PEER_OPEN/PEER_CLOSE/STATUS in order.
const CTRL_RESERVE: usize = 64;
/// Queued messages written in one batch before flushing.
const WRITE_BATCH: usize = 64;
/// How long a closing link waits for the peer's half of the close handshake.
const CLOSE_GRACE: Duration = Duration::from_secs(2);

/// Write one timestamped line to stderr.
pub fn log(args: fmt::Arguments) {
    eprintln!("{} {}", utc(now_secs()), args);
}

macro_rules! log {
    ($($arg:tt)*) => { $crate::log(format_args!($($arg)*)) };
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// `YYYY-MM-DD HH:MM:SSZ` for a Unix time (days-to-civil, proleptic Gregorian).
fn utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Which rooms may use the relay.
#[derive(Clone, Debug)]
pub enum Allow {
    /// Every room (tests only).
    Open,
    /// Room ids listed in this file, re-read on every HELLO.
    File(PathBuf),
}

/// Read an allow file: one room id (64 hex digits) per line, `#` starts a
/// comment, blank lines are skipped. Returns the ids and the number of lines
/// that held something else.
pub fn read_allow_file(path: &Path) -> io::Result<(HashSet<RoomId>, usize)> {
    let text = std::fs::read_to_string(path)?;
    let mut ids = HashSet::new();
    let mut bad = 0;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        match RoomId::from_hex(line) {
            Some(id) => {
                ids.insert(id);
            }
            None => bad += 1,
        }
    }
    Ok((ids, bad))
}

/// Per-room, per-direction rate limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rate {
    pub bytes_per_sec: u64,
    /// Bucket size: how much may pass at once after a quiet spell.
    pub burst: u64,
}

impl Rate {
    /// `mbit` megabits per second with a quarter-second burst (at least
    /// 256 KiB). Zero means no limit.
    pub fn from_mbit(mbit: u64) -> Option<Rate> {
        if mbit == 0 {
            return None;
        }
        let bytes_per_sec = mbit.saturating_mul(125_000);
        Some(Rate { bytes_per_sec, burst: (bytes_per_sec / 4).max(256 * 1024) })
    }
}

impl fmt::Display for Rate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} Mbit/s", self.bytes_per_sec as f64 / 125_000.0)
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub allow: Allow,
    /// Rooms that may exist at once (a room exists while a host or client is in it).
    pub max_rooms: usize,
    /// Clients per room.
    pub max_clients: usize,
    /// Limit for each direction of each room; None for no limit.
    pub rate: Option<Rate>,
    /// Time a new connection has to answer the challenge.
    pub auth_timeout: Duration,
    /// Interval between pings the relay sends on an idle link.
    pub ping_interval: Duration,
    /// A link that sends nothing (not even a pong) for this long is closed.
    pub idle_timeout: Duration,
}

impl Config {
    pub fn new(allow: Allow) -> Config {
        Config {
            allow,
            max_rooms: 16,
            max_clients: 4,
            rate: Rate::from_mbit(60),
            auth_timeout: Duration::from_secs(5),
            ping_interval: Duration::from_secs(20),
            idle_timeout: Duration::from_secs(60),
        }
    }
}

/// Token bucket. Starts full.
#[derive(Debug)]
struct Bucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn new(rate: Rate, now: Instant) -> Bucket {
        let burst = rate.burst as f64;
        Bucket { rate: rate.bytes_per_sec as f64, burst, tokens: burst, last: now }
    }

    /// Take `n` bytes if the bucket holds them.
    fn take(&mut self, n: usize, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = self.last.max(now);
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        if self.tokens >= n as f64 {
            self.tokens -= n as f64;
            true
        } else {
            false
        }
    }
}

/// The relay's handle on one authenticated connection.
struct Link {
    id: u64,
    /// The only sender: dropping the Link ends the connection's writer,
    /// which closes the WebSocket.
    tx: mpsc::Sender<Bytes>,
    /// Closes the connection at once (it could not take a control message).
    kill: Arc<Notify>,
}

/// Queue a control message. A link that cannot take one is closed rather
/// than left with a gap in its PEER_OPEN/PEER_CLOSE/STATUS sequence.
fn send_ctrl(link: &Link, msg: Msg) {
    if link.tx.try_send(encode(msg)).is_err() {
        link.kill.notify_one();
    }
}

/// Queue a datagram, or drop it if the link is behind (as a congested UDP
/// path would). The last [`CTRL_RESERVE`] slots are kept for control messages.
fn send_data(link: &Link, bytes: Bytes) {
    if link.tx.capacity() > CTRL_RESERVE {
        let _ = link.tx.try_send(bytes);
    }
}

fn encode(msg: Msg) -> Bytes {
    Bytes::from(msg.encode())
}

struct Room {
    host: Option<Link>,
    clients: BTreeMap<u32, Link>,
    next_peer: u32,
    to_host: Option<Bucket>,
    to_clients: Option<Bucket>,
}

impl Room {
    fn new(rate: Option<Rate>) -> Room {
        let now = Instant::now();
        Room {
            host: None,
            clients: BTreeMap::new(),
            next_peer: 1,
            to_host: rate.map(|r| Bucket::new(r, now)),
            to_clients: rate.map(|r| Bucket::new(r, now)),
        }
    }

    /// A peer id not in use; never 0.
    fn alloc_peer(&mut self) -> u32 {
        loop {
            let peer = self.next_peer;
            self.next_peer = self.next_peer.checked_add(1).unwrap_or(1);
            if peer != 0 && !self.clients.contains_key(&peer) {
                return peer;
            }
        }
    }

    fn host_is(&self, id: u64) -> bool {
        self.host.as_ref().is_some_and(|h| h.id == id)
    }

    fn client_is(&self, peer: u32, id: u64) -> bool {
        self.clients.get(&peer).is_some_and(|c| c.id == id)
    }
}

/// A connection's place in its room.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Seat {
    Host,
    Client(u32),
}

struct Shared {
    config: Config,
    /// All rooms. Held only for short, non-async sections.
    rooms: Mutex<HashMap<RoomId, Room>>,
    next_link: AtomicU64,
}

impl Shared {
    fn rooms(&self) -> MutexGuard<'_, HashMap<RoomId, Room>> {
        self.rooms.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn counts(&self) -> (usize, usize) {
        let rooms = self.rooms();
        let hosts = rooms.values().filter(|r| r.host.is_some()).count();
        let clients = rooms.values().map(|r| r.clients.len()).sum();
        (hosts, clients)
    }

    fn allowed(&self, room: &RoomId) -> bool {
        match &self.config.allow {
            Allow::Open => true,
            Allow::File(path) => match read_allow_file(path) {
                Ok((ids, _)) => ids.contains(room),
                Err(e) => {
                    log!("cannot read the allow list {}: {e}", path.display());
                    false
                }
            },
        }
    }

    /// Seat a host. Returns the messages to send it first, and whether it
    /// replaced another host.
    fn join_host(&self, room: RoomId, link: Link) -> Result<(Vec<Bytes>, bool), u8> {
        let mut rooms = self.rooms();
        if !rooms.contains_key(&room) && rooms.len() >= self.config.max_rooms {
            return Err(refused::RELAY_FULL);
        }
        let rate = self.config.rate;
        let r = rooms.entry(room).or_insert_with(|| Room::new(rate));
        let mut first = vec![encode(Msg::Ok)];
        for &peer in r.clients.keys() {
            first.push(encode(Msg::PeerOpen(peer)));
        }
        for c in r.clients.values() {
            send_ctrl(c, Msg::Status { host_online: true });
        }
        // Dropping the old host's Link closes its connection.
        let replaced = r.host.replace(link).is_some();
        Ok((first, replaced))
    }

    /// Seat a client. Returns the messages to send it first, its peer id and
    /// whether the host is online.
    fn join_client(&self, room: RoomId, link: Link) -> Result<(Vec<Bytes>, u32, bool), u8> {
        let mut rooms = self.rooms();
        match rooms.get(&room) {
            Some(r) if r.clients.len() >= self.config.max_clients => return Err(refused::ROOM_FULL),
            Some(_) => {}
            None if rooms.len() >= self.config.max_rooms => return Err(refused::RELAY_FULL),
            None if self.config.max_clients == 0 => return Err(refused::ROOM_FULL),
            None => {}
        }
        let rate = self.config.rate;
        let r = rooms.entry(room).or_insert_with(|| Room::new(rate));
        let peer = r.alloc_peer();
        let online = r.host.is_some();
        if let Some(h) = &r.host {
            send_ctrl(h, Msg::PeerOpen(peer));
        }
        r.clients.insert(peer, link);
        Ok((vec![encode(Msg::Ok), encode(Msg::Status { host_online: online })], peer, online))
    }

    /// Remove a connection from its room if it still holds its seat, and tell
    /// the other side. Returns false if it had already been removed.
    fn leave(&self, room: RoomId, seat: Seat, id: u64) -> bool {
        let mut rooms = self.rooms();
        let Some(r) = rooms.get_mut(&room) else { return false };
        let left = match seat {
            Seat::Host if r.host_is(id) => {
                r.host = None;
                for c in r.clients.values() {
                    send_ctrl(c, Msg::Status { host_online: false });
                }
                true
            }
            Seat::Client(peer) if r.client_is(peer, id) => {
                r.clients.remove(&peer);
                if let Some(h) = &r.host {
                    send_ctrl(h, Msg::PeerClose(peer));
                }
                true
            }
            _ => false,
        };
        if r.host.is_none() && r.clients.is_empty() {
            rooms.remove(&room);
        }
        left
    }

    /// Handle one message from an authenticated peer. Err ends the link.
    fn forward(&self, room: RoomId, seat: Seat, id: u64, bytes: &[u8]) -> Result<(), &'static str> {
        let msg = Msg::decode(bytes).ok_or("sent a malformed message")?;
        match (seat, msg) {
            (Seat::Client(peer), Msg::ClientData(payload)) => {
                let out = encode(Msg::HostData { peer, payload });
                let mut rooms = self.rooms();
                let Some(r) = rooms.get_mut(&room) else { return Ok(()) };
                if !r.client_is(peer, id) {
                    return Ok(());
                }
                let Some(host) = &r.host else { return Ok(()) };
                if r.to_host.as_mut().is_some_and(|b| !b.take(out.len(), Instant::now())) {
                    return Ok(());
                }
                send_data(host, out);
                Ok(())
            }
            (Seat::Host, Msg::HostData { peer, payload }) => {
                let out = encode(Msg::ClientData(payload));
                let mut rooms = self.rooms();
                let Some(r) = rooms.get_mut(&room) else { return Ok(()) };
                if !r.host_is(id) {
                    return Ok(());
                }
                let Some(client) = r.clients.get(&peer) else { return Ok(()) };
                if r.to_clients.as_mut().is_some_and(|b| !b.take(out.len(), Instant::now())) {
                    return Ok(());
                }
                send_data(client, out);
                Ok(())
            }
            (Seat::Host, Msg::PeerClose(peer)) => {
                let removed = {
                    let mut rooms = self.rooms();
                    match rooms.get_mut(&room) {
                        // Dropping the client's Link closes its connection.
                        Some(r) if r.host_is(id) => r.clients.remove(&peer).is_some(),
                        _ => false,
                    }
                };
                if removed {
                    log!("client {peer} closed by the host of room {}", room.masked());
                }
                Ok(())
            }
            _ => Err("sent a message not meant for its role"),
        }
    }
}

/// Serve the relay on `listener` until it fails.
pub async fn serve(listener: TcpListener, config: Config) -> io::Result<()> {
    let shared = Arc::new(Shared { config, rooms: Mutex::new(HashMap::new()), next_link: AtomicU64::new(1) });
    let app = Router::new().fallback(dispatch).with_state(shared);
    let listener = listener.tap_io(|tcp| {
        let _ = tcp.set_nodelay(true);
    });
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await
}

async fn dispatch(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let read = method == Method::GET || method == Method::HEAD;
    match (uri.path(), upgrade) {
        ("/health", _) if read => (StatusCode::OK, "hyperspace relay ok\n").into_response(),
        ("/", _) if read => {
            let (hosts, clients) = shared.counts();
            let text = format!(
                "hyperspace relay {}: {hosts} host(s) online, {clients} client(s)\n",
                env!("CARGO_PKG_VERSION")
            );
            (StatusCode::OK, text).into_response()
        }
        (proto::PATH, Ok(upgrade)) => {
            let from = remote_addr(peer, &headers);
            upgrade
                .max_message_size(MAX_WS_MESSAGE)
                .max_frame_size(MAX_WS_MESSAGE)
                .on_upgrade(move |ws| connection(ws, shared, from))
        }
        _ => (StatusCode::NOT_FOUND, "not found\n").into_response(),
    }
}

/// The address to log for a connection: the proxy's X-Forwarded-For (its
/// last entry, which the proxy itself added) when the connection comes from
/// loopback, else the socket's peer.
fn remote_addr(peer: SocketAddr, headers: &HeaderMap) -> String {
    if peer.ip().is_loopback() {
        let forwarded = headers
            .get_all("x-forwarded-for")
            .iter()
            .last()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok());
        if let Some(ip) = forwarded {
            return ip.to_string();
        }
    }
    peer.ip().to_string()
}

/// One WebSocket connection, from CHALLENGE to close.
async fn connection(mut ws: WebSocket, shared: Arc<Shared>, from: String) {
    let nonce = proto::new_nonce();
    let hello = match tokio::time::timeout(shared.config.auth_timeout, challenge(&mut ws, &nonce)).await {
        Err(_) => return refuse(ws, None, refused::TIMEOUT, &from).await,
        Ok(None) => return,
        Ok(Some(Err(reason))) => return refuse(ws, None, reason, &from).await,
        Ok(Some(Ok(hello))) => hello,
    };
    let (role, room) = (hello.role, hello.room);
    let who = Some((role, room));
    if !hello.verify(&nonce) {
        return refuse(ws, who, refused::BAD_SIGNATURE, &from).await;
    }
    if !shared.allowed(&room) {
        return refuse(ws, who, refused::NOT_ALLOWED, &from).await;
    }

    let (tx, rx) = mpsc::channel(DATA_QUEUE + CTRL_RESERVE);
    let kill = Arc::new(Notify::new());
    let id = shared.next_link.fetch_add(1, Ordering::Relaxed);
    let link = Link { id, tx, kill: kill.clone() };
    let (first, seat) = match role {
        Role::Host => match shared.join_host(room, link) {
            Ok((first, replaced)) => {
                let note = if replaced { " (replacing the previous host)" } else { "" };
                log!("host joined room {} from {from}{note}", room.masked());
                (first, Seat::Host)
            }
            Err(reason) => return refuse(ws, who, reason, &from).await,
        },
        Role::Client => match shared.join_client(room, link) {
            Ok((first, peer, online)) => {
                let note = if online { "host online" } else { "waiting for the host" };
                log!("client {peer} joined room {} from {from} ({note})", room.masked());
                (first, Seat::Client(peer))
            }
            Err(reason) => return refuse(ws, who, reason, &from).await,
        },
    };

    let (sink, stream) = ws.split();
    let why = tokio::select! {
        why = write(sink, rx, first, shared.config.ping_interval) => why,
        why = read(stream, &shared, room, seat, id) => why,
        _ = kill.notified() => "too slow (its queue was full)".to_string(),
    };
    if shared.leave(room, seat, id) {
        match seat {
            Seat::Host => log!("host left room {}: {why}", room.masked()),
            Seat::Client(peer) => log!("client {peer} left room {}: {why}", room.masked()),
        }
    }
}

/// Send CHALLENGE and wait for the answer. None: the peer went away first.
async fn challenge(ws: &mut WebSocket, nonce: &[u8; proto::NONCE_LEN]) -> Option<Result<Hello, u8>> {
    let challenge = Msg::Challenge { version: proto::VERSION, nonce: *nonce };
    ws.send(Message::Binary(encode(challenge))).await.ok()?;
    loop {
        match ws.recv().await? {
            Ok(Message::Binary(b)) => return Some(parse_hello(&b)),
            Ok(Message::Close(_)) | Err(_) => return None,
            Ok(_) => {}
        }
    }
}

fn parse_hello(b: &[u8]) -> Result<Hello, u8> {
    // Checked before decoding: another version's HELLO may not even have
    // this version's length.
    if b.len() >= 2 && b[0] == mt::HELLO && b[1] != proto::VERSION {
        return Err(refused::VERSION_MISMATCH);
    }
    match Msg::decode(b) {
        Some(Msg::Hello(hello)) => Ok(hello),
        _ => Err(refused::PROTOCOL),
    }
}

/// Log a refusal, tell the peer why and close.
async fn refuse(mut ws: WebSocket, who: Option<(Role, RoomId)>, reason: u8, from: &str) {
    let why = refused::describe(reason);
    match who {
        Some((role, room)) => log!("refused {} for room {} from {from}: {why}", role.name(), room.masked()),
        None => log!("refused a connection from {from}: {why}"),
    }
    let _ = tokio::time::timeout(CLOSE_GRACE, async {
        ws.send(Message::Binary(encode(Msg::Refused(reason)))).await?;
        ws.send(Message::Close(Some(CloseFrame { code: close_code::POLICY, reason: "refused".into() }))).await?;
        // Let the peer read everything and answer the close.
        while let Some(Ok(m)) = ws.recv().await {
            if matches!(m, Message::Close(_)) {
                break;
            }
        }
        Ok::<(), axum::Error>(())
    })
    .await;
}

/// Writes everything queued for the link, plus pings. Returns when the link
/// fails or the room drops it (then it closes the WebSocket).
async fn write(
    mut sink: SplitSink<WebSocket, Message>,
    mut rx: mpsc::Receiver<Bytes>,
    first: Vec<Bytes>,
    ping: Duration,
) -> String {
    let lost = |e: axum::Error| format!("connection lost ({e})");
    for b in first {
        if let Err(e) = sink.feed(Message::Binary(b)).await {
            return lost(e);
        }
    }
    if let Err(e) = sink.flush().await {
        return lost(e);
    }
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + ping, ping);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            _ = tick.tick() => {
                if let Err(e) = sink.send(Message::Ping(Bytes::new())).await {
                    return lost(e);
                }
            }
            next = rx.recv() => {
                let Some(b) = next else {
                    // Removed from the room (replaced, or closed by the host).
                    let close = CloseFrame { code: close_code::NORMAL, reason: "".into() };
                    let _ = tokio::time::timeout(CLOSE_GRACE, sink.send(Message::Close(Some(close)))).await;
                    // Leave the reader time to see the peer's close.
                    tokio::time::sleep(CLOSE_GRACE).await;
                    return "removed".to_string();
                };
                if let Err(e) = sink.feed(Message::Binary(b)).await {
                    return lost(e);
                }
                for _ in 1..WRITE_BATCH {
                    let Ok(b) = rx.try_recv() else { break };
                    if let Err(e) = sink.feed(Message::Binary(b)).await {
                        return lost(e);
                    }
                }
                if let Err(e) = sink.flush().await {
                    return lost(e);
                }
            }
        }
    }
}

/// Reads and forwards the peer's messages until it closes, fails, goes
/// quiet for too long or breaks the protocol.
async fn read(mut stream: SplitStream<WebSocket>, shared: &Shared, room: RoomId, seat: Seat, id: u64) -> String {
    loop {
        let msg = match tokio::time::timeout(shared.config.idle_timeout, stream.next()).await {
            Err(_) => return "timed out".to_string(),
            Ok(None) => return "connection lost".to_string(),
            Ok(Some(Err(e))) => return format!("connection lost ({e})"),
            Ok(Some(Ok(msg))) => msg,
        };
        match msg {
            Message::Binary(b) => {
                if let Err(why) = shared.forward(room, seat, id, &b) {
                    return why.to_string();
                }
            }
            Message::Close(_) => {
                // Polling once more sends the reply to the peer's close.
                let _ = tokio::time::timeout(CLOSE_GRACE, stream.next()).await;
                return "closed".to_string();
            }
            // Text is ignored; pings and pongs only show the link is alive.
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_passes_its_burst_then_its_rate() {
        let t0 = Instant::now();
        let mut b = Bucket::new(Rate { bytes_per_sec: 1000, burst: 3000 }, t0);
        assert!(b.take(1000, t0));
        assert!(b.take(2000, t0));
        assert!(!b.take(1, t0), "burst used up");
        assert!(!b.take(600, t0 + Duration::from_millis(500)), "only 500 bytes back");
        assert!(b.take(500, t0 + Duration::from_millis(500)));
        // A long quiet spell refills up to the burst, not beyond.
        let later = t0 + Duration::from_secs(60);
        assert!(b.take(3000, later));
        assert!(!b.take(1, later));
        // Time going backwards (it cannot with Instant, but be safe) adds nothing.
        assert!(!b.take(1, t0));
    }

    #[test]
    fn rate_from_mbit() {
        assert_eq!(Rate::from_mbit(0), None);
        assert_eq!(Rate::from_mbit(60), Some(Rate { bytes_per_sec: 7_500_000, burst: 1_875_000 }));
        assert_eq!(Rate::from_mbit(1).unwrap().burst, 256 * 1024);
        assert_eq!(Rate::from_mbit(60).unwrap().to_string(), "60 Mbit/s");
    }

    #[test]
    fn utc_timestamps() {
        assert_eq!(utc(0), "1970-01-01 00:00:00Z");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00Z");
        assert_eq!(utc(1_700_000_000), "2023-11-14 22:13:20Z");
        assert_eq!(utc(4_107_542_399), "2100-02-28 23:59:59Z");
    }

    #[test]
    fn peer_ids_skip_zero_and_ids_in_use() {
        let mut room = Room::new(None);
        let (tx, _rx) = mpsc::channel(1);
        let link = |id| Link { id, tx: tx.clone(), kill: Arc::new(Notify::new()) };
        assert_eq!(room.alloc_peer(), 1);
        room.clients.insert(2, link(1));
        assert_eq!(room.alloc_peer(), 3);
        room.next_peer = u32::MAX;
        assert_eq!(room.alloc_peer(), u32::MAX);
        assert_eq!(room.alloc_peer(), 1);
        assert_eq!(room.alloc_peer(), 3, "2 is taken");
    }

    #[test]
    fn allow_file_format() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("hyperspace-relay-allow-unit-{}", std::process::id()));
        let id = RoomId::from_bytes([0xab; 32]);
        let text = format!("# relay allow list\n\n  {}  # the office PC\nnot an id\n{}\n", id.hex(), id.hex().to_uppercase());
        std::fs::write(&path, text).unwrap();
        let (ids, bad) = read_allow_file(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(ids.len(), 1);
        assert!(ids.contains(&id));
        assert_eq!(bad, 1);
        assert!(read_allow_file(&path).is_err());
    }

    #[test]
    fn hello_version_is_checked_before_its_layout() {
        let mut b = vec![mt::HELLO, proto::VERSION + 1];
        assert_eq!(parse_hello(&b).unwrap_err(), refused::VERSION_MISMATCH);
        b[1] = proto::VERSION;
        assert_eq!(parse_hello(&b).unwrap_err(), refused::PROTOCOL);
        assert_eq!(parse_hello(&[mt::OK]).unwrap_err(), refused::PROTOCOL);
    }

    #[test]
    fn forwarded_for_is_trusted_from_loopback_only() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "10.1.2.3, 192.0.2.7".parse().unwrap());
        let local: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let remote: SocketAddr = "198.51.100.1:5000".parse().unwrap();
        assert_eq!(remote_addr(local, &headers), "192.0.2.7");
        assert_eq!(remote_addr(remote, &headers), "198.51.100.1");
        headers.insert("x-forwarded-for", "<script>".parse().unwrap());
        assert_eq!(remote_addr(local, &headers), "127.0.0.1");
        assert_eq!(remote_addr(local, &HeaderMap::new()), "127.0.0.1");
    }
}
