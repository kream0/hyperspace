//! The relay end to end, over real sockets on loopback.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hyperspace_proto::relay::{self, refused, Msg, Role, RoomKey};
use hyperspace_proto::secure::Key;
use hyperspace_relay::{Allow, Config, Rate};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

/// Upper bound for anything a test waits for.
const WAIT: Duration = Duration::from_secs(5);

fn config(allow: Allow) -> Config {
    let mut c = Config::new(allow);
    c.rate = None;
    c.auth_timeout = Duration::from_millis(300);
    c
}

async fn start(config: Config) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        hyperspace_relay::serve(listener, config).await.unwrap();
    });
    addr
}

fn room() -> RoomKey {
    RoomKey::derive(&Key::generate())
}

async fn connect(addr: SocketAddr) -> Ws {
    let url = format!("ws://{addr}{}", relay::PATH);
    let (ws, _) = timeout(WAIT, tokio_tungstenite::connect_async(url)).await.expect("connect timed out").unwrap();
    ws
}

/// The next binary message, or None once the connection has ended.
async fn next(ws: &mut Ws) -> Option<Vec<u8>> {
    loop {
        match timeout(WAIT, ws.next()).await.expect("timed out waiting for the relay") {
            Some(Ok(Message::Binary(b))) => return Some(b.to_vec()),
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return None,
            Some(Ok(_)) => {}
        }
    }
}

async fn expect(ws: &mut Ws, want: Msg<'_>) {
    let got = next(ws).await.unwrap_or_else(|| panic!("connection ended while waiting for {want:?}"));
    assert_eq!(Msg::decode(&got), Some(want));
}

async fn expect_closed(ws: &mut Ws) {
    if let Some(b) = next(ws).await {
        panic!("expected the relay to close, got {:?}", Msg::decode(&b));
    }
}

/// Nothing arrives for a little while.
async fn expect_quiet(ws: &mut Ws) {
    match timeout(Duration::from_millis(300), ws.next()).await {
        Err(_) => {}
        Ok(Some(Ok(Message::Binary(b)))) => panic!("unexpected {:?}", Msg::decode(&b)),
        Ok(other) => panic!("unexpected {other:?}"),
    }
}

async fn send(ws: &mut Ws, msg: Msg<'_>) {
    ws.send(Message::binary(msg.encode())).await.unwrap();
}

async fn challenge(ws: &mut Ws) -> [u8; relay::NONCE_LEN] {
    let b = next(ws).await.expect("no CHALLENGE");
    match Msg::decode(&b) {
        Some(Msg::Challenge { version, nonce }) => {
            assert_eq!(version, relay::VERSION);
            nonce
        }
        other => panic!("expected CHALLENGE, got {other:?}"),
    }
}

/// Connect and authenticate; returns the socket and the relay's answer.
async fn try_join(addr: SocketAddr, key: &RoomKey, role: Role) -> (Ws, Vec<u8>) {
    let mut ws = connect(addr).await;
    let nonce = challenge(&mut ws).await;
    send(&mut ws, Msg::Hello(key.hello(role, &nonce))).await;
    let answer = next(&mut ws).await.expect("no answer to HELLO");
    (ws, answer)
}

async fn join(addr: SocketAddr, key: &RoomKey, role: Role) -> Ws {
    let (ws, answer) = try_join(addr, key, role).await;
    assert_eq!(Msg::decode(&answer), Some(Msg::Ok));
    ws
}

async fn join_refused(addr: SocketAddr, key: &RoomKey, role: Role, reason: u8) {
    let (mut ws, answer) = try_join(addr, key, role).await;
    assert_eq!(Msg::decode(&answer), Some(Msg::Refused(reason)), "{}", refused::describe(reason));
    expect_closed(&mut ws).await;
}

/// A client: joins and reads its first STATUS.
async fn client(addr: SocketAddr, key: &RoomKey, host_online: bool) -> Ws {
    let mut ws = join(addr, key, Role::Client).await;
    expect(&mut ws, Msg::Status { host_online }).await;
    ws
}

/// Status line and body of a plain HTTP/1.1 request.
async fn http(addr: SocketAddr, method: &str, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!("{method} {path} HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    timeout(WAIT, s.read_to_end(&mut buf)).await.expect("HTTP timed out").unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or_else(|| panic!("bad response {text:?}"));
    let body = text.split_once("\r\n\r\n").map_or("", |(_, b)| b).to_string();
    (status, body)
}

struct TempFile(PathBuf);

impl TempFile {
    fn new(contents: &str) -> TempFile {
        static N: AtomicUsize = AtomicUsize::new(0);
        let name = format!("hyperspace-relay-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed));
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, contents).unwrap();
        TempFile(path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[tokio::test]
async fn datagrams_flow_both_ways() {
    let addr = start(config(Allow::Open)).await;
    let key = room();
    let mut host = join(addr, &key, Role::Host).await;
    let mut a = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(1)).await;
    let mut b = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(2)).await;

    send(&mut a, Msg::ClientData(b"from a")).await;
    expect(&mut host, Msg::HostData { peer: 1, payload: b"from a" }).await;
    send(&mut b, Msg::ClientData(b"from b")).await;
    expect(&mut host, Msg::HostData { peer: 2, payload: b"from b" }).await;

    // Data for a peer that does not exist is dropped; the rest still flows.
    send(&mut host, Msg::HostData { peer: 9, payload: b"nobody" }).await;
    send(&mut host, Msg::HostData { peer: 2, payload: b"to b" }).await;
    send(&mut host, Msg::HostData { peer: 1, payload: b"to a" }).await;
    expect(&mut b, Msg::ClientData(b"to b")).await;
    expect(&mut a, Msg::ClientData(b"to a")).await;

    // Largest datagram, and an empty one.
    let big = vec![0x5a; relay::MAX_PAYLOAD];
    send(&mut a, Msg::ClientData(&big)).await;
    expect(&mut host, Msg::HostData { peer: 1, payload: &big }).await;
    send(&mut host, Msg::HostData { peer: 1, payload: b"" }).await;
    expect(&mut a, Msg::ClientData(b"")).await;

    // Text messages are ignored.
    a.send(Message::text("hello?")).await.unwrap();
    send(&mut a, Msg::ClientData(b"after text")).await;
    expect(&mut host, Msg::HostData { peer: 1, payload: b"after text" }).await;
    expect_quiet(&mut b).await;
}

#[tokio::test]
async fn clients_wait_for_the_host() {
    let addr = start(config(Allow::Open)).await;
    let key = room();
    let mut a = client(addr, &key, false).await;
    let mut b = client(addr, &key, false).await;
    // Sent while no host is online: dropped.
    send(&mut a, Msg::ClientData(b"lost")).await;
    expect_quiet(&mut a).await;

    let mut host = join(addr, &key, Role::Host).await;
    expect(&mut host, Msg::PeerOpen(1)).await;
    expect(&mut host, Msg::PeerOpen(2)).await;
    expect(&mut a, Msg::Status { host_online: true }).await;
    expect(&mut b, Msg::Status { host_online: true }).await;
    send(&mut a, Msg::ClientData(b"kept")).await;
    expect(&mut host, Msg::HostData { peer: 1, payload: b"kept" }).await;

    host.close(None).await.unwrap();
    expect(&mut a, Msg::Status { host_online: false }).await;
    expect(&mut b, Msg::Status { host_online: false }).await;

    // The host comes back and sees the same clients.
    let mut host = join(addr, &key, Role::Host).await;
    expect(&mut host, Msg::PeerOpen(1)).await;
    expect(&mut host, Msg::PeerOpen(2)).await;
    expect(&mut a, Msg::Status { host_online: true }).await;
    expect(&mut b, Msg::Status { host_online: true }).await;
}

#[tokio::test]
async fn the_host_hears_when_a_client_leaves() {
    let addr = start(config(Allow::Open)).await;
    let key = room();
    let mut host = join(addr, &key, Role::Host).await;
    let mut a = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(1)).await;
    a.close(None).await.unwrap();
    expect(&mut host, Msg::PeerClose(1)).await;

    // A client that just drops the TCP connection counts too.
    let b = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(2)).await;
    drop(b);
    expect(&mut host, Msg::PeerClose(2)).await;

    // Data for a closed peer is dropped.
    send(&mut host, Msg::HostData { peer: 1, payload: b"gone" }).await;
    let mut c = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(3)).await;
    expect_quiet(&mut c).await;
}

#[tokio::test]
async fn the_host_can_close_a_client() {
    let addr = start(config(Allow::Open)).await;
    let key = room();
    let mut host = join(addr, &key, Role::Host).await;
    let mut a = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(1)).await;
    let mut b = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(2)).await;

    send(&mut host, Msg::PeerClose(1)).await;
    expect_closed(&mut a).await;
    // No PEER_CLOSE echoed back for a close the host asked for; the other
    // client is untouched.
    send(&mut b, Msg::ClientData(b"still here")).await;
    expect(&mut host, Msg::HostData { peer: 2, payload: b"still here" }).await;
    let _c = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(3)).await;
}

#[tokio::test]
async fn a_new_host_replaces_the_old_one() {
    let addr = start(config(Allow::Open)).await;
    let key = room();
    let mut old = join(addr, &key, Role::Host).await;
    let mut a = client(addr, &key, true).await;
    expect(&mut old, Msg::PeerOpen(1)).await;

    let mut new = join(addr, &key, Role::Host).await;
    expect(&mut new, Msg::PeerOpen(1)).await;
    expect_closed(&mut old).await;
    // STATUS true again tells the client a new host is there.
    expect(&mut a, Msg::Status { host_online: true }).await;
    send(&mut a, Msg::ClientData(b"to the new host")).await;
    expect(&mut new, Msg::HostData { peer: 1, payload: b"to the new host" }).await;
    // The old host leaving later does not take the room offline.
    expect_quiet(&mut a).await;
}

#[tokio::test]
async fn rooms_are_separate() {
    let addr = start(config(Allow::Open)).await;
    let (k1, k2) = (room(), room());
    let mut h1 = join(addr, &k1, Role::Host).await;
    let mut h2 = join(addr, &k2, Role::Host).await;
    let mut c2 = client(addr, &k2, true).await;
    expect(&mut h2, Msg::PeerOpen(1)).await;
    send(&mut c2, Msg::ClientData(b"room 2")).await;
    expect(&mut h2, Msg::HostData { peer: 1, payload: b"room 2" }).await;
    expect_quiet(&mut h1).await;
}

#[tokio::test]
async fn the_allow_list_is_read_on_every_connection() {
    let key = room();
    let other = room();
    let file = TempFile::new(&format!("# allowed rooms\n{}  # someone else\n", other.id().hex()));
    let addr = start(config(Allow::File(file.0.clone()))).await;

    join_refused(addr, &key, Role::Host, refused::NOT_ALLOWED).await;
    join_refused(addr, &key, Role::Client, refused::NOT_ALLOWED).await;

    std::fs::write(&file.0, format!("{}\n{}\n", other.id().hex(), key.id().hex())).unwrap();
    let mut host = join(addr, &key, Role::Host).await;
    let mut a = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(1)).await;

    // Removing the id stops new connections; existing ones stay.
    std::fs::write(&file.0, "").unwrap();
    join_refused(addr, &key, Role::Client, refused::NOT_ALLOWED).await;
    // An unreadable list refuses everyone.
    std::fs::remove_file(&file.0).unwrap();
    join_refused(addr, &other, Role::Host, refused::NOT_ALLOWED).await;
    send(&mut host, Msg::HostData { peer: 1, payload: b"still on" }).await;
    expect(&mut a, Msg::ClientData(b"still on")).await;
}

#[tokio::test]
async fn a_bad_signature_is_refused() {
    let addr = start(config(Allow::Open)).await;
    let key = room();

    // Tampered signature.
    let mut ws = connect(addr).await;
    let nonce = challenge(&mut ws).await;
    let mut hello = key.hello(Role::Host, &nonce);
    hello.signature[10] ^= 1;
    send(&mut ws, Msg::Hello(hello)).await;
    expect(&mut ws, Msg::Refused(refused::BAD_SIGNATURE)).await;
    expect_closed(&mut ws).await;

    // A HELLO recorded on another connection (other nonce).
    let mut ws = connect(addr).await;
    let _nonce = challenge(&mut ws).await;
    send(&mut ws, Msg::Hello(key.hello(Role::Host, &[7; relay::NONCE_LEN]))).await;
    expect(&mut ws, Msg::Refused(refused::BAD_SIGNATURE)).await;

    // Signed as a client, claiming to be the host.
    let mut ws = connect(addr).await;
    let nonce = challenge(&mut ws).await;
    let mut hello = key.hello(Role::Client, &nonce);
    hello.role = Role::Host;
    send(&mut ws, Msg::Hello(hello)).await;
    expect(&mut ws, Msg::Refused(refused::BAD_SIGNATURE)).await;

    // Someone else's room id with our signature.
    let mut ws = connect(addr).await;
    let nonce = challenge(&mut ws).await;
    let mut hello = key.hello(Role::Host, &nonce);
    hello.room = room().id();
    send(&mut ws, Msg::Hello(hello)).await;
    expect(&mut ws, Msg::Refused(refused::BAD_SIGNATURE)).await;

    // The genuine key still gets in.
    join(addr, &key, Role::Host).await;
}

#[tokio::test]
async fn a_version_mismatch_is_refused() {
    let addr = start(config(Allow::Open)).await;
    let key = room();
    let mut ws = connect(addr).await;
    let nonce = challenge(&mut ws).await;
    let mut hello = Msg::Hello(key.hello(Role::Client, &nonce)).encode();
    hello[1] = relay::VERSION + 1;
    ws.send(Message::binary(hello)).await.unwrap();
    expect(&mut ws, Msg::Refused(refused::VERSION_MISMATCH)).await;
    expect_closed(&mut ws).await;

    // Garbage instead of HELLO.
    let mut ws = connect(addr).await;
    challenge(&mut ws).await;
    ws.send(Message::binary(vec![relay::mt::HELLO, relay::VERSION, 1])).await.unwrap();
    expect(&mut ws, Msg::Refused(refused::PROTOCOL)).await;
}

#[tokio::test]
async fn a_silent_connection_is_refused_after_the_auth_timeout() {
    let addr = start(config(Allow::Open)).await;
    let mut ws = connect(addr).await;
    challenge(&mut ws).await;
    expect(&mut ws, Msg::Refused(refused::TIMEOUT)).await;
    expect_closed(&mut ws).await;
}

#[tokio::test]
async fn room_and_relay_limits() {
    let mut c = config(Allow::Open);
    c.max_rooms = 1;
    c.max_clients = 2;
    let addr = start(c).await;
    let key = room();
    let _a = client(addr, &key, false).await;
    let b = client(addr, &key, false).await;
    join_refused(addr, &key, Role::Client, refused::ROOM_FULL).await;
    join_refused(addr, &room(), Role::Host, refused::RELAY_FULL).await;
    join_refused(addr, &room(), Role::Client, refused::RELAY_FULL).await;
    // The full room still takes its host.
    let mut host = join(addr, &key, Role::Host).await;
    expect(&mut host, Msg::PeerOpen(1)).await;
    expect(&mut host, Msg::PeerOpen(2)).await;

    // A seat frees up once a client leaves.
    drop(b);
    expect(&mut host, Msg::PeerClose(2)).await;
    let _c = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(3)).await;
}

#[tokio::test]
async fn oversized_or_malformed_messages_close_the_link() {
    let addr = start(config(Allow::Open)).await;
    let key = room();
    let mut host = join(addr, &key, Role::Host).await;

    // Over the WebSocket limit.
    let mut a = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(1)).await;
    let _ = a.send(Message::binary(vec![relay::mt::CLIENT_DATA; 20_000])).await;
    expect_closed(&mut a).await;
    expect(&mut host, Msg::PeerClose(1)).await;

    // Under the WebSocket limit but over the datagram limit.
    let mut b = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(2)).await;
    let _ = b.send(Message::binary(vec![relay::mt::CLIENT_DATA; relay::MAX_PAYLOAD + 2])).await;
    expect_closed(&mut b).await;
    expect(&mut host, Msg::PeerClose(2)).await;

    // A message for the other role.
    let mut c = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(3)).await;
    send(&mut c, Msg::HostData { peer: 3, payload: b"spoof" }).await;
    expect_closed(&mut c).await;
    expect(&mut host, Msg::PeerClose(3)).await;

    // The relay is fine.
    assert_eq!(http(addr, "GET", "/health").await, (200, "hyperspace relay ok\n".to_string()));
    let mut d = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(4)).await;
    send(&mut d, Msg::ClientData(b"ok")).await;
    expect(&mut host, Msg::HostData { peer: 4, payload: b"ok" }).await;
}

#[tokio::test]
async fn quiet_links_are_pinged_and_dead_ones_closed() {
    let mut c = config(Allow::Open);
    c.ping_interval = Duration::from_millis(100);
    c.idle_timeout = Duration::from_millis(600);
    let addr = start(c).await;
    let key = room();
    let mut host = join(addr, &key, Role::Host).await;
    let a = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(1)).await;

    // The host keeps reading (so it answers pings) for well over the idle
    // timeout; the client never reads, so it never answers and is closed.
    let mut pings = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
    let mut closed = false;
    while let Ok(m) = tokio::time::timeout_at(deadline, host.next()).await {
        match m {
            Some(Ok(Message::Ping(_))) => pings += 1,
            Some(Ok(Message::Binary(b))) => {
                assert_eq!(Msg::decode(&b), Some(Msg::PeerClose(1)));
                closed = true;
            }
            other => panic!("host link ended: {other:?}"),
        }
    }
    assert!(closed, "the silent client was not closed");
    assert!(pings >= 5, "only {pings} pings");
    drop(a);
    // The host is still connected.
    let _b = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(2)).await;
}

#[tokio::test]
async fn each_direction_is_rate_limited() {
    let mut c = config(Allow::Open);
    c.rate = Some(Rate { bytes_per_sec: 1000, burst: 5000 });
    let addr = start(c).await;
    let key = room();
    let mut host = join(addr, &key, Role::Host).await;
    let mut a = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(1)).await;

    // 20 datagrams of about 1 KB at once: the 5 KB burst lets 5 through.
    let payload = vec![1u8; 995];
    for _ in 0..20 {
        send(&mut a, Msg::ClientData(&payload)).await;
    }
    tokio::time::sleep(Duration::from_millis(1100)).await;
    send(&mut a, Msg::ClientData(b"end")).await;
    let mut passed = 0;
    loop {
        let b = next(&mut host).await.expect("host link ended");
        match Msg::decode(&b) {
            Some(Msg::HostData { peer: 1, payload: p }) if p == payload.as_slice() => passed += 1,
            Some(Msg::HostData { peer: 1, payload: b"end" }) => break,
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!((4..=6).contains(&passed), "{passed} of 20 passed");

    // The other direction has its own bucket.
    for _ in 0..3 {
        send(&mut host, Msg::HostData { peer: 1, payload: &payload }).await;
    }
    for _ in 0..3 {
        expect(&mut a, Msg::ClientData(&payload)).await;
    }
}

#[tokio::test]
async fn http_endpoints() {
    let addr = start(config(Allow::Open)).await;
    assert_eq!(http(addr, "GET", "/health").await, (200, "hyperspace relay ok\n".to_string()));
    let version = env!("CARGO_PKG_VERSION");
    let status = |h: usize, c: usize| -> (u16, String) { (200, format!("hyperspace relay {version}: {h} host(s) online, {c} client(s)\n")) };
    assert_eq!(http(addr, "GET", "/").await, status(0, 0));

    let key = room();
    let mut host = join(addr, &key, Role::Host).await;
    let _a = client(addr, &key, true).await;
    let _b = client(addr, &room(), false).await;
    expect(&mut host, Msg::PeerOpen(1)).await;
    assert_eq!(http(addr, "GET", "/").await, status(1, 2));

    assert_eq!(http(addr, "GET", "/nope").await.0, 404);
    assert_eq!(http(addr, "GET", "/v1").await.0, 404, "no upgrade");
    assert_eq!(http(addr, "POST", "/health").await.0, 404);
    assert_eq!(http(addr, "GET", "/health/x").await.0, 404);
}
