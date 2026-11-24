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
    try_connect(addr).await.unwrap_or_else(|status| panic!("HTTP {status} instead of an upgrade"))
}

/// Open a WebSocket, or the HTTP status the relay answered instead.
async fn try_connect(addr: SocketAddr) -> Result<Ws, u16> {
    let url = format!("ws://{addr}{}", relay::PATH);
    match timeout(WAIT, tokio_tungstenite::connect_async(url)).await.expect("connect timed out") {
        Ok((ws, _)) => Ok(ws),
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => Err(response.status().as_u16()),
        Err(e) => panic!("connect failed: {e}"),
    }
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

/// The relay dropped the connection without a close frame. Pings may come
/// first; the end shows as an error or as the end of the stream.
async fn expect_dropped(ws: &mut Ws) {
    loop {
        match timeout(WAIT, ws.next()).await.expect("timed out waiting for the relay to drop the link") {
            Some(Ok(Message::Close(frame))) => panic!("expected no close frame, got {frame:?}"),
            Some(Ok(Message::Binary(b))) => panic!("expected the link to be dropped, got {:?}", Msg::decode(&b)),
            Some(Ok(_)) => {}
            Some(Err(_)) | None => return,
        }
    }
}

/// The close frame the relay sends after REFUSED.
async fn expect_refused_close(ws: &mut Ws) {
    assert_eq!(close_frame(ws).await, (1008, "refused".to_string()));
}

/// Code and reason of the close frame the relay sends next.
async fn close_frame(ws: &mut Ws) -> (u16, String) {
    loop {
        match timeout(WAIT, ws.next()).await.expect("timed out waiting for the close") {
            Some(Ok(Message::Close(Some(frame)))) => return (u16::from(frame.code), frame.reason.as_str().to_string()),
            Some(Ok(Message::Binary(b))) => panic!("expected a close, got {:?}", Msg::decode(&b)),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            other => panic!("expected a close frame, got {other:?}"),
        }
    }
}

/// Queue `n` datagrams of `payload` for `peer` and flush once.
async fn blast(host: &mut Ws, peer: u32, payload: &[u8], n: usize) {
    for _ in 0..n {
        host.feed(Message::binary(Msg::HostData { peer, payload }.encode())).await.unwrap();
    }
    host.flush().await.unwrap();
}

/// What GET / says for this many hosts and clients (to a local request).
fn counts(hosts: usize, clients: usize) -> String {
    format!("hyperspace relay {}: {hosts} host(s) online, {clients} client(s)\n", env!("CARGO_PKG_VERSION"))
}

/// Polls GET / until it answers `want` or [`WAIT`] runs out.
async fn wait_for_counts(addr: SocketAddr, want: &str) {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let (_, body) = http(addr, "GET", "/").await;
        if body == want {
            return;
        }
        assert!(tokio::time::Instant::now() < deadline, "GET / still says {body:?}, waiting for {want:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
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
    expect_refused_close(&mut ws).await;
}

/// A client: joins and reads its first STATUS.
async fn client(addr: SocketAddr, key: &RoomKey, host_online: bool) -> Ws {
    let mut ws = join(addr, key, Role::Client).await;
    expect(&mut ws, Msg::Status { host_online }).await;
    ws
}

/// A client that will stop reading. Its receive buffer is a few kilobytes,
/// so the relay's writes to it back up soon on every platform.
async fn slow_client(addr: SocketAddr, key: &RoomKey) -> Ws {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    let tcp = timeout(WAIT, socket.connect(addr)).await.expect("connect timed out").unwrap();
    let url = format!("ws://{addr}{}", relay::PATH);
    let handshake = tokio_tungstenite::client_async(url, tokio_tungstenite::MaybeTlsStream::Plain(tcp));
    let (mut ws, _) = timeout(WAIT, handshake).await.expect("handshake timed out").unwrap();
    let nonce = challenge(&mut ws).await;
    send(&mut ws, Msg::Hello(key.hello(Role::Client, &nonce))).await;
    expect(&mut ws, Msg::Ok).await;
    expect(&mut ws, Msg::Status { host_online: true }).await;
    ws
}

/// Status line and body of a plain HTTP/1.1 request.
async fn http(addr: SocketAddr, method: &str, path: &str) -> (u16, String) {
    http_with(addr, method, path, "").await
}

/// The same, with extra header lines (each ending in CRLF).
async fn http_with(addr: SocketAddr, method: &str, path: &str, headers: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!("{method} {path} HTTP/1.1\r\nHost: relay.test\r\n{headers}Connection: close\r\n\r\n");
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
    // A close frame of its own: 4001 goes only to a replaced host.
    assert_eq!(close_frame(&mut a).await, (1000, "closed by the host".to_string()));
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
    // What the old host sends before it reads its close is ignored: no
    // datagram reaches the client, and it cannot close the client.
    send(&mut old, Msg::HostData { peer: 1, payload: b"stale" }).await;
    send(&mut old, Msg::PeerClose(1)).await;
    // Closed with a code of its own, so it backs off instead of taking the
    // room back.
    assert_eq!(close_frame(&mut old).await, (relay::close::REPLACED, relay::close::REPLACED_REASON.to_string()));
    // STATUS true again tells the client a new host is there.
    expect(&mut a, Msg::Status { host_online: true }).await;
    expect_quiet(&mut a).await;
    expect_quiet(&mut new).await;
    send(&mut a, Msg::ClientData(b"to the new host")).await;
    expect(&mut new, Msg::HostData { peer: 1, payload: b"to the new host" }).await;
    send(&mut new, Msg::HostData { peer: 1, payload: b"from the new host" }).await;
    expect(&mut a, Msg::ClientData(b"from the new host")).await;
    // The old host leaving later does not take the room offline.
    drop(old);
    expect_quiet(&mut a).await;
}

#[tokio::test]
async fn a_client_that_stops_reading_does_not_hold_up_the_room() {
    let mut c = config(Allow::Open);
    c.write_timeout = Duration::from_millis(500);
    let addr = start(c).await;
    let key = room();
    let mut host = join(addr, &key, Role::Host).await;
    // Never read: the relay's writes to it pile up.
    let _slow = slow_client(addr, &key).await;
    expect(&mut host, Msg::PeerOpen(1)).await;
    let mut fast = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(2)).await;

    // The host floods the slow client and keeps talking to the other one,
    // which hears every datagram meant for it, without delay, while the
    // slow client's socket and queue fill up; then the slow client is closed.
    let big = vec![0x5a; relay::MAX_PAYLOAD];
    let deadline = tokio::time::Instant::now() + 4 * WAIT;
    let mut round = 0u32;
    let closed = loop {
        blast(&mut host, 1, &big, 32).await;
        let mark = round.to_le_bytes();
        send(&mut host, Msg::HostData { peer: 2, payload: &mark }).await;
        expect(&mut fast, Msg::ClientData(&mark)).await;
        round += 1;
        match timeout(Duration::from_millis(5), host.next()).await {
            Err(_) | Ok(Some(Ok(Message::Ping(_)))) => {}
            Ok(Some(Ok(Message::Binary(b)))) => break Msg::decode(&b) == Some(Msg::PeerClose(1)),
            Ok(other) => panic!("host link ended: {other:?}"),
        }
        assert!(tokio::time::Instant::now() < deadline, "the slow client was not closed after {round} rounds");
    };
    assert!(closed, "expected PEER_CLOSE for the slow client");

    // Its seat is free, and the room carries on.
    assert_eq!(http(addr, "GET", "/").await, (200, counts(1, 1)));
    send(&mut fast, Msg::ClientData(b"still here")).await;
    expect(&mut host, Msg::HostData { peer: 2, payload: b"still here" }).await;
    let _c = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(3)).await;
}

#[tokio::test]
async fn a_client_that_cannot_take_a_control_message_is_closed_at_once() {
    let mut c = config(Allow::Open);
    // Far longer than the test: only a full queue can close the client here.
    c.write_timeout = Duration::from_secs(300);
    c.idle_timeout = Duration::from_secs(300);
    // Room for the 80 hosts below, even if replaced ones linger a moment.
    c.max_links = 1024;
    let addr = start(c).await;
    let key = room();
    let mut host = join(addr, &key, Role::Host).await;
    let _slow = slow_client(addr, &key).await;
    expect(&mut host, Msg::PeerOpen(1)).await;
    let mut fast = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(2)).await;

    // 32 MB fills the socket buffers between the relay and the slow client,
    // then its queue up to its byte limit; the rest is dropped.
    let big = vec![0x5a; relay::MAX_PAYLOAD];
    for _ in 0..64 {
        blast(&mut host, 1, &big, 64).await;
    }
    // Small datagrams then take every slot but the ones kept for control
    // messages; the rest is dropped.
    blast(&mut host, 1, b"x", 400).await;
    // The relay handles a link's messages in order: once this reaches the
    // other client, all of the above has been queued or dropped.
    send(&mut host, Msg::HostData { peer: 2, payload: b"sync" }).await;
    expect(&mut fast, Msg::ClientData(b"sync")).await;
    // Each new host sends STATUS to every client. The reserve takes 64; the
    // next one cannot be queued, and the slow client is closed rather than
    // left with a gap in its STATUS sequence.
    let started = tokio::time::Instant::now();
    for _ in 0..80 {
        host = join(addr, &key, Role::Host).await;
    }
    wait_for_counts(addr, &counts(1, 1)).await;
    assert!(started.elapsed() < Duration::from_secs(20), "closed by a timeout, not at once");

    // The other client kept up: it has every STATUS, and still gets data.
    send(&mut host, Msg::HostData { peer: 2, payload: b"still here" }).await;
    let mut statuses = 0;
    loop {
        let b = next(&mut fast).await.expect("the other client was closed");
        match Msg::decode(&b) {
            Some(Msg::Status { host_online: true }) => statuses += 1,
            Some(Msg::ClientData(b"still here")) => break,
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(statuses, 80);
}

#[tokio::test]
async fn a_removed_link_that_stops_reading_gives_its_slot_back_in_time() {
    let mut c = config(Allow::Open);
    // Far longer than the test: only the close deadline can end the link.
    c.write_timeout = Duration::from_secs(300);
    c.idle_timeout = Duration::from_secs(300);
    c.max_links = 3;
    let addr = start(c).await;
    let key = room();
    let mut host = join(addr, &key, Role::Host).await;
    let _slow = slow_client(addr, &key).await;
    expect(&mut host, Msg::PeerOpen(1)).await;
    let mut fast = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(2)).await;
    assert_eq!(try_connect(addr).await.err(), Some(503), "every link slot is taken");

    // Fill the socket buffers between the relay and the slow client, then
    // its queue: the relay's writer for it is stuck on a write.
    let big = vec![0x5a; relay::MAX_PAYLOAD];
    for _ in 0..64 {
        blast(&mut host, 1, &big, 64).await;
    }
    send(&mut host, Msg::HostData { peer: 2, payload: b"sync" }).await;
    expect(&mut fast, Msg::ClientData(b"sync")).await;

    // The host lets it go. Its writer can take neither the rest of the queue
    // nor the close, yet the link ends at its deadline (5 s) and gives its
    // slot back, long before the write timeout.
    send(&mut host, Msg::PeerClose(1)).await;
    let started = tokio::time::Instant::now();
    let mut d = loop {
        match try_connect(addr).await {
            Ok(ws) => break ws,
            Err(status) => assert_eq!(status, 503),
        }
        assert!(started.elapsed() < Duration::from_secs(7), "the removed link still holds its slot");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    challenge(&mut d).await;
    send(&mut fast, Msg::ClientData(b"still here")).await;
    expect(&mut host, Msg::HostData { peer: 2, payload: b"still here" }).await;
}

#[tokio::test]
async fn a_host_replaced_over_and_over_does_not_fill_the_relay() {
    let mut c = config(Allow::Open);
    // Far longer than the test: only the cap on closing links ends them.
    c.write_timeout = Duration::from_secs(300);
    c.idle_timeout = Duration::from_secs(300);
    c.max_links = 7;
    let addr = start(c).await;
    let key = room();

    // Hosts that never read, so never answer the close: each replaced one
    // would hold its slot until its close deadline (5 s). Without the cap
    // on closing links, these 7 take every slot: 6 closing, 1 seated.
    let mut hosts = vec![join(addr, &key, Role::Host).await];
    let started = tokio::time::Instant::now();
    for _ in 0..6 {
        hosts.push(join(addr, &key, Role::Host).await);
    }

    // With it, the room keeps 4 closing and the 2 oldest were dropped at
    // once, giving their slots back long before the deadline.
    let mut a = loop {
        match try_connect(addr).await {
            Ok(ws) => break ws,
            Err(status) => assert_eq!(status, 503),
        }
        assert!(started.elapsed() < Duration::from_secs(3), "replaced hosts still hold every slot");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    // And the last host holds the room.
    let nonce = challenge(&mut a).await;
    send(&mut a, Msg::Hello(key.hello(Role::Client, &nonce))).await;
    expect(&mut a, Msg::Ok).await;
    expect(&mut a, Msg::Status { host_online: true }).await;
    expect(hosts.last_mut().unwrap(), Msg::PeerOpen(1)).await;
}

/// Linux doubles the size set, and must not grow it: a proxy that stops
/// reading would otherwise make it grow up to megabytes.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn connections_have_small_kernel_buffers() {
    let listener = hyperspace_relay::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let _peer = TcpStream::connect(addr).await.unwrap();
    let (tcp, _) = timeout(WAIT, listener.accept()).await.expect("accept timed out").unwrap();
    let socket = tokio::net::TcpSocket::from_std_stream(tcp.into_std().unwrap());
    let size = 2 * hyperspace_relay::SOCKET_BUFFER;
    assert_eq!(socket.send_buffer_size().unwrap(), size);
    assert_eq!(socket.recv_buffer_size().unwrap(), size);
}

#[tokio::test]
async fn connections_past_the_limits_are_answered_503() {
    let mut c = config(Allow::Open);
    c.max_pending = 2;
    c.max_links = 3;
    c.auth_timeout = Duration::from_secs(60);
    let addr = start(c).await;
    let key = room();

    // Two connections still authenticating: a third must wait.
    let mut a = connect(addr).await;
    let nonce_a = challenge(&mut a).await;
    let mut b = connect(addr).await;
    let nonce_b = challenge(&mut b).await;
    assert_eq!(try_connect(addr).await.err(), Some(503), "pending limit");

    // Authenticating frees the pending slot, not the link slot.
    send(&mut a, Msg::Hello(key.hello(Role::Host, &nonce_a))).await;
    expect(&mut a, Msg::Ok).await;
    let mut c3 = connect(addr).await;
    challenge(&mut c3).await;
    send(&mut b, Msg::Hello(key.hello(Role::Client, &nonce_b))).await;
    expect(&mut b, Msg::Ok).await;
    expect(&mut b, Msg::Status { host_online: true }).await;
    assert_eq!(try_connect(addr).await.err(), Some(503), "link limit");

    // A link that ends gives its slot back.
    drop(b);
    expect(&mut a, Msg::PeerOpen(1)).await;
    expect(&mut a, Msg::PeerClose(1)).await;
    let deadline = tokio::time::Instant::now() + WAIT;
    let mut d = loop {
        match try_connect(addr).await {
            Ok(ws) => break ws,
            Err(status) => assert_eq!(status, 503),
        }
        assert!(tokio::time::Instant::now() < deadline, "no slot was given back");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    challenge(&mut d).await;
    // And the relay still answers plain HTTP while full.
    assert_eq!(http(addr, "GET", "/health").await.0, 200);
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
    expect_refused_close(&mut ws).await;

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
    expect_refused_close(&mut ws).await;

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
    expect_refused_close(&mut ws).await;
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
    expect_dropped(&mut a).await;
    expect(&mut host, Msg::PeerClose(1)).await;

    // Under the WebSocket limit but over the datagram limit.
    let mut b = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(2)).await;
    let _ = b.send(Message::binary(vec![relay::mt::CLIENT_DATA; relay::MAX_PAYLOAD + 2])).await;
    expect_dropped(&mut b).await;
    expect(&mut host, Msg::PeerClose(2)).await;

    // A message for the other role.
    let mut c = client(addr, &key, true).await;
    expect(&mut host, Msg::PeerOpen(3)).await;
    send(&mut c, Msg::HostData { peer: 3, payload: b"spoof" }).await;
    expect_dropped(&mut c).await;
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
    let mut a = client(addr, &key, true).await;
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
    // Dropped, without a close frame (it gets the pings it never read).
    expect_dropped(&mut a).await;
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
    let status = |h: usize, c: usize| -> (u16, String) { (200, counts(h, c)) };
    assert_eq!(http(addr, "GET", "/").await, status(0, 0));

    let key = room();
    let mut host = join(addr, &key, Role::Host).await;
    let _a = client(addr, &key, true).await;
    let _b = client(addr, &room(), false).await;
    expect(&mut host, Msg::PeerOpen(1)).await;
    assert_eq!(http(addr, "GET", "/").await, status(1, 2));

    // Through the reverse proxy: the version only, no counts.
    let plain = (200, format!("hyperspace relay {version}\n"));
    assert_eq!(http_with(addr, "GET", "/", "X-Forwarded-For: 192.0.2.7\r\n").await, plain);
    assert_eq!(http_with(addr, "GET", "/", "X-Real-IP: 192.0.2.7\r\n").await, plain);
    assert_eq!(http_with(addr, "HEAD", "/", "X-Real-IP: 192.0.2.7\r\n").await.0, 200);

    assert_eq!(http(addr, "GET", "/nope").await.0, 404);
    assert_eq!(http(addr, "GET", "/v1").await.0, 404, "no upgrade");
    assert_eq!(http(addr, "POST", "/health").await.0, 404);
    assert_eq!(http(addr, "GET", "/health/x").await.0, 404);
}
