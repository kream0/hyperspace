//! The bridges against a real relay on loopback, with a UDP echo standing in
//! for the host's server.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener as StdTcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use futures_util::SinkExt;
use hyperspace_proto::relay::{self, refused, Msg, Role, RoomKey};
use hyperspace_proto::secure::Key;
use hyperspace_relay::{Allow, Config};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::MaybeTlsStream;

use crate::errors::{self, UNTRUSTED};
use crate::link::{self, secs, Backoff, Timing};
use crate::queue;
use crate::{check, ClientBridge, HostBridge, LinkStats, RelayUrl, RelayedPeers, Status};

/// Upper bound for anything a test waits for.
const WAIT: Duration = Duration::from_secs(10);
/// What the echo answers to [`BIG`]: more than the relay carries.
const BIG_ANSWER: usize = 9000;
const BIG: &[u8] = b"big";

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

/// Pings and a dead-link limit far shorter than the defaults (and than the
/// relay's own 20 s pings), so a test sees whether pings keep a link up, yet
/// long enough that a busy test machine does not cut a healthy link.
fn short_idle() -> Timing {
    Timing { ping_interval: Duration::from_millis(400), idle_timeout: Duration::from_millis(2500), ..fast() }
}

/// A relay on its own runtime, so stopping it closes every link at once.
struct Relay {
    rt: Option<tokio::runtime::Runtime>,
    addr: SocketAddr,
}

impl Relay {
    fn start(allow: Allow) -> Relay {
        Relay::start_on("127.0.0.1:0".parse().unwrap(), allow)
    }

    fn start_on(addr: SocketAddr, allow: Allow) -> Relay {
        Relay::start_with(addr, allow, |_| {})
    }

    fn start_with(addr: SocketAddr, allow: Allow, tweak: impl FnOnce(&mut Config)) -> Relay {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let deadline = Instant::now() + WAIT;
        // The port of a relay just stopped can take a moment to free up.
        let listener = loop {
            match rt.block_on(tokio::net::TcpListener::bind(addr)) {
                Ok(l) => break l,
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => panic!("cannot bind the relay to {addr}: {e}"),
            }
        };
        let addr = listener.local_addr().unwrap();
        let mut config = Config::new(allow);
        config.rate = None;
        config.auth_timeout = Duration::from_secs(2);
        tweak(&mut config);
        rt.spawn(async move {
            let _ = hyperspace_relay::serve(listener, config).await;
        });
        Relay { rt: Some(rt), addr }
    }

    fn url(&self) -> RelayUrl {
        RelayUrl::parse(&format!("ws://{}", self.addr)).unwrap()
    }

    fn stop(mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_timeout(Duration::from_secs(1));
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

/// A relay that lets every link in, then goes silent: it stops reading (so
/// pings go unanswered) and sends nothing, with TCP left open, as a relay or
/// a proxy that hangs would. Notes when each link was let in.
struct Silent {
    rt: Option<tokio::runtime::Runtime>,
    addr: SocketAddr,
    joined: Arc<Mutex<Vec<Instant>>>,
}

impl Silent {
    fn start() -> Silent {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
        let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
        let addr = listener.local_addr().unwrap();
        let joined = Arc::new(Mutex::new(Vec::new()));
        let log = joined.clone();
        rt.spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let log = log.clone();
                tokio::spawn(async move {
                    let Ok(mut ws) = tokio_tungstenite::accept_async(MaybeTlsStream::Plain(tcp)).await else { return };
                    let challenge = Msg::Challenge { version: relay::VERSION, nonce: [7; relay::NONCE_LEN] };
                    if ws.send(Message::binary(challenge.encode())).await.is_err() {
                        return;
                    }
                    // The HELLO, unchecked.
                    if link::next_binary(&mut ws).await.is_err() {
                        return;
                    }
                    for msg in [Msg::Ok, Msg::Status { host_online: true }] {
                        if ws.send(Message::binary(msg.encode())).await.is_err() {
                            return;
                        }
                    }
                    log.lock().unwrap().push(Instant::now());
                    std::future::pending::<()>().await;
                    drop(ws);
                });
            }
        });
        Silent { rt: Some(rt), addr, joined }
    }

    fn url(&self) -> RelayUrl {
        RelayUrl::parse(&format!("ws://{}", self.addr)).unwrap()
    }

    fn joined(&self) -> Vec<Instant> {
        self.joined.lock().unwrap().clone()
    }

    /// Waits for a second link, and checks it came after the first was
    /// found dead: no sooner than the dead-link limit, and not long after.
    fn wait_for_a_reconnect(&self, idle: Duration) {
        wait_for("a second link", || self.joined().len() >= 2);
        let joined = self.joined();
        let gap = joined[1] - joined[0];
        assert!(gap >= idle - Duration::from_millis(100), "reconnected after only {gap:?}");
        assert!(gap < idle + Duration::from_millis(3000), "reconnected only after {gap:?}");
    }
}

impl Drop for Silent {
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

/// What nginx answers on its plain HTTP port to anything that is not HTTP, a
/// TLS ClientHello included (seen on a real server), before it closes.
const HTTP_400: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\nContent-Length: 155\r\n\
    Connection: close\r\n\r\n<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n\
    <center><h1>400 Bad Request</h1></center>\r\n<hr><center>web server</center>\r\n</body>\r\n</html>\r\n";

/// A plain HTTP site's answer to anything on its HTTP port: go to HTTPS.
const HTTP_301: &[u8] =
    b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://relay.example/v1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// A TCP server that gives every connection the same answer, as a web
/// server would: it reads what the client sends first, answers, then closes
/// its side and reads to the end, so the answer is not cut by a reset.
struct OneReply {
    addr: SocketAddr,
}

impl OneReply {
    fn start(reply: &'static [u8]) -> OneReply {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for tcp in listener.incoming() {
                let Ok(mut tcp) = tcp else { return };
                std::thread::spawn(move || {
                    let _ = tcp.set_read_timeout(Some(WAIT));
                    let mut buf = [0; 16 * 1024];
                    if !matches!(tcp.read(&mut buf), Ok(n) if n > 0) {
                        return;
                    }
                    let _ = tcp.write_all(reply);
                    let _ = tcp.shutdown(Shutdown::Write);
                    while matches!(tcp.read(&mut buf), Ok(n) if n > 0) {}
                });
            }
        });
        OneReply { addr }
    }

    /// What this OS's TLS library itself says when it meets this server,
    /// for test failure messages.
    fn raw_tls_error(&self) -> String {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let tcp = tokio::net::TcpStream::connect(self.addr).await.unwrap();
            let connector = tokio_native_tls::TlsConnector::from(tokio_native_tls::native_tls::TlsConnector::new().unwrap());
            match tokio::time::timeout(WAIT, connector.connect("127.0.0.1", tcp)).await {
                Ok(Ok(_)) => "no error".to_string(),
                Ok(Err(e)) => format!("display {:?}, debug {:?}", e.to_string(), format!("{e:?}")),
                Err(_) => "timed out".to_string(),
            }
        })
    }
}

/// Stands in for the host's server: echoes each datagram, answers [`BIG`]
/// with [`BIG_ANSWER`] bytes, and notes who sent what.
struct Echo {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<(SocketAddr, usize)>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Echo {
    fn start() -> Echo {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        let addr = sock.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (log, halt) = (seen.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            while !halt.load(Ordering::Relaxed) {
                let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
                log.lock().unwrap().push((from, n));
                if &buf[..n] == BIG {
                    let _ = sock.send_to(&vec![1u8; BIG_ANSWER], from);
                } else {
                    let _ = sock.send_to(&buf[..n], from);
                }
            }
        });
        Echo { addr, seen, stop, thread: Some(thread) }
    }

    fn senders(&self) -> Vec<SocketAddr> {
        let mut s: Vec<SocketAddr> = self.seen.lock().unwrap().iter().map(|(a, _)| *a).collect();
        s.sort();
        s.dedup();
        s
    }

    fn largest(&self) -> usize {
        self.seen.lock().unwrap().iter().map(|(_, n)| *n).max().unwrap_or(0)
    }
}

impl Drop for Echo {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The client program's socket.
fn app() -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    s
}

/// Sends `payload` to the bridge until the same bytes come back.
fn echo_through(app: &UdpSocket, bridge: SocketAddr, payload: &[u8]) {
    let deadline = Instant::now() + WAIT;
    let mut buf = vec![0u8; 65536];
    loop {
        assert!(Instant::now() < deadline, "no echo of {:?} through the relay", String::from_utf8_lossy(payload));
        app.send_to(payload, bridge).unwrap();
        while let Ok((n, _)) = app.recv_from(&mut buf) {
            if &buf[..n] == payload {
                return;
            }
        }
    }
}

/// A host bridge in front of an echo and a client bridge, both on `relay`.
struct Setup {
    echo: Echo,
    peers: RelayedPeers,
    host: Option<HostBridge>,
    client: Option<ClientBridge>,
    local: SocketAddr,
}

impl Setup {
    fn new(relay: &Relay) -> Setup {
        let key = Key::generate();
        let echo = Echo::start();
        let peers = RelayedPeers::new();
        let host = HostBridge::start_with(relay.url(), &key, echo.addr, peers.clone(), fast()).unwrap();
        let (client, local) = ClientBridge::start_with(relay.url(), &key, fast()).unwrap();
        assert!(local.ip().is_loopback());
        assert_eq!(client.local_addr(), local);
        let s = Setup { echo, peers, host: Some(host), client: Some(client), local };
        wait_for("the client to see the host online", || s.client().status() == Status::HostOnline);
        s
    }

    fn client(&self) -> &ClientBridge {
        self.client.as_ref().unwrap()
    }
}

#[test]
fn datagrams_flow_and_peers_come_and_go() {
    let relay = Relay::start(Allow::Open);
    let mut s = Setup::new(&relay);
    let app = app();
    echo_through(&app, s.local, b"hello");
    echo_through(&app, s.local, &[0u8; 1200]);

    let stats = s.client().stats();
    assert!(stats.connected_since.is_some_and(|t| t <= Instant::now()), "{stats:?}");
    assert!(stats.datagrams_out >= 2 && stats.bytes_out >= 1205, "{stats:?}");
    assert!(stats.datagrams_in >= 2 && stats.bytes_in >= 1205, "{stats:?}");
    assert!(stats.datagrams_in <= stats.datagrams_out, "{stats:?}");
    assert_eq!((stats.reconnects, stats.dropped, stats.discarded_while_down), (0, 0, 0), "{stats:?}");
    assert_eq!(stats.last_close, None);

    // The echo saw one sender: the host bridge's loopback socket, registered
    // as a relayed peer.
    let senders = s.echo.senders();
    assert_eq!(senders.len(), 1, "{senders:?}");
    assert!(senders[0].ip().is_loopback());
    assert!(s.peers.contains(senders[0]));
    assert_eq!(s.peers.len(), 1);

    // The client leaving closes the peer and unregisters it.
    drop(s.client.take());
    wait_for("the peer to be unregistered", || s.peers.is_empty());
    assert!(!s.peers.contains(senders[0]));

    // The host bridge stopping unregisters everything too.
    let key = Key::generate();
    let peers = RelayedPeers::new();
    let host = HostBridge::start_with(relay.url(), &key, s.echo.addr, peers.clone(), fast()).unwrap();
    let (client, _) = ClientBridge::start_with(relay.url(), &key, fast()).unwrap();
    wait_for("a second peer", || peers.len() == 1);
    drop(host);
    assert!(peers.is_empty());
    drop(client);
    drop(s.host.take());
}

#[test]
fn oversize_datagrams_are_dropped_and_the_link_survives() {
    let relay = Relay::start(Allow::Open);
    let s = Setup::new(&relay);
    let app = app();
    echo_through(&app, s.local, b"before");
    let hosts = s.client().hosts_seen();

    // From the client: more than the relay carries, so the client bridge drops it.
    app.send_to(&vec![7u8; BIG_ANSWER], s.local).unwrap();
    // From the host: the echo answers this with too much, so the host bridge drops it.
    app.send_to(BIG, s.local).unwrap();
    echo_through(&app, s.local, b"after");
    std::thread::sleep(Duration::from_millis(300));
    echo_through(&app, s.local, b"still");

    assert!(s.echo.largest() < BIG_ANSWER, "the oversize datagram reached the host");
    // Had either bridge sent it, the relay would have closed that link: the
    // client would have reconnected, or seen the host go and come back.
    let stats = s.client().stats();
    assert_eq!(stats.reconnects, 0, "{stats:?}");
    assert_eq!(stats.last_close, None, "{stats:?}");
    assert!(stats.dropped >= 1, "the client's oversize datagram was not counted: {stats:?}");
    assert_eq!(s.client().hosts_seen(), hosts);
    assert_eq!(s.client().status(), Status::HostOnline);
}

#[test]
fn both_ends_reconnect_after_a_relay_restart() {
    let relay = Relay::start(Allow::Open);
    let addr = relay.addr;
    let s = Setup::new(&relay);
    let app = app();
    echo_through(&app, s.local, b"first");

    relay.stop();
    wait_for("the client to notice", || matches!(s.client().status(), Status::CannotReach(_)));
    let down = s.client().stats();
    assert_eq!(down.connected_since, None, "{down:?}");
    assert!(down.last_close.is_some(), "{down:?}");
    // Sent while the link is down: discarded, and counted as such.
    app.send_to(b"into the void", s.local).unwrap();
    wait_for("the discarded datagram to be counted", || s.client().stats().discarded_while_down >= 1);

    let relay = Relay::start_on(addr, Allow::Open);
    wait_for("the host to come back", || s.client().status() == Status::HostOnline);
    echo_through(&app, s.local, b"second");
    // The new link's peer replaced the old one.
    wait_for("one peer", || s.peers.len() == 1);
    let up = s.client().stats();
    assert_eq!(up.reconnects, 1, "{up:?}");
    assert!(up.connected_since.is_some(), "{up:?}");
    // Through the same local address: a session going through it carries on.
    assert_eq!(s.client().local_addr(), s.local);
    drop(relay);
}

#[test]
fn pings_keep_a_quiet_link_up() {
    // The relay pings every 20 s and drops a link after 60 s of silence;
    // here the bridges give up after 2.5 s without traffic, so only their
    // own pings (answered by the relay) keep the links up.
    let relay = Relay::start(Allow::Open);
    let key = Key::generate();
    let echo = Echo::start();
    let t = short_idle();
    let host = HostBridge::start_with(relay.url(), &key, echo.addr, RelayedPeers::new(), t).unwrap();
    let (client, local) = ClientBridge::start_with(relay.url(), &key, t).unwrap();
    wait_for("the client to see the host online", || client.status() == Status::HostOnline);
    // Three times the dead-link limit.
    std::thread::sleep(t.idle_timeout * 3);
    let stats = client.stats();
    assert_eq!(stats.reconnects, 0, "{stats:?}");
    assert_eq!(stats.last_close, None, "{stats:?}");
    // The host's link stayed up too: had it dropped, the client would have
    // seen the host go and come back.
    assert_eq!(client.hosts_seen(), 1);
    assert_eq!(client.status(), Status::HostOnline);
    echo_through(&app(), local, b"still there");
    drop(client);
    drop(host);
}

#[test]
fn a_client_finds_a_silent_link_dead_and_reconnects() {
    let relay = Silent::start();
    let t = short_idle();
    let (client, local) = ClientBridge::start_with(relay.url(), &Key::generate(), t).unwrap();
    relay.wait_for_a_reconnect(t.idle_timeout);
    wait_for("the reconnect to be counted", || client.stats().reconnects >= 1);
    let stats = client.stats();
    assert_eq!(stats.last_close.as_deref(), Some("no traffic for 2.5 s"), "{stats:?}");
    // The link came back to a host that was online before the cut: the
    // session carries on, no new handshake.
    assert_eq!(client.hosts_seen(), 1);
    assert_eq!(client.local_addr(), local);
}

#[test]
fn a_host_finds_a_silent_link_dead_and_reconnects() {
    let relay = Silent::start();
    let t = short_idle();
    let echo = Echo::start();
    let host = HostBridge::start_with(relay.url(), &Key::generate(), echo.addr, RelayedPeers::new(), t).unwrap();
    relay.wait_for_a_reconnect(t.idle_timeout);
    drop(host);
}

#[test]
fn a_client_the_host_closed_waits_to_be_asked() {
    let relay = Relay::start(Allow::Open);
    let key = Key::generate();
    let room = RoomKey::derive(&key);
    let url = relay.url();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    // The host side, by hand, so the test can close the client's connection.
    let mut host = rt.block_on(link::connect(&url, &room, Role::Host)).unwrap();
    let peer_open = |host: &mut link::Ws| -> u32 {
        rt.block_on(async {
            tokio::time::timeout(WAIT, async {
                loop {
                    let b = link::next_binary(host).await.unwrap();
                    if let Some(Msg::PeerOpen(id)) = Msg::decode(&b) {
                        return id;
                    }
                }
            })
            .await
            .expect("no PEER_OPEN from the relay")
        })
    };

    let (client, local) = ClientBridge::start_with(url, &key, fast()).unwrap();
    let peer = peer_open(&mut host);
    wait_for("the client to see the host online", || client.status() == Status::HostOnline);
    assert_eq!(client.hosts_seen(), 1);

    rt.block_on(host.send(Message::binary(Msg::PeerClose(peer).encode()))).unwrap();
    wait_for("the client to see it closed", || client.status() == Status::ClosedByHost);
    assert!(client.status().to_string().contains("host closed"), "{}", client.status());
    let stats = client.stats();
    assert!(
        stats.last_close.as_deref().is_some_and(|w| w.starts_with("the host closed this connection")),
        "{stats:?}"
    );
    assert_eq!(stats.connected_since, None);

    // It stays closed: no reconnect until asked.
    let app = app();
    app.send_to(b"hello?", local).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(client.status(), Status::ClosedByHost);
    let stats = client.stats();
    assert_eq!(stats.reconnects, 0, "{stats:?}");
    assert!(stats.discarded_while_down >= 1, "{stats:?}");

    client.reconnect();
    let again = peer_open(&mut host);
    assert_ne!(again, peer);
    wait_for("the client to see the host again", || client.status() == Status::HostOnline);
    assert_eq!(client.stats().reconnects, 1);
    // The host ended the old session: this one needs a new handshake.
    assert_eq!(client.hosts_seen(), 2);
    drop(client);
    drop(host);
}

#[test]
fn a_client_whose_loopback_socket_fails_is_dropped() {
    let relay = Relay::start(Allow::Open);
    let s = Setup::new(&relay);
    let app = app();
    echo_through(&app, s.local, b"before");
    assert_eq!(s.peers.len(), 1);

    // The echo sends this back, and the host bridge's socket for this client
    // fails as it reads it: the client is dropped, not left half open.
    app.send_to(crate::host::FAIL_READER, s.local).unwrap();
    wait_for("the peer to be unregistered", || s.peers.is_empty());
    wait_for("the client to see it closed", || s.client().status() == Status::ClosedByHost);

    // The host's link itself is fine: the client comes back as a new peer.
    s.client().reconnect();
    wait_for("the client to see the host again", || s.client().status() == Status::HostOnline);
    echo_through(&app, s.local, b"after");
    wait_for("one peer", || s.peers.len() == 1);
    assert_eq!(s.client().hosts_seen(), 2);
}

#[test]
fn only_the_first_local_sender_is_served() {
    // A length no other datagram in this test has.
    const ODD: usize = 333;
    let relay = Relay::start(Allow::Open);
    let addr = relay.addr;
    let s = Setup::new(&relay);
    let (first, stranger) = (app(), app());
    stranger.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    let mut buf = vec![0u8; 65536];
    echo_through(&first, s.local, b"mine");

    // Another local program gets nothing back, and nothing of it reaches
    // the host.
    stranger.send_to(&[5u8; ODD], s.local).unwrap();
    assert!(stranger.recv_from(&mut buf).is_err(), "the bridge answered another socket");
    wait_for("the stranger's datagram to be counted", || s.client().stats().dropped >= 1);
    echo_through(&first, s.local, b"still mine");

    // Nor while the link is down, or once it is back.
    relay.stop();
    wait_for("the client to notice", || matches!(s.client().status(), Status::CannotReach(_)));
    let down = s.client().stats();
    stranger.send_to(&[5u8; ODD], s.local).unwrap();
    wait_for("the stranger's datagram to be counted", || s.client().stats().dropped > down.dropped);
    assert_eq!(s.client().stats().discarded_while_down, down.discarded_while_down);
    let relay = Relay::start_on(addr, Allow::Open);
    wait_for("the host to come back", || s.client().status() == Status::HostOnline);
    stranger.send_to(&[5u8; ODD], s.local).unwrap();
    echo_through(&first, s.local, b"mine again");
    assert!(stranger.recv_from(&mut buf).is_err(), "the bridge answered another socket");

    assert!(s.echo.seen.lock().unwrap().iter().all(|(_, n)| *n != ODD), "the stranger's datagram reached the host");
    drop(relay);
}

#[test]
fn a_busy_relay_is_reported_and_retried() {
    let relay = Relay::start_with("127.0.0.1:0".parse().unwrap(), Allow::Open, |c| c.max_links = 0);
    let (client, _) = ClientBridge::start_with(relay.url(), &Key::generate(), fast()).unwrap();
    wait_for("the client to see the relay busy", || client.status() == Status::RelayBusy);
    assert!(client.status().to_string().contains("busy"), "{}", client.status());
    let err = check(&format!("ws://{}", relay.addr)).unwrap_err();
    assert!(err.contains("busy (HTTP 503)"), "{err}");
    assert_eq!(client.stats(), LinkStats::default());
}

#[test]
fn a_client_whose_host_is_away_sees_it_offline() {
    let relay = Relay::start(Allow::Open);
    let key = Key::generate();
    let (client, local) = ClientBridge::start_with(relay.url(), &key, fast()).unwrap();
    wait_for("the host to be reported offline", || client.status() == Status::HostOffline);
    assert!(client.status().to_string().contains("offline"), "{}", client.status());
    // What the client sends meanwhile goes nowhere and breaks nothing.
    let app = app();
    app.send_to(b"anyone there?", local).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(client.status(), Status::HostOffline);
    assert_eq!(client.hosts_seen(), 0);

    // The host coming online is a host the client has no session with yet.
    let echo = Echo::start();
    let host = HostBridge::start_with(relay.url(), &key, echo.addr, RelayedPeers::new(), fast()).unwrap();
    wait_for("the host to come online", || client.status() == Status::HostOnline);
    assert_eq!(client.hosts_seen(), 1);
    echo_through(&app, local, b"there you are");
    drop(host);
}

#[test]
fn a_new_host_with_the_same_key_takes_over() {
    let relay = Relay::start(Allow::Open);
    let key = Key::generate();
    let (first_echo, second_echo) = (Echo::start(), Echo::start());
    // The replaced host waits before it tries again; long enough here that
    // it stays out of the way.
    let stays_away = Timing { refused_wait: WAIT * 3, ..fast() };
    let first = HostBridge::start_with(relay.url(), &key, first_echo.addr, RelayedPeers::new(), stays_away).unwrap();
    let (client, local) = ClientBridge::start_with(relay.url(), &key, fast()).unwrap();
    wait_for("the first host", || client.status() == Status::HostOnline);
    let app = app();
    echo_through(&app, local, b"to the first host");
    let seen = client.hosts_seen();

    let second_peers = RelayedPeers::new();
    let second = HostBridge::start_with(relay.url(), &key, second_echo.addr, second_peers.clone(), fast()).unwrap();
    // The status stays "host online": the count is how the client tells.
    wait_for("the client to see a new host", || client.hosts_seen() > seen);
    assert_eq!(client.status(), Status::HostOnline);
    echo_through(&app, local, b"to the second host");
    assert!(!second_echo.senders().is_empty());
    assert_eq!(second_peers.len(), 1);

    drop(second);
    wait_for("the host to be reported offline", || client.status() == Status::HostOffline);
    // Stopping a bridge does not wait out its pause.
    let began = Instant::now();
    drop(first);
    assert!(began.elapsed() < WAIT, "{:?}", began.elapsed());
}

#[test]
fn close_frames_are_told_apart() {
    let frame = |code: u16, reason: &'static str| Some(CloseFrame { code: CloseCode::from(code), reason: reason.into() });
    assert!(link::is_replaced(&frame(hyperspace_proto::relay::close::REPLACED, "replaced")));
    assert!(!link::is_replaced(&frame(1000, "")));
    assert!(!link::is_replaced(&None));
    assert!(link::is_closed_by_host(&frame(1000, "closed by the host")));
    assert!(!link::is_closed_by_host(&frame(hyperspace_proto::relay::close::REPLACED, "replaced")));
    assert!(!link::is_closed_by_host(&frame(1008, "refused")));
    // A normal close from anything else (a proxy, say) is a lost link.
    assert!(!link::is_closed_by_host(&frame(1000, "")));
    assert!(!link::is_closed_by_host(&frame(1000, "bye")));
    assert!(!link::is_closed_by_host(&None));
    assert_eq!(link::close_text(&frame(1008, "")), " (code 1008)");
    assert_eq!(link::close_text(&frame(1008, "bad\nline")), " (code 1008: bad?line)");
    assert_eq!(link::close_text(&None), "");
}

#[test]
fn a_room_the_relay_does_not_serve_is_refused() {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let dir = std::env::temp_dir().join(format!("hyperspace-bridge-test-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let allow = dir.join("allow");
    // Some other host's room only.
    std::fs::write(&allow, format!("{}\n", RoomKey::derive(&Key::generate()).id().hex())).unwrap();
    let relay = Relay::start(Allow::File(allow));

    let key = Key::generate();
    let peers = RelayedPeers::new();
    let echo = Echo::start();
    let host = HostBridge::start_with(relay.url(), &key, echo.addr, peers.clone(), fast()).unwrap();
    let (client, _) = ClientBridge::start_with(relay.url(), &key, fast()).unwrap();
    wait_for("the refusal", || client.status() == Status::Refused(refused::NOT_ALLOWED));
    assert!(client.status().to_string().contains("allow list"), "{}", client.status());
    assert!(peers.is_empty());
    drop(client);
    drop(host);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn check_tells_what_works() {
    let relay = Relay::start(Allow::Open);
    let ok = check(&format!("ws://{}", relay.addr)).unwrap();
    assert_eq!(ok, "relay reachable (no TLS): WebSocket ok, relay protocol v1");

    // An HTTP answer that is not an upgrade.
    let err = check(&format!("ws://{}/health", relay.addr)).unwrap_err();
    assert!(err.contains("answered HTTP 200"), "{err}");

    // Nothing listening.
    let port = {
        let l = StdTcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let err = check(&format!("ws://127.0.0.1:{port}")).unwrap_err();
    assert!(err.starts_with("cannot connect to 127.0.0.1 port"), "{err}");
    assert!(!err.contains("os error"), "{err}");

    // Not a relay address at all.
    assert!(check("https://relay.example").is_err());
}

/// wss:// to a plain HTTP port, against this OS's own TLS library.
#[test]
fn a_server_that_does_not_answer_with_tls_is_named_on_every_os() {
    let server = OneReply::start(HTTP_400);
    let port = server.addr.port();
    let line = check(&format!("wss://127.0.0.1:{port}")).unwrap_err();
    assert_eq!(
        line,
        format!("the server at 127.0.0.1 port {port} did not answer with TLS (wrong port?)"),
        "the TLS library said: {}",
        server.raw_tls_error()
    );
}

#[test]
fn a_redirect_of_ws_suggests_wss() {
    let server = OneReply::start(HTTP_301);
    let err = check(&format!("ws://{}", server.addr)).unwrap_err();
    assert_eq!(
        err,
        format!(
            "the server at ws://{}/v1 answered HTTP 301 Moved Permanently instead of opening a WebSocket (try wss://)",
            server.addr
        )
    );
}

#[test]
fn only_a_redirect_of_ws_gets_the_wss_hint() {
    let line = |url: &str, code: u16| errors::http_answer(&RelayUrl::parse(url).unwrap(), StatusCode::from_u16(code).unwrap());
    let hint = " (try wss://)";
    assert_eq!(
        line("ws://relay.example", 301),
        format!("the server at ws://relay.example/v1 answered HTTP 301 Moved Permanently instead of opening a WebSocket{hint}")
    );
    for code in [302, 307, 308] {
        assert!(line("ws://relay.example", code).ends_with(hint), "{code}");
    }
    // Already wss://, or not a redirect: the line as it was.
    assert_eq!(
        line("wss://relay.example", 301),
        "the server at wss://relay.example/v1 answered HTTP 301 Moved Permanently instead of opening a WebSocket"
    );
    assert_eq!(
        line("ws://relay.example", 200),
        "the server at ws://relay.example/v1 answered HTTP 200 OK instead of opening a WebSocket"
    );
    for code in [303, 404] {
        assert!(!line("ws://relay.example", code).contains("try"), "{code}");
    }
}

#[test]
fn relay_urls() {
    let ok = |s: &str| RelayUrl::parse(s).unwrap_or_else(|e| panic!("{s}: {e}")).to_string();
    assert_eq!(ok("wss://relay.example"), "wss://relay.example/v1");
    assert_eq!(ok(" WSS://Relay.Example/ "), "wss://relay.example/v1");
    assert_eq!(ok("wss://relay.example:443/v1"), "wss://relay.example/v1");
    assert_eq!(ok("wss://relay.example:8443/hs/v1"), "wss://relay.example:8443/hs/v1");
    assert_eq!(ok("ws://relay.example"), "ws://relay.example/v1");
    assert_eq!(ok("ws://192.0.2.7:8080"), "ws://192.0.2.7:8080/v1");
    let u = RelayUrl::parse("wss://relay.example:8443").unwrap();
    assert!(u.tls() && u.host() == "relay.example" && u.port() == 8443 && u.path() == "/v1");
    assert_eq!(RelayUrl::parse(&u.to_string()), Ok(u));

    for bad in [
        "",
        "relay.example",
        "https://relay.example",
        "wss://",
        "wss://:443",
        "wss://user:pw@relay.example",
        "wss://[2001:db8::1]/v1",
        "wss://2001:db8::1",
        "wss://relay.example:0",
        "wss://relay.example:65536",
        "wss://relay.example:x",
        "wss://relay.example/v1?x=1",
        "wss://relay.example/v1#x",
        "wss://relay.example/7",
        "wss://relay ex",
        "wss://relay.example/a,b",
        "wss://relay.example/~x",
        "wss://relay.example/é",
        "wss://relay*.example",
    ] {
        assert!(RelayUrl::parse(bad).is_err(), "{bad:?} should be refused");
    }
}

#[test]
fn queue_limits() {
    let (tx, rx) = queue::queue(4, 100);
    assert!(tx.push(vec![0; 60]));
    assert!(!tx.push(vec![0; 41]), "over the byte limit");
    assert!(tx.push(vec![0; 40]));
    assert_eq!(rx.len(), (2, 100));
    assert!(tx.push_control(vec![0; 5]), "control messages pass the byte limit");
    assert_eq!(rx.try_recv().map(|m| m.len()), Some(60));
    assert!(tx.push(vec![0; 10]));
    assert!(tx.push(vec![0; 10]));
    assert!(!tx.push(vec![0; 1]), "over the count limit");
    assert_eq!(rx.len(), (4, 65));
    while rx.try_recv().is_some() {}
    assert_eq!(rx.len(), (0, 0));
    assert!(tx.push(vec![0; 100]));
}

#[test]
fn relayed_peers_compare_canonical_addresses() {
    let peers = RelayedPeers::new();
    assert!(peers.is_empty());
    peers.insert("127.0.0.1:5000".parse().unwrap());
    assert!(peers.contains("[::ffff:127.0.0.1]:5000".parse().unwrap()));
    assert!(peers.contains("127.0.0.1:5000".parse().unwrap()));
    assert!(!peers.contains("127.0.0.1:5001".parse().unwrap()));
    peers.remove("[::ffff:127.0.0.1]:5000".parse().unwrap());
    assert!(peers.is_empty());
}

/// Within 20 % of `ms` milliseconds.
fn about(d: Duration, ms: u64) -> bool {
    let ms = ms as f64;
    let got = d.as_secs_f64() * 1000.0;
    got >= ms * 0.8 - 0.001 && got <= ms * 1.2 + 0.001
}

#[test]
fn the_host_backs_off_from_1_s_to_30_s() {
    let t = Timing::host();
    assert_eq!((t.ping_interval, t.idle_timeout), (Duration::from_secs(15), Duration::from_secs(35)));
    assert_eq!(t.refused_wait, Duration::from_secs(60));
    let mut b = Backoff::new(&t);
    for ms in [1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000] {
        let d = b.next();
        assert!(about(d, ms), "{d:?} is not about {ms} ms");
    }
    b.reset();
    let d = b.next();
    assert!(about(d, 1000), "{d:?}");
}

#[test]
fn the_client_reconnects_fast_then_every_5_s() {
    let t = Timing::client();
    assert_eq!((t.ping_interval, t.idle_timeout), (Duration::from_secs(15), Duration::from_secs(35)));
    let mut b = Backoff::new(&t);
    for ms in [250, 500, 1000, 2000, 4000, 5000, 5000, 5000] {
        let d = b.next();
        assert!(about(d, ms), "{d:?} is not about {ms} ms");
    }
    b.reset();
    let d = b.next();
    assert!(about(d, 250), "{d:?}");
}

#[test]
fn durations_read_well() {
    assert_eq!(secs(Duration::from_secs(35)), "35 s");
    assert_eq!(secs(Duration::from_secs(742)), "742 s");
    assert_eq!(secs(Duration::from_millis(10_400)), "10 s");
    assert_eq!(secs(Duration::from_secs(1)), "1 s");
    assert_eq!(secs(Duration::from_millis(600)), "0.6 s");
    assert_eq!(secs(Duration::from_millis(1500)), "1.5 s");
    assert_eq!(secs(Duration::ZERO), "0 s");
}

/// What native-tls's OpenSSL backend (Linux) prints for a verify failure:
/// the error stack, then the verify result in parentheses.
fn openssl(verify: &str, code: u32) -> (String, String) {
    let display = format!(
        "error:0A000086:SSL routines:tls_post_process_server_certificate:certificate verify failed:\
         ../ssl/statem/statem_clnt.c:1889: ({verify})"
    );
    let debug = format!(
        "Ssl(Error {{ code: ErrorCode(1), cause: Some(Ssl(ErrorStack([Error {{ code: 167772294, library: \
         \"SSL routines\", function: \"tls_post_process_server_certificate\", reason: \"certificate verify \
         failed\", file: \"../ssl/statem/statem_clnt.c\", line: 1889 }}]))) }}, X509VerifyResult {{ code: \
         {code}, error: \"{verify}\" }})"
    );
    (display, debug)
}

/// macOS (Security framework): Display is the message alone, in the user's
/// language; the number is only in Debug.
fn macos(code: i32, message: &str) -> (String, String) {
    (message.to_string(), format!("Error {{ code: {code}, message: {message:?} }}"))
}

/// Windows (SChannel): std's io::Error, with a translated message.
fn windows(hresult: u32, message: &str) -> (String, String) {
    let code = hresult as i32;
    (format!("{message} (os error {code})"), format!("Os {{ code: {code}, kind: Uncategorized, message: {message:?} }}"))
}

fn tls_line(error: (String, String)) -> String {
    let line = errors::tls_error("relay.example", 443, &error.0, &error.1);
    for raw in ["routines", ".c:", "error:0", "ssl", "SSL", "Error {", "os error"] {
        assert!(!line.contains(raw), "{line:?} contains {raw:?}");
    }
    line
}

#[test]
fn tls_failures_read_the_same_on_every_os() {
    let name = "the relay's certificate is not valid for relay.example";
    let expired = "the relay's certificate has expired";

    // Linux, OpenSSL 3 (the hostname case is a line seen on a real run).
    assert_eq!(tls_line(openssl("hostname mismatch", 62)), name);
    assert_eq!(tls_line(openssl("IP address mismatch", 64)), name);
    assert_eq!(tls_line(openssl("certificate has expired", 10)), expired);
    assert_eq!(tls_line(openssl("unable to get local issuer certificate", 20)), UNTRUSTED);
    assert_eq!(tls_line(openssl("self-signed certificate", 18)), UNTRUSTED);
    assert_eq!(tls_line(openssl("self-signed certificate in certificate chain", 19)), UNTRUSTED);
    // OpenSSL 1.1 spells it without the hyphen.
    assert_eq!(tls_line(openssl("self signed certificate", 18)), UNTRUSTED);

    // macOS, with messages in French: only the numbers count.
    assert_eq!(tls_line(macos(-67602, "Le nom d'hôte ne correspond pas.")), name);
    assert_eq!(tls_line(macos(-67818, "Un certificat expiré a été détecté.")), expired);
    assert_eq!(tls_line(macos(-67843, "Le certificat n'était pas fiable.")), UNTRUSTED);
    assert_eq!(tls_line(macos(-9807, "chaîne de certificats non valide")), UNTRUSTED);

    // Windows, in French as well.
    assert_eq!(tls_line(windows(0x800B_010F, "Le nom CN du certificat ne correspond pas.")), name);
    assert_eq!(tls_line(windows(0x8009_0322, "Le nom principal cible est incorrect.")), name);
    assert_eq!(tls_line(windows(0x800B_0101, "Le certificat a expiré.")), expired);
    assert_eq!(tls_line(windows(0x800B_0109, "Une chaîne de certificats ... non approuvée.")), UNTRUSTED);
    assert_eq!(tls_line(windows(0x8009_0325, "La chaîne de certificats n'est pas approuvée.")), UNTRUSTED);
}

#[test]
fn other_tls_failures_keep_a_short_detail() {
    let failed = "secure connection to relay.example failed";
    // Linux: the verify result, or OpenSSL's reason without its codes and paths.
    assert_eq!(tls_line(openssl("certificate is not yet valid", 9)), format!("{failed} (certificate is not yet valid)"));
    let eof = "error:0A000126:SSL routines::unexpected eof while reading:../ssl/record/rec_layer_s3.c:303:".to_string();
    assert_eq!(tls_line((eof.clone(), eof)), format!("{failed} (unexpected eof while reading)"));
    // An OS error: its message, without the number, which differs between
    // OSes.
    let reset = "Connection reset by peer (os error 104)".to_string();
    assert_eq!(tls_line((reset.clone(), reset)), format!("{failed} (Connection reset by peer)"));
    // macOS and Windows: the number, since their messages are translated.
    assert_eq!(tls_line(macos(-9800, "erreur de protocole SSL")), format!("{failed} (error -9800)"));
    assert_eq!(tls_line(windows(0x8009_0326, "Le message reçu était inattendu.")), format!("{failed} (error 0x80090326)"));
    // Nothing usable: no detail at all.
    let odd = "error:0A000126:SSL routines::unexpected eof:../ssl/x.c:1:, func_name(): /path/x".to_string();
    assert_eq!(tls_line((odd.clone(), String::new())), failed);
}

#[test]
fn an_answer_that_is_not_tls_reads_the_same_on_every_os() {
    let not_tls = "the server at relay.example port 443 did not answer with TLS (wrong port?)";
    // Linux: OpenSSL 3.0 (seen on a real run against an HTTP port), and a
    // later one that adds a second entry.
    let wrong = "error:0A00010B:SSL routines::wrong version number:../ssl/record/ssl3_record.c:354:".to_string();
    assert_eq!(tls_line((wrong.clone(), wrong)), not_tls);
    let stacked = "error:0A00010B:SSL routines:tls_get_more_records:wrong version number:\
                   ../ssl/record/methods/tls_common.c:605:, error:0A000139:SSL routines::record layer failure:\
                   ../ssl/record/rec_layer_s3.c:696:"
        .to_string();
    assert_eq!(tls_line((stacked.clone(), stacked)), not_tls);
    // macOS and Windows, by number.
    assert_eq!(tls_line(macos(-9847, "dépassement d'enregistrement")), not_tls);
    assert_eq!(tls_line(windows(0x8009_0308, "Le jeton fourni à la fonction n'est pas valide")), not_tls);
}

#[test]
fn openssl_text_is_cut_to_its_reason() {
    assert_eq!(
        errors::clean(
            "error:0A000086:SSL routines:tls_post_process_server_certificate:certificate verify failed:\
             ../ssl/statem/statem_clnt.c:1889: (hostname mismatch)"
        ),
        "certificate verify failed (hostname mismatch)"
    );
    assert_eq!(
        errors::clean("error:0A000126:SSL routines::unexpected eof while reading:../ssl/record/rec_layer_s3.c:303:"),
        "unexpected eof while reading"
    );
    assert_eq!(
        errors::clean("error:0A000126:SSL routines::a:../x.c:1:, error:0A000127:SSL routines::b:../y.c:2:data"),
        "a, b"
    );
    // std's OS error numbers, Windows' negative ones included, are taken out.
    assert_eq!(errors::clean("IO error: Connection reset by peer (os error 104)"), "IO error: Connection reset by peer");
    assert_eq!(errors::clean("Connection reset by peer (os error 10054)"), "Connection reset by peer");
    assert_eq!(errors::clean("Le message reçu était inattendu. (os error -2146893018)"), "Le message reçu était inattendu.");
    assert_eq!(errors::clean("a (os error 5) b (os error 6)"), "a b");
    let gone = errors::plain(std::io::Error::from_raw_os_error(2));
    assert!(!gone.is_empty() && !gone.contains("os error"), "{gone:?}");
    // Anything else: kept as it is.
    for text in ["error: something", "network error:", "(os error x)", "a (os error 5 b", "(os error )", "(os error -)"] {
        assert_eq!(errors::clean(text), text);
    }
}

#[test]
fn a_connect_failure_names_the_address_only_for_a_host_name() {
    let addr: SocketAddr = "192.0.2.7:443".parse().unwrap();
    assert_eq!(
        errors::connect_error("relay.example", 443, &addr, "timed out"),
        "cannot connect to relay.example port 443 (192.0.2.7): timed out"
    );
    let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    assert_eq!(
        errors::connect_error("127.0.0.1", 9, &addr, "connection refused"),
        "cannot connect to 127.0.0.1 port 9: connection refused"
    );
    // The same line on every OS.
    for why in ["Connection refused (os error 111)", "Connection refused (os error 61)", "Connection refused (os error 10061)"] {
        assert_eq!(errors::connect_error("127.0.0.1", 9, &addr, why), "cannot connect to 127.0.0.1 port 9: Connection refused");
    }
}
