//! The bridges against a real relay on loopback, with a UDP echo standing in
//! for the host's server.

use std::net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use hyperspace_proto::relay::{refused, RoomKey};
use hyperspace_proto::secure::Key;
use hyperspace_relay::{Allow, Config};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;

use crate::link::{self, Backoff, Timing};
use crate::queue;
use crate::{check, ClientBridge, HostBridge, RelayUrl, RelayedPeers, Status};

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
        idle_timeout: Duration::from_secs(10),
        stable: Duration::from_secs(1),
    }
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
    // client would have seen the host go and come back (or reconnected).
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
    let relay = Relay::start_on(addr, Allow::Open);
    wait_for("the host to come back", || s.client().status() == Status::HostOnline);
    echo_through(&app, s.local, b"second");
    // The new link's peer replaced the old one.
    wait_for("one peer", || s.peers.len() == 1);
    drop(relay);
}

#[test]
fn a_client_whose_host_is_away_sees_it_offline() {
    let relay = Relay::start(Allow::Open);
    let (client, local) = ClientBridge::start_with(relay.url(), &Key::generate(), fast()).unwrap();
    wait_for("the host to be reported offline", || client.status() == Status::HostOffline);
    assert!(client.status().to_string().contains("offline"), "{}", client.status());
    // What the client sends meanwhile goes nowhere and breaks nothing.
    let app = app();
    app.send_to(b"anyone there?", local).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(client.status(), Status::HostOffline);
    assert_eq!(client.hosts_seen(), 0);
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

    // Not a relay address at all.
    assert!(check("https://relay.example").is_err());
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

#[test]
fn backoff_grows_to_its_cap_with_jitter() {
    let t = Timing::default();
    let mut b = Backoff::new(&t);
    let first = b.next();
    assert!(first >= Duration::from_millis(800) && first <= Duration::from_millis(1200), "{first:?}");
    for _ in 0..10 {
        b.next();
    }
    let capped = b.next();
    assert!(capped >= Duration::from_secs(24) && capped <= Duration::from_secs(36), "{capped:?}");
    b.reset();
    assert!(b.next() <= Duration::from_millis(1200));
}
