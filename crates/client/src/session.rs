//! Platform-independent client session: encrypted handshake, receive loop,
//! loss repair, clock sync, bitrate control and the input sender, and the
//! reconnects when a relay is configured.

use crate::relay::Relay;
use hyperspace_bridge::{clause, plain_error, Status};
use hyperspace_proto::clock::{now_us, ClockSync};
use hyperspace_proto::cursor::CursorShape;
use hyperspace_proto::frag::{Action, Frame, Reassembler};
use hyperspace_proto::input::{InputEvent, InputQueue};
use hyperspace_proto::pairing::{is_local, resolve_addr};
use hyperspace_proto::rate::{RateControl, Sample};
use hyperspace_proto::secure::{self, Initiator, Key, DATA_OVERHEAD};
use hyperspace_proto::wire::{self, bye, pt, Hello, Packet, Welcome, FRAG_HEADER_LEN};
use hyperspace_proto::{log, rendezvous, DEFAULT_PORT};
use std::cell::RefCell;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const HOST_TIMEOUT: Duration = Duration::from_secs(5);
const PING_INTERVAL_US: u64 = 200_000;
/// The head start the host's direct addresses get before the relay joins the
/// race: on a network where UDP gets through, the direct path wins.
const RELAY_JOIN_AFTER: Duration = Duration::from_millis(600);
/// Waits between reconnect attempts: doubling from the first to the last.
const RETRY_FIRST: Duration = Duration::from_millis(500);
const RETRY_MAX: Duration = Duration::from_secs(5);
/// Connect attempts after a session is lost, before giving up.
const RETRY_ATTEMPTS: u32 = 3;
/// A session that lasted this long resets the wait between attempts.
const STABLE_SESSION: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct Options {
    pub key: Key,
    /// Addresses to try, all at once.
    pub candidates: Vec<SocketAddr>,
    /// Look the host's current address up if the known ones do not answer.
    pub lookup: bool,
    pub timeout: Duration,
    pub fps: u16,
    pub bitrate_kbps: u32,
    pub codecs: u8,
    pub max_datagram: u16,
    /// Testing: end the first session this long after it starts, without a
    /// goodbye, as if it were lost (with a relay set, a new connect follows).
    pub cut_first_session: Option<Duration>,
}

/// An established, encrypted path to the host.
pub struct Link {
    sock: UdpSocket,
    secure: secure::Session,
}

thread_local! {
    static WIRE: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

impl Link {
    /// Encrypt and send one packet.
    pub fn send(&self, plain: &[u8]) {
        WIRE.with(|w| {
            let mut w = w.borrow_mut();
            self.secure.seal(plain, &mut w);
            let _ = self.sock.send(&w);
        });
    }
}

pub struct Connection {
    pub link: Arc<Link>,
    pub welcome: Welcome,
    /// The address that answered.
    pub peer: SocketAddr,
    /// Addresses learned from the lookup service during this connect (to be saved).
    pub learned: Vec<String>,
    /// The session goes through the relay.
    pub relayed: bool,
    /// The relay's count of hosts when this session started: a rise means
    /// the host restarted or was replaced, and the session is gone.
    pub hosts_seen: u64,
}

impl Connection {
    /// How the session reaches the host, for the log.
    pub fn path(&self) -> String {
        if self.relayed {
            "through the relay".to_string()
        } else {
            format!("directly at {}", self.peer)
        }
    }
}

enum Via {
    Direct(usize),
    Relay,
}

/// The host's answer to the handshake, if `data` is one.
fn answer(init: &mut Initiator, data: &[u8]) -> Result<Option<secure::Session>, String> {
    let Some((session, payload)) = init.finish(data) else { return Ok(None) };
    match payload.first() {
        Some(&wire::ACCEPT_OK) => Ok(Some(session)),
        Some(&wire::ACCEPT_VERSION_MISMATCH) => Err(bye::describe(bye::VERSION_MISMATCH).into()),
        _ => Err("the host sent an invalid answer".into()),
    }
}

fn make_socket(host: SocketAddr) -> std::io::Result<UdpSocket> {
    let any = if host.is_ipv4() { IpAddr::from(Ipv4Addr::UNSPECIFIED) } else { IpAddr::from(Ipv6Addr::UNSPECIFIED) };
    socket_to(host, any)
}

/// The session's end of the relay link: bound to loopback in the family of
/// the link's address and connected to it, so the system drops datagrams
/// from any other program on this machine, and ours go to the link only.
pub fn relay_socket(link: SocketAddr) -> std::io::Result<UdpSocket> {
    if !link.ip().is_loopback() {
        return Err(std::io::Error::new(ErrorKind::InvalidInput, format!("{link} is not a loopback address")));
    }
    let lo = if link.is_ipv4() { IpAddr::from(Ipv4Addr::LOCALHOST) } else { IpAddr::from(Ipv6Addr::LOCALHOST) };
    socket_to(link, lo)
}

/// A non-blocking UDP socket bound to `local` (any port) and connected to `host`.
fn socket_to(host: SocketAddr, local: IpAddr) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::for_address(host), Type::DGRAM, Some(Protocol::UDP))?;
    // Room for a burst of keyframe datagrams while the decode thread is busy.
    for size in [8 << 20, 4 << 20, 1 << 20, 256 << 10] {
        if s.set_recv_buffer_size(size).is_ok() {
            break;
        }
    }
    s.bind(&SocketAddr::new(local, 0).into())?;
    s.connect(&host.into())?;
    s.set_nonblocking(true)?;
    Ok(s.into())
}

/// Network interfaces whose names mark them as tunnels (VPNs, security clients).
fn is_tunnel(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["utun", "tun", "tap", "ppp", "ipsec", "wg", "zt", "tailscale", "gpd"].iter().any(|p| n.starts_with(p))
}

/// Best explanation this machine can give for an address staying silent.
fn why_unreachable(sock: &UdpSocket, addr: SocketAddr, relay_set: bool) -> String {
    let ifaces = if_addrs::get_if_addrs().unwrap_or_default();
    // Which of our interfaces would carry traffic to it.
    let via = sock.local_addr().ok().and_then(|l| ifaces.iter().find(|i| i.ip() == l.ip()));
    let tunnel = via.filter(|i| is_tunnel(&i.name));
    if is_local(addr.ip()) {
        let same_subnet = |i: &if_addrs::Interface| match (&i.addr, addr.ip()) {
            (if_addrs::IfAddr::V4(a), std::net::IpAddr::V4(t)) => {
                let mask = u32::from(a.netmask);
                mask != 0 && u32::from(a.ip) & mask == u32::from(t) & mask && !a.ip.is_loopback()
            }
            _ => false,
        };
        if addr.ip().is_loopback() || ifaces.iter().any(same_subnet) {
            "on this network, but silent - is the host running, and does its firewall allow hyperspace-host?".into()
        } else {
            "a private address, only reachable from the host's own network (expected when you are elsewhere)".into()
        }
    } else if let Some(t) = tunnel {
        through_tunnel(&t.name, relay_set)
    } else {
        format!(
            "the host's public address - its router must forward UDP {} to the PC (the host log says whether it does), \
             and this network must allow outgoing UDP",
            addr.port()
        )
    }
}

/// Why a public address stays silent when the traffic to it leaves through
/// a tunnel interface (`iface`). Without a relay, it points to one.
fn through_tunnel(iface: &str, relay_set: bool) -> String {
    let advice = if relay_set {
        "if the relay is blocked as well, this network does not allow the session; its administrators decide what \
         it lets through"
    } else {
        "the host's relay (--relay URL) carries the session over HTTPS instead"
    };
    format!(
        "traffic to this public address leaves through {iface} - a VPN or security client - which commonly blocks \
         direct UDP like this; {advice}"
    )
}

/// Connect: authenticate with the pairing key over whichever address answers
/// first, then wait for the host to start its stream. With a relay, its link
/// starts at once and joins the race after the direct addresses' head start
/// (at once if there is no direct address, or if the relay carried the last
/// session); if the host answers directly, the link closes.
pub fn connect(opts: &Options, mut relay: Option<&mut Relay>, stop: &AtomicBool) -> Result<Connection, String> {
    let hello = wire::hello(&Hello {
        nonce: 0,
        codecs: opts.codecs,
        fps: opts.fps,
        bitrate_kbps: opts.bitrate_kbps,
        max_datagram: opts.max_datagram,
    });
    let mut init = Initiator::new(&opts.key, &hello);
    let mut socks: Vec<(UdpSocket, SocketAddr)> = Vec::new();
    let add = |socks: &mut Vec<(UdpSocket, SocketAddr)>, addr: SocketAddr| {
        if socks.iter().all(|(_, a)| *a != addr) {
            // A family this machine has no route for simply fails here.
            if let Ok(s) = make_socket(addr) {
                socks.push((s, addr));
            }
        }
    };
    for &c in &opts.candidates {
        add(&mut socks, c);
    }
    let list = |socks: &[(UdpSocket, SocketAddr)]| socks.iter().map(|(_, a)| a.to_string()).collect::<Vec<_>>().join(", ");

    // The relay's end on this machine: a loopback address that stands for
    // the host, reached through the link's one socket.
    let mut relay_sock: Option<(UdpSocket, SocketAddr)> = relay.as_deref_mut().and_then(Relay::start);
    let relay_line = |relay: Option<&Relay>| relay.map(|r| format!("\n  relay {}: {}", r.url(), r.diagnose())).unwrap_or_default();
    if socks.is_empty() && !opts.lookup && relay_sock.is_none() {
        return Err(format!("no usable address for the host{}", relay_line(relay.as_deref())));
    }
    let mut relay_joined = relay_sock.is_some() && (socks.is_empty() || relay.as_deref().is_some_and(Relay::won_last));
    let relay_url = relay.as_deref().map(|r| r.url().to_string()).unwrap_or_default();
    match (socks.is_empty(), relay_sock.is_some()) {
        (true, false) => log!("connecting to the host (looking up its address) ..."),
        (false, false) => log!("connecting to {} ...", list(&socks)),
        (true, true) => log!("connecting to the host through the relay at {relay_url} ..."),
        (false, true) if relay_joined => log!("connecting to {} and through the relay at {relay_url} ...", list(&socks)),
        (false, true) => log!("connecting to {} (then through the relay at {relay_url} too) ...", list(&socks)),
    }

    let (tx, rx) = mpsc::channel::<Option<Vec<String>>>();
    let mut lookup_started = false;
    let mut lookup_done = !opts.lookup;
    let mut learned: Vec<String> = Vec::new();
    let start = Instant::now();
    let mut last_send: Option<Instant> = None;
    let mut relay_hosts = relay.as_deref().map_or(0, Relay::hosts_seen);
    let mut buf = [0u8; 2048];
    let (session, via) = 'handshake: loop {
        if stop.load(Ordering::Relaxed) {
            return Err("stopped".into());
        }
        if !relay_joined && relay_sock.is_some() && (socks.is_empty() || start.elapsed() >= RELAY_JOIN_AFTER) {
            relay_joined = true;
            last_send = None;
            log!("no direct answer yet: trying through the relay too");
        }
        if relay_joined {
            // The host just came online at the relay: knock at once.
            let seen = relay.as_deref().map_or(0, Relay::hosts_seen);
            if seen != relay_hosts {
                relay_hosts = seen;
                last_send = None;
            }
        }
        // Nothing left to wait for: no address, the lookup is over, and the
        // relay (if any) failed in a way waiting will not fix.
        let gave_up = socks.is_empty()
            && lookup_done
            && (relay_sock.is_none() || relay.as_deref().is_none_or(Relay::failed));
        if start.elapsed() > opts.timeout || gave_up {
            let mut tried = String::new();
            for (s, addr) in &socks {
                tried += &format!("\n  {addr}: {}", why_unreachable(s, *addr, relay.is_some()));
            }
            tried += &relay_line(relay.as_deref());
            let mut msg = if tried.is_empty() {
                "the host's address is unknown and the lookup found nothing - is hyperspace-host running?".to_string()
            } else {
                format!(
                    "no answer from the host. Addresses tried:{tried}\nAlso check that hyperspace-host is running and \
                     that this is the pairing string it printed."
                )
            };
            if cfg!(target_os = "macos") {
                msg += "\nOn macOS, System Settings > Privacy & Security > Local Network must allow the terminal you launched this from.";
            }
            return Err(msg);
        }
        if last_send.is_none_or(|t| t.elapsed() >= Duration::from_millis(250)) {
            last_send = Some(Instant::now());
            for (s, _) in &socks {
                let _ = s.send(init.packet());
            }
            if let Some((s, _)) = relay_sock.as_ref().filter(|_| relay_joined) {
                let _ = s.send(init.packet());
            }
        }
        // On the host's own network the answer arrives within milliseconds;
        // only bother the lookup service when nothing came back.
        if opts.lookup && !lookup_started && (socks.is_empty() || start.elapsed() > Duration::from_millis(700)) {
            lookup_started = true;
            let (tx, key) = (tx.clone(), opts.key.clone());
            std::thread::spawn(move || {
                let found = rendezvous::connect().ok().and_then(|dht| rendezvous::resolve(&dht, &key));
                let _ = tx.send(found);
            });
        }
        if let Ok(found) = rx.try_recv() {
            lookup_done = true;
            if let Some(addrs) = found {
                let before = socks.len();
                for a in &addrs {
                    for sa in resolve_addr(a, DEFAULT_PORT) {
                        add(&mut socks, sa);
                    }
                }
                if socks.len() > before {
                    log!("found the host's current addresses: {}", addrs.join(", "));
                    last_send = None;
                }
                learned = addrs;
            }
        }
        for (i, (s, _)) in socks.iter().enumerate() {
            // Errors (ICMP unreachable, no route) just mean "not this address".
            if let Ok(n) = s.recv(&mut buf) {
                if let Some(session) = answer(&mut init, &buf[..n])? {
                    break 'handshake (session, Via::Direct(i));
                }
            }
        }
        if let Some((s, _)) = relay_sock.as_ref().filter(|_| relay_joined) {
            // A few at a time: the link's socket outlives sessions, and the
            // last one's datagrams may still trickle in.
            for _ in 0..64 {
                let Ok(n) = s.recv(&mut buf) else { break };
                if let Some(session) = answer(&mut init, &buf[..n])? {
                    break 'handshake (session, Via::Relay);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    };

    let (sock, peer, relayed) = match via {
        Via::Direct(i) => {
            let (sock, peer) = socks.swap_remove(i);
            (sock, peer, false)
        }
        Via::Relay => {
            let (sock, peer) = relay_sock.take().ok_or("the relay link closed")?;
            (sock, peer, true)
        }
    };
    drop(relay_sock);
    let mut hosts_seen = 0;
    match relay.as_deref_mut() {
        Some(r) if relayed => {
            r.won();
            hosts_seen = r.hosts_seen();
            log!("authenticated with the host through the relay ({})", r.url());
        }
        r => {
            if let Some(r) = r {
                r.stop();
            }
            log!("authenticated with {peer}{}", if is_local(peer.ip()) { "" } else { " (over the internet)" });
        }
    }
    sock.set_nonblocking(false).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_millis(100))).map_err(|e| e.to_string())?;
    let link = Link { sock, secure: session };

    // Our first encrypted packet proves to the host that we hold the session
    // keys; it then starts capturing and tells us about the stream.
    let mut plain = Vec::new();
    let start = Instant::now();
    let mut last_req: Option<Instant> = None;
    while start.elapsed() < opts.timeout {
        if stop.load(Ordering::Relaxed) {
            return Err("stopped".into());
        }
        // On a timer, not once per datagram: stray ones (the last session's,
        // on the relay link) must not set off a burst. Shorter than the
        // 100 ms read timeout, so a quiet link still asks every 100 ms.
        if last_req.is_none_or(|t| t.elapsed() >= Duration::from_millis(80)) {
            last_req = Some(Instant::now());
            link.send(&wire::req_welcome());
        }
        let n = match link.sock.recv(&mut buf) {
            Ok(n) => n,
            Err(_) => continue,
        };
        match link.secure.open(&buf[..n], &mut plain).and_then(wire::parse) {
            Some(Packet::Welcome(w)) => {
                if (w.chunk as usize) < 64 || w.width == 0 || w.height == 0 {
                    return Err("host sent an invalid WELCOME".into());
                }
                return Ok(Connection { link: Arc::new(link), welcome: w, peer, learned, relayed, hosts_seen });
            }
            Some(Packet::Bye(reason)) => {
                return Err(format!("host refused the connection: {}", bye::describe(reason)));
            }
            _ => {}
        }
    }
    Err("the host accepted the connection but never started the stream (see the host log)".into())
}

/// Sends input with redundancy until acked. Shared between the UI thread
/// (events) and the network thread (acks, resends).
pub struct InputTx {
    state: Mutex<InputState>,
}

struct InputState {
    link: Arc<Link>,
    q: InputQueue,
    buf: Vec<u8>,
    last_send_us: u64,
}

impl InputTx {
    pub fn new(link: Arc<Link>) -> InputTx {
        InputTx {
            state: Mutex::new(InputState { link, q: InputQueue::default(), buf: Vec::with_capacity(1500), last_send_us: 0 }),
        }
    }

    /// A new session replaced the last: send on its link, from a fresh queue
    /// (the new session numbers input from the start). Input typed while the
    /// client was connecting again went out on the old link, and the host
    /// dropped it: on purpose. Never carry it over, since clicks replayed
    /// late on the new session would do worse than none.
    pub fn set_link(&self, link: Arc<Link>) {
        let mut s = self.state.lock().unwrap();
        s.link = link;
        s.q = InputQueue::default();
        s.last_send_us = 0;
    }

    /// Queue an event and put it on the wire immediately.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn send(&self, ev: InputEvent) {
        let mut s = self.state.lock().unwrap();
        s.q.push(ev);
        Self::flush(&mut s);
    }

    /// Queue several events and send them in one datagram.
    pub fn send_all(&self, evs: &[InputEvent]) {
        if evs.is_empty() {
            return;
        }
        let mut s = self.state.lock().unwrap();
        for ev in evs {
            s.q.push(*ev);
        }
        Self::flush(&mut s);
    }

    fn flush(s: &mut InputState) {
        let InputState { link, q, buf, last_send_us } = s;
        if q.encode(buf) {
            link.send(buf);
            *last_send_us = now_us();
        }
    }

    pub fn on_ack(&self, seq: u32) {
        self.state.lock().unwrap().q.ack(seq);
    }

    /// Resend unacked events if the last datagram is older than `after_us`.
    pub fn resend_if_stale(&self, now: u64, after_us: u64) {
        let mut s = self.state.lock().unwrap();
        if s.q.has_unacked() && now.saturating_sub(s.last_send_us) >= after_us {
            Self::flush(&mut s);
        }
    }

    pub fn has_unacked(&self) -> bool {
        self.state.lock().unwrap().q.has_unacked()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub fps: f64,
    pub mbps: f64,
    /// Host capture -> frame handed back by the handler (decoded + presented), ms.
    pub latency_ms: Option<f64>,
    /// Time spent inside the handler (decode + render), ms.
    pub handler_ms: f64,
    pub rtt_ms: Option<f64>,
    pub frames_dropped: u64,
    pub nacks: u64,
    pub keyframe_requests: u64,
    /// The session goes through the relay.
    pub relayed: bool,
}

impl Stats {
    pub fn summary(&self) -> String {
        let mut s = format!("{:.0} fps  {:.1} Mbit/s", self.fps, self.mbps);
        if let Some(l) = self.latency_ms {
            s += &format!("  latency {:.1} ms", l);
        }
        if let Some(r) = self.rtt_ms {
            s += &format!("  rtt {:.1} ms", r);
        }
        s += &format!("  decode+present {:.1} ms", self.handler_ms);
        if self.frames_dropped != 0 || self.nacks != 0 {
            s += &format!("  dropped {}  nacks {}", self.frames_dropped, self.nacks);
        }
        if self.relayed {
            s += "  via relay";
        }
        s
    }
}

/// Receives the stream. Called on the network thread.
pub trait Handler {
    /// Decode and present. Return false if the decoder needs a keyframe to continue.
    fn video_frame(&mut self, frame: &Frame) -> bool;
    fn cursor_shape(&mut self, shape: CursorShape);
    fn cursor_visible(&mut self, visible: bool);
    fn stats(&mut self, stats: &Stats);
    /// Called once per loop iteration (at least every 20 ms), frames or not.
    fn idle(&mut self) {}
    /// A new session replaced the last one (after a reconnect): the stream
    /// starts over with a keyframe.
    fn new_session(&mut self, _welcome: &Welcome, _relayed: bool) {}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exit {
    /// We were asked to stop (window closed, frame budget reached).
    Local,
    /// The host said goodbye.
    Host(u8),
    HostTimeout,
    /// Through the relay: the host restarted, or another took its place.
    NewHost,
    /// Through the relay: the host closed this client's connection.
    RelayClosed,
    Error(String),
}

impl Exit {
    pub fn describe(&self) -> String {
        match self {
            Exit::Local => "disconnected".into(),
            Exit::Host(r) => format!("host closed the session: {}", bye::describe(*r)),
            Exit::HostTimeout => "lost contact with the host".into(),
            Exit::NewHost => "the host reconnected to the relay (restarted or replaced)".into(),
            Exit::RelayClosed => "the host closed the connection through the relay".into(),
            Exit::Error(e) => e.clone(),
        }
    }
}

/// A failure of the session's socket, without the OS error number (it
/// differs from one OS to the next) or a closing period, as the reason of a
/// longer line.
fn network_error(e: &std::io::Error) -> String {
    format!("network error: {}", clause(&plain_error(e)))
}

/// Run until `stop` is set, the host goes away, or the socket fails. Sends BYE
/// on the way out when the exit is ours. `keyframe_every_us` periodically asks
/// the host for a keyframe, and `cut_after` ends the session without a
/// goodbye (testing only).
fn receive_loop(
    conn: &Connection,
    input: &InputTx,
    stop: &AtomicBool,
    handler: &mut dyn Handler,
    keyframe_every_us: Option<u64>,
    cut_after: Option<Duration>,
    mut relay: Option<&mut Relay>,
) -> Exit {
    let cut_at = cut_after.map(|d| Instant::now() + d);
    let link = &*conn.link;
    let sock = &link.sock;
    let chunk = conn.welcome.chunk as usize;
    let mut rate = RateControl::new(conn.welcome.bitrate_kbps, conn.welcome.max_bitrate_kbps);
    let mut plain_buf = Vec::new();
    let (mut prev_dropped, mut prev_nacks) = (0u64, 0u64);
    let (mut st_delay_sum, mut st_delay_min, mut st_delay_n) = (0u64, u64::MAX, 0u64);
    let start = now_us();
    let mut video = Reassembler::new(pt::VIDEO, chunk, start);
    let mut cursor = Reassembler::new(pt::CURSOR, chunk, start);
    let mut cursor_serial = 0u32;
    let mut cursor_visible = true;
    let mut clock = ClockSync::default();
    let mut buf = vec![0u8; wire::MAX_DATAGRAM + FRAG_HEADER_LEN + DATA_OVERHEAD + 64];
    let mut out = Vec::with_capacity(1500);
    let mut ping_id = 0u32;
    let mut last_ping = 0u64;
    let mut last_forced_kf = start;
    let mut last_rx = Instant::now();
    let mut timeout_ms = 0u64;

    // Per-interval stats.
    let mut st_start = start;
    let mut st_frames = 0u64;
    let mut st_bytes = 0u64;
    let mut st_lat_sum = 0u64;
    let mut st_lat_n = 0u64;
    let mut st_handler_sum = 0u64;

    let exit = loop {
        if stop.load(Ordering::Relaxed) {
            break Exit::Local;
        }
        // A host the relay reports anew has no session with us (one atomic load).
        if conn.relayed && relay.as_deref().is_some_and(|r| r.hosts_seen() > conn.hosts_seen) {
            break Exit::NewHost;
        }
        // Wake quickly while repairs or input acks are pending; otherwise idle.
        let want_ms = if video.busy() || cursor.busy() || input.has_unacked() { 1 } else { 20 };
        if want_ms != timeout_ms {
            timeout_ms = want_ms;
            let _ = sock.set_read_timeout(Some(Duration::from_millis(want_ms)));
        }
        match sock.recv(&mut buf) {
            Ok(n) => {
                // Anything that does not authenticate is ignored outright.
                let plain: &[u8] = link.secure.open(&buf[..n], &mut plain_buf).unwrap_or(&[]);
                if !plain.is_empty() {
                    last_rx = Instant::now();
                }
                match wire::parse(plain) {
                    Some(Packet::Frag(h, payload)) if h.kind == pt::VIDEO => {
                        video.push(&h, payload, now_us());
                        while let Some(frame) = video.pop() {
                            let t0 = now_us();
                            let ok = handler.video_frame(&frame);
                            let t1 = now_us();
                            st_frames += 1;
                            st_bytes += frame.data.len() as u64;
                            st_handler_sum += t1 - t0;
                            if let Some(cap_local) = clock.peer_to_local(frame.ts_us) {
                                let lat = t1.saturating_sub(cap_local);
                                st_lat_sum += lat;
                                st_lat_n += 1;
                                let delay = frame.first_rx_us.saturating_sub(cap_local);
                                st_delay_sum += delay;
                                st_delay_min = st_delay_min.min(delay);
                                st_delay_n += 1;
                            }
                            video.recycle(frame.data);
                            if !ok {
                                video.force_keyframe(t1);
                                link.send(&wire::req_keyframe());
                            }
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                        }
                    }
                    Some(Packet::Frag(h, payload)) if h.kind == pt::CURSOR => {
                        cursor.push(&h, payload, now_us());
                        while let Some(msg) = cursor.pop() {
                            if let Some(shape) = CursorShape::decode(&msg.data) {
                                cursor_serial = msg.id;
                                handler.cursor_shape(shape);
                            }
                            cursor.recycle(msg.data);
                        }
                    }
                    Some(Packet::InputAck(seq)) => input.on_ack(seq),
                    Some(Packet::Pong { id: _, t_us, peer_t_us }) => {
                        clock.add_sample(t_us, peer_t_us, now_us());
                        if let Some(rtt) = clock.rtt_us() {
                            video.set_rtt_us(rtt);
                            cursor.set_rtt_us(rtt);
                        }
                    }
                    Some(Packet::Status { cursor_serial: _, cursor_visible: v }) => {
                        if v != cursor_visible {
                            cursor_visible = v;
                            handler.cursor_visible(v);
                        }
                    }
                    Some(Packet::Bye(reason)) => break Exit::Host(reason),
                    _ => {}
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => {}
            Err(e) if matches!(e.kind(), ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset) => {
                // The host's port is closed: it exited without saying goodbye.
                if last_rx.elapsed() > Duration::from_millis(500) {
                    break Exit::HostTimeout;
                }
            }
            Err(e) => break Exit::Error(network_error(&e)),
        }

        handler.idle();

        let now = now_us();
        video.poll(now, |a| match a {
            Action::Nack { frame_id, frags } => {
                wire::nack(&mut out, pt::VIDEO, frame_id, frags);
                link.send(&out);
            }
            Action::RequestKeyframe => {
                link.send(&wire::req_keyframe());
            }
        });
        cursor.poll(now, |a| {
            if let Action::Nack { frame_id, frags } = a {
                wire::nack(&mut out, pt::CURSOR, frame_id, frags);
                link.send(&out);
            }
        });

        let rtt = clock.rtt_us().unwrap_or(5_000);
        input.resend_if_stale(now, (rtt + rtt / 2).clamp(4_000, 100_000));

        // Ping fast at first so the clock offset settles, then relax.
        let ping_every = if now - start < 1_000_000 { 50_000 } else { PING_INTERVAL_US };
        if now.saturating_sub(last_ping) >= ping_every {
            last_ping = now;
            ping_id = ping_id.wrapping_add(1);
            link.send(&wire::ping(ping_id, now, cursor_serial));
        }

        // Test hook: a static desktop produces no frames; periodic keyframe
        // requests keep the stream flowing and exercise the IDR path.
        if let Some(every) = keyframe_every_us {
            if now - last_forced_kf >= every {
                last_forced_kf = now;
                link.send(&wire::req_keyframe());
            }
        }

        if last_rx.elapsed() > HOST_TIMEOUT {
            break Exit::HostTimeout;
        }
        if cut_at.is_some_and(|t| Instant::now() >= t) {
            break Exit::Error("test: dropped the session without a goodbye (--test-reconnect)".into());
        }

        if now - st_start >= 1_000_000 {
            let dt = (now - st_start) as f64 / 1e6;
            let ms = |us: u64, n: u64| us as f64 / n as f64 / 1000.0;
            handler.stats(&Stats {
                fps: st_frames as f64 / dt,
                mbps: st_bytes as f64 * 8.0 / dt / 1e6,
                latency_ms: (st_lat_n > 0).then(|| ms(st_lat_sum, st_lat_n)),
                handler_ms: if st_frames > 0 { ms(st_handler_sum, st_frames) } else { 0.0 },
                rtt_ms: clock.rtt_us().map(|r| r as f64 / 1000.0),
                frames_dropped: video.stats.frames_dropped,
                nacks: video.stats.nacks_sent,
                keyframe_requests: video.stats.keyframe_requests,
                relayed: conn.relayed,
            });
            // Ask the host for less (or more) if the path changed.
            let sample = Sample {
                frames: st_frames,
                delay_avg_us: (st_delay_n > 0).then(|| st_delay_sum / st_delay_n),
                delay_min_us: (st_delay_n > 0).then_some(st_delay_min),
                dropped: video.stats.frames_dropped - prev_dropped,
                nacks: video.stats.nacks_sent - prev_nacks,
                rtt_us: clock.rtt_us().unwrap_or(5_000),
            };
            prev_dropped = video.stats.frames_dropped;
            prev_nacks = video.stats.nacks_sent;
            (st_delay_sum, st_delay_min, st_delay_n) = (0, u64::MAX, 0);
            if let Some(kbps) = rate.update(&sample) {
                log!("network conditions changed: asking the host for {:.1} Mbit/s", kbps as f64 / 1000.0);
                link.send(&wire::set_bitrate(kbps));
            }
            st_start = now;
            st_frames = 0;
            st_bytes = 0;
            st_lat_sum = 0;
            st_lat_n = 0;
            st_handler_sum = 0;
            if let Some(r) = relay.as_deref_mut() {
                r.tick();
                if conn.relayed && r.status() == Some(Status::ClosedByHost) {
                    break Exit::RelayClosed;
                }
            }
        }
    };

    if exit == Exit::Local {
        for _ in 0..3 {
            link.send(&wire::bye(bye::QUIT));
        }
    }
    exit
}

/// Worth connecting again (with a relay configured): the session was lost,
/// not ended. Never after the host said goodbye or replaced this client.
fn retryable(exit: &Exit) -> bool {
    match exit {
        Exit::HostTimeout | Exit::NewHost | Exit::RelayClosed | Exit::Error(_) => true,
        Exit::Host(reason) => matches!(*reason, bye::TIMEOUT | bye::UNKNOWN_SESSION),
        Exit::Local => false,
    }
}

/// 75 to 125 % of `d`, so clients cut at the same moment do not all come back
/// at the same moment. The clock's low bits are random enough for that.
fn jittered(d: Duration) -> Duration {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |t| t.subsec_nanos());
    d.mul_f64(0.75 + f64::from(nanos % 1000) / 2000.0)
}

/// Sleeps `d` unless `stop` is set first; false if it was.
fn wait_unless_stopped(d: Duration, stop: &AtomicBool) -> bool {
    let until = Instant::now() + d;
    loop {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return true;
        }
        std::thread::sleep(left.min(Duration::from_millis(50)));
    }
}

/// Runs sessions until one ends for good. With a relay configured, a lost
/// session (silence, a new host at the relay, the host closing the relayed
/// connection) is followed by a new connect, racing the direct addresses and
/// the relay again, with a growing wait between attempts. `on_connect` sees
/// each new connection; the handler hears about it through `new_session`.
#[allow(clippy::too_many_arguments)]
pub fn run_sessions(
    opts: &Options,
    mut conn: Connection,
    input: &InputTx,
    stop: &AtomicBool,
    handler: &mut dyn Handler,
    keyframe_every_us: Option<u64>,
    mut relay: Option<&mut Relay>,
    on_connect: &mut dyn FnMut(&Connection),
) -> Exit {
    let mut wait = RETRY_FIRST;
    let mut cut = opts.cut_first_session;
    loop {
        let began = Instant::now();
        let exit = receive_loop(&conn, input, stop, handler, keyframe_every_us, cut.take(), relay.as_deref_mut());
        if relay.is_none() || stop.load(Ordering::Relaxed) || !retryable(&exit) {
            if exit == Exit::Local && conn.relayed {
                // The goodbyes are queued on the relay link: give it a moment
                // to carry them before it closes.
                std::thread::sleep(Duration::from_millis(300));
            }
            return exit;
        }
        if began.elapsed() >= STABLE_SESSION {
            wait = RETRY_FIRST;
        }
        log!("{}; connecting again", clause(&exit.describe()));
        let mut attempts = 0;
        conn = loop {
            if !wait_unless_stopped(jittered(wait), stop) {
                return Exit::Local;
            }
            wait = (wait * 2).min(RETRY_MAX);
            match connect(opts, relay.as_deref_mut(), stop) {
                Ok(c) => break c,
                Err(_) if stop.load(Ordering::Relaxed) => return Exit::Local,
                Err(e) => {
                    attempts += 1;
                    if attempts >= RETRY_ATTEMPTS {
                        return Exit::Error(e);
                    }
                    log!("{e}");
                    log!("connecting again");
                }
            }
        };
        on_connect(&conn);
        input.set_link(conn.link.clone());
        handler.new_session(&conn.welcome, conn.relayed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blocking_tunnel_points_to_the_relay_when_none_is_set() {
        let without = through_tunnel("utun4", false);
        assert_eq!(
            without,
            "traffic to this public address leaves through utun4 - a VPN or security client - which commonly blocks \
             direct UDP like this; the host's relay (--relay URL) carries the session over HTTPS instead"
        );
        let with = through_tunnel("utun4", true);
        assert_eq!(
            with,
            "traffic to this public address leaves through utun4 - a VPN or security client - which commonly blocks \
             direct UDP like this; if the relay is blocked as well, this network does not allow the session; its \
             administrators decide what it lets through"
        );
        for line in [&without, &with] {
            assert!(!line.contains("e.g."), "{line}");
            assert!(!line.contains('\n'), "{line}");
        }
    }

    #[test]
    fn only_lost_sessions_are_retried() {
        for exit in [Exit::HostTimeout, Exit::NewHost, Exit::RelayClosed, Exit::Error("network error: x".into())] {
            assert!(retryable(&exit), "{exit:?}");
        }
        assert!(retryable(&Exit::Host(bye::TIMEOUT)));
        assert!(retryable(&Exit::Host(bye::UNKNOWN_SESSION)));
        // The host said goodbye, another client took over, or we stopped.
        for exit in [Exit::Local, Exit::Host(bye::QUIT), Exit::Host(bye::REPLACED), Exit::Host(bye::STREAM_ENDED)] {
            assert!(!retryable(&exit), "{exit:?}");
        }
    }

    #[test]
    fn network_errors_read_plainly() {
        use std::io::Error;
        assert_eq!(
            network_error(&Error::new(ErrorKind::Other, "Connection refused (os error 111)")),
            "network error: Connection refused"
        );
        // Windows ends its messages with a period: "...; connecting again"
        // never reads ".;".
        let windows = "An existing connection was forcibly closed by the remote host.";
        assert_eq!(
            network_error(&Error::new(ErrorKind::ConnectionReset, windows)),
            "network error: An existing connection was forcibly closed by the remote host"
        );
        for code in [1, 10054, 111] {
            let exit = Exit::Error(network_error(&Error::from_raw_os_error(code)));
            let line = format!("{}; connecting again", clause(&exit.describe()));
            assert!(!line.contains("os error") && !line.contains(".;"), "{line:?}");
        }
    }

    #[test]
    fn a_stray_answer_leaves_the_handshake_usable() {
        // A late answer to an earlier handshake (the last session's, on the
        // relay link), or a damaged answer, is ignored, and the real one still
        // completes the handshake. This relies on the noise library putting
        // its state back after a failed read.
        let key = Key::generate();
        let ok = wire::accept(wire::ACCEPT_OK);
        let earlier = Initiator::new(&key, b"earlier");
        let (r, _) = secure::Responder::accept(&key, earlier.packet()).unwrap();
        let (_, stale) = r.finish(&ok);
        let mut init = Initiator::new(&key, b"now");
        let (r, payload) = secure::Responder::accept(&key, init.packet()).unwrap();
        assert_eq!(payload, b"now");
        let (host, real) = r.finish(&ok);
        let mut damaged = real.clone();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(matches!(answer(&mut init, &stale), Ok(None)));
        assert!(matches!(answer(&mut init, &damaged), Ok(None)));
        assert!(matches!(answer(&mut init, &real[..real.len() - 1]), Ok(None)));
        assert!(matches!(answer(&mut init, &[]), Ok(None)));
        let client = match answer(&mut init, &real) {
            Ok(Some(s)) => s,
            other => panic!("the real answer did not complete the handshake: {:?}", other.err()),
        };
        // Both ends hold the same keys.
        let (mut sealed, mut plain) = (Vec::new(), Vec::new());
        client.seal(b"ping", &mut sealed);
        assert_eq!(host.open(&sealed, &mut plain), Some(&b"ping"[..]));
        host.seal(b"pong", &mut sealed);
        assert_eq!(client.open(&sealed, &mut plain), Some(&b"pong"[..]));
    }

    #[test]
    fn retry_waits_are_jittered_within_bounds() {
        for _ in 0..100 {
            let d = jittered(Duration::from_secs(2));
            assert!(d >= Duration::from_millis(1500) && d <= Duration::from_millis(2500), "{d:?}");
        }
    }

    #[test]
    fn waiting_stops_early() {
        let stop = AtomicBool::new(true);
        let t = Instant::now();
        assert!(!wait_unless_stopped(Duration::from_secs(5), &stop));
        assert!(t.elapsed() < Duration::from_secs(1));
        stop.store(false, Ordering::Relaxed);
        assert!(wait_unless_stopped(Duration::from_millis(20), &stop));
    }

    #[test]
    fn stats_line_says_relay() {
        let mut s = Stats::default();
        assert!(!s.summary().contains("relay"));
        s.relayed = true;
        assert!(s.summary().ends_with("  via relay"));
    }
}
