//! UDP session server: encrypted handshake, retransmits, input, liveness.
//!
//! One client at a time; a newly authenticated client replaces the current
//! session. The capture/encode pipeline only runs while a client is connected
//! and pushes packets straight onto the socket from its own thread - the
//! server thread handles everything that flows the other way.
//!
//! Nothing is ever sent in response to a packet that does not authenticate
//! with the pairing key, so to anyone else the port is indistinguishable
//! from a closed one.

use crate::inject::{new_injector, Injector};
use crate::pipeline::{self, Config, Control, Sink, StreamInfo, StreamRequest};
use hyperspace_proto::clock::now_us;
use hyperspace_proto::cursor::CursorShape;
use hyperspace_proto::frag::Fragmenter;
use hyperspace_proto::input::InputReceiver;
use hyperspace_proto::pairing::is_local;
use hyperspace_proto::secure::{self, Responder, DATA_OVERHEAD, PT_DATA, PT_INIT};
use hyperspace_proto::wire::{self, bye, pt, Hello, Packet, FLAG_KEYFRAME, FRAG_HEADER_LEN};
use hyperspace_bridge::{plain_error, RelayedPeers};
use hyperspace_proto::{annexb, log, Codec};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{ErrorKind, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Set (by the console control handler) to make the server say goodbye to its
/// client, release held keys and return.
pub static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Outer packet type of the host's own reachability probe (see `reach`).
pub const PT_PROBE: u8 = 0x83;
/// Token of the probe currently in flight (0 = none) and whether it arrived.
pub static PROBE_TOKEN: AtomicU64 = AtomicU64::new(0);
pub static PROBE_SEEN: AtomicBool = AtomicBool::new(false);

/// Frames kept for NACK retransmission.
const STORE_FRAMES: usize = 48;
const SESSION_TIMEOUT: Duration = Duration::from_secs(5);
const STATUS_INTERVAL: Duration = Duration::from_millis(200);
const STATS_INTERVAL: Duration = Duration::from_secs(5);
/// Handshakes answered but not yet confirmed by an encrypted packet.
const MAX_PENDING: usize = 8;
const PENDING_TTL: Duration = Duration::from_secs(10);

thread_local! {
    static WIRE: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

struct Stored {
    id: u32,
    flags: u8,
    ts_us: u64,
    data: Vec<u8>,
}

#[derive(Default)]
struct VideoTx {
    frag: Fragmenter,
    wire: Vec<u8>,
    next_id: u32,
    store: VecDeque<Stored>,
    dump: Option<std::fs::File>,
}

#[derive(Default)]
struct CursorTx {
    frag: Fragmenter,
    wire: Vec<u8>,
    serial: u32,
    visible: bool,
    msg: Vec<u8>,
    last_sent_us: u64,
}

#[derive(Default)]
struct Stats {
    frames: AtomicU64,
    keyframes: AtomicU64,
    bytes: AtomicU64,
    retransmits: AtomicU64,
    /// Keyframe requests from the client.
    keyframe_requests: AtomicU64,
    /// Requests to resend video fragments (each one resends one or more of
    /// the `retransmits`)...
    resend_requests: AtomicU64,
    /// ...and those for a frame no longer kept, answered with a keyframe.
    too_old: AtomicU64,
    /// Sum / max of capture -> packets-on-the-wire time.
    latency_sum_us: AtomicU64,
    latency_max_us: AtomicU64,
}

/// Keyframes sent, and what the client asked for to repair the stream: the
/// 5-second line shows them with their rise, the line that closes the
/// session their totals.
#[derive(Clone, Copy, Default)]
struct Repairs {
    keyframes: u64,
    keyframe_requests: u64,
    resend_requests: u64,
    too_old: u64,
}

impl Repairs {
    fn now(st: &Stats) -> Repairs {
        let n = |count: &AtomicU64| count.load(Ordering::Relaxed);
        Repairs {
            keyframes: n(&st.keyframes),
            keyframe_requests: n(&st.keyframe_requests),
            resend_requests: n(&st.resend_requests),
            too_old: n(&st.too_old),
        }
    }

    /// Each count for the session so far, with its rise since `last` (the
    /// previous line) in parentheses, so that a jump in retransmits can be
    /// matched to the keyframes and requests around it.
    fn text(&self, last: &Repairs) -> String {
        let rise = |now: u64, then: u64| now.saturating_sub(then);
        format!(
            "{} keyframes (+{}), {} keyframe requests (+{}), {} resend requests (+{}), {} too old to resend (+{})",
            self.keyframes,
            rise(self.keyframes, last.keyframes),
            self.keyframe_requests,
            rise(self.keyframe_requests, last.keyframe_requests),
            self.resend_requests,
            rise(self.resend_requests, last.resend_requests),
            self.too_old,
            rise(self.too_old, last.too_old)
        )
    }
}

/// The line that closes a session: what it sent, then the repair totals (the
/// keyframes beside the frames), without the rises of the 5-second line.
fn ended_line(session: u32, secs: f64, st: &Stats, input_events: u64) -> String {
    let n = |count: &AtomicU64| count.load(Ordering::Relaxed);
    let r = Repairs::now(st);
    format!(
        "session {session} ended after {secs:.1}s: {} frames ({} keyframes), {:.1} MB, {} retransmits, \
         {input_events} input events, {} keyframe requests, {} resend requests, {} too old to resend",
        n(&st.frames),
        r.keyframes,
        n(&st.bytes) as f64 / 1e6,
        n(&st.retransmits),
        r.keyframe_requests,
        r.resend_requests,
        r.too_old
    )
}

/// Per-session state shared with the pipeline thread.
pub struct Shared {
    sock: Arc<UdpSocket>,
    /// The client's current address; follows it if it roams.
    addr: RwLock<SocketAddr>,
    secure: secure::Session,
    session: u32,
    chunk: usize,
    welcome: Mutex<Option<Vec<u8>>>,
    info: Mutex<Option<StreamInfo>>,
    video: Mutex<VideoTx>,
    cursor: Mutex<CursorTx>,
    stats: Stats,
}

impl Shared {
    fn addr(&self) -> SocketAddr {
        *self.addr.read().unwrap()
    }

    /// Encrypt and send one control packet.
    fn send(&self, plain: &[u8]) {
        WIRE.with(|w| {
            let mut w = w.borrow_mut();
            self.secure.seal(plain, &mut w);
            let _ = self.sock.send_to(&w, self.addr());
        });
    }

    fn send_cursor_shape(&self, c: &mut CursorTx) {
        if c.msg.is_empty() {
            return;
        }
        let addr = self.addr();
        let CursorTx { frag, wire, serial, msg, .. } = c;
        frag.send_all(pt::CURSOR, FLAG_KEYFRAME, *serial, 0, msg, self.chunk, |d| {
            self.secure.seal(d, wire);
            let _ = self.sock.send_to(wire, addr);
        });
        c.last_sent_us = now_us();
    }

    /// Resend fragments; false if the frame is no longer available.
    fn retransmit(&self, n: &wire::Nack<'_>) -> bool {
        let addr = self.addr();
        match n.kind {
            pt::VIDEO => {
                let mut v = self.video.lock().unwrap();
                let VideoTx { frag, wire, store, .. } = &mut *v;
                let mut send = |d: &[u8]| {
                    self.secure.seal(d, wire);
                    let _ = self.sock.send_to(wire, addr);
                    self.stats.retransmits.fetch_add(1, Ordering::Relaxed);
                };
                let Some(first) = store.front().map(|s| s.id) else { return false };
                let Some(s) = store.get(n.frame_id.wrapping_sub(first) as usize) else { return false };
                if n.whole_frame() {
                    frag.send_all(pt::VIDEO, s.flags, s.id, s.ts_us, &s.data, self.chunk, send);
                } else {
                    for idx in n.frags() {
                        frag.send_one(pt::VIDEO, s.flags, s.id, s.ts_us, &s.data, self.chunk, idx as usize, &mut send);
                    }
                }
                true
            }
            pt::CURSOR => {
                let mut c = self.cursor.lock().unwrap();
                if n.frame_id == c.serial && !c.msg.is_empty() {
                    let CursorTx { frag, wire, serial, msg, .. } = &mut *c;
                    let mut send = |d: &[u8]| {
                        self.secure.seal(d, wire);
                        let _ = self.sock.send_to(wire, addr);
                    };
                    if n.whole_frame() {
                        frag.send_all(pt::CURSOR, FLAG_KEYFRAME, *serial, 0, msg, self.chunk, send);
                    } else {
                        for idx in n.frags() {
                            frag.send_one(pt::CURSOR, FLAG_KEYFRAME, *serial, 0, msg, self.chunk, idx as usize, &mut send);
                        }
                    }
                }
                true
            }
            _ => true,
        }
    }
}

impl Sink for Shared {
    fn started(&self, info: &StreamInfo) {
        let w = wire::welcome(&wire::Welcome {
            nonce: 0,
            session: self.session,
            codec: info.codec,
            width: info.width as u16,
            height: info.height as u16,
            fps: info.fps as u16,
            bitrate_kbps: info.bitrate_kbps,
            max_bitrate_kbps: info.max_bitrate_kbps,
            chunk: self.chunk as u16,
        });
        self.send(&w);
        *self.info.lock().unwrap() = Some(*info);
        *self.welcome.lock().unwrap() = Some(w);
        log!(
            "stream started: {}x{} @ {} fps, {}, {:.1} Mbit/s",
            info.width,
            info.height,
            info.fps,
            info.codec.name(),
            info.bitrate_kbps as f64 / 1000.0
        );
    }

    fn frame(&self, data: &[u8], keyframe: bool, ts_us: u64) {
        if data.is_empty() {
            return;
        }
        let addr = self.addr();
        let mut v = self.video.lock().unwrap();
        let id = v.next_id;
        v.next_id = id.wrapping_add(1);
        let flags = if keyframe { FLAG_KEYFRAME } else { 0 };
        let VideoTx { frag, wire, store, dump, .. } = &mut *v;
        frag.send_all(pt::VIDEO, flags, id, ts_us, data, self.chunk, |d| {
            self.secure.seal(d, wire);
            let _ = self.sock.send_to(wire, addr);
        });
        let lat = now_us().saturating_sub(ts_us);
        self.stats.latency_sum_us.fetch_add(lat, Ordering::Relaxed);
        self.stats.latency_max_us.fetch_max(lat, Ordering::Relaxed);
        self.stats.frames.fetch_add(1, Ordering::Relaxed);
        self.stats.keyframes.fetch_add(keyframe as u64, Ordering::Relaxed);
        self.stats.bytes.fetch_add(data.len() as u64, Ordering::Relaxed);

        let mut buf = if store.len() >= STORE_FRAMES { store.pop_front().unwrap().data } else { Vec::new() };
        buf.clear();
        buf.extend_from_slice(data);
        store.push_back(Stored { id, flags, ts_us, data: buf });

        if let Some(f) = dump {
            let codec = self.info.lock().unwrap().map(|i| i.codec).unwrap_or(Codec::H264);
            write_dump(f, codec, data);
        }
    }

    fn cursor(&self, shape: Option<&CursorShape>, visible: bool) {
        let mut c = self.cursor.lock().unwrap();
        if let Some(shape) = shape {
            c.serial = c.serial.wrapping_add(1).max(1);
            c.msg = shape.encode();
            self.send_cursor_shape(&mut c);
        }
        if c.visible != visible || shape.is_some() {
            c.visible = visible;
            self.send(&wire::status(c.serial, c.visible));
        }
    }
}

/// Append an access unit to an Annex B dump, delimiting it with an AUD so the
/// file can be replayed with `--file` (and played by ffplay/VLC).
pub fn write_dump(f: &mut std::fs::File, codec: Codec, au: &[u8]) {
    if !annexb::inspect(codec, au).has_aud {
        let _ = f.write_all(annexb::aud(codec));
    }
    let _ = f.write_all(au);
}

/// A handshake we answered; becomes the session once the client proves it
/// holds the session keys (which a replayed first message cannot).
struct Pending {
    init: Vec<u8>,
    resp: Vec<u8>,
    secure: secure::Session,
    hello: Hello,
    created: Instant,
}

struct Session {
    shared: Arc<Shared>,
    ctl: Arc<Control>,
    thread: Option<JoinHandle<Result<(), String>>>,
    /// The handshake that created this session, to answer retransmissions.
    init: Vec<u8>,
    resp: Vec<u8>,
    started_at: Instant,
    /// Whether the client is across the internet or comes through the relay,
    /// as of its latest address.
    wan: bool,
    last_rx: Instant,
    last_status: Instant,
    last_stats: Instant,
    last_frames: u64,
    last_bytes: u64,
    /// The repairs in the last 5-second line, for the rise in the next one.
    last_repairs: Repairs,
    input_rx: InputReceiver,
    injector: Box<dyn Injector>,
    applied_rect: Option<(i32, i32, i32, i32)>,
    client_cursor_serial: u32,
}

pub struct Server {
    cfg: Config,
    sock: Arc<UdpSocket>,
    session: Option<Session>,
    pending: Vec<Pending>,
    next_session_id: u32,
    plain: Vec<u8>,
    /// Loopback addresses of clients that come through the relay.
    relayed: RelayedPeers,
}

/// Bind the listening socket. With no explicit address this is one
/// dual-stack socket serving IPv4 and IPv6.
pub fn bind_socket(bind: Option<SocketAddr>, port: u16) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let make = |addr: SocketAddr, dual: bool| -> std::io::Result<UdpSocket> {
        let s = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        if dual {
            s.set_only_v6(false)?;
        }
        // Big buffers: a keyframe is a burst of a few hundred datagrams.
        for size in [8 << 20, 2 << 20, 512 << 10] {
            if s.set_send_buffer_size(size).is_ok() {
                break;
            }
        }
        let _ = s.set_recv_buffer_size(1 << 20);
        s.bind(&addr.into())?;
        Ok(s.into())
    };
    match bind {
        Some(addr) => make(addr, false),
        None => make(SocketAddr::from(([0u16; 8], port)), true).or_else(|_| make(SocketAddr::from(([0u8; 4], port)), false)),
    }
}

/// Whether a client at `from` is across the internet. One through the relay
/// (`relayed`: `from` is one of [`RelayedPeers`]) is, though its datagrams
/// come from a loopback socket of the relay bridge.
fn is_wan(from: SocketAddr, relayed: bool) -> bool {
    relayed || !is_local(from.ip())
}

/// The session's client, so far across the internet or not (`was_wan`),
/// moved to `from`: the line saying so, and the new value of `wan` if the
/// move took it between the local network and the internet.
fn roamed(from: SocketAddr, relayed: bool, was_wan: bool) -> (String, Option<bool>) {
    let via = if relayed { " (through the relay)" } else { "" };
    let wan = is_wan(from, relayed);
    (format!("client moved to {}{via}", pretty(from)), (wan != was_wan).then_some(wan))
}

impl Server {
    pub fn new(cfg: Config) -> Result<Server, String> {
        let sock =
            bind_socket(cfg.bind, cfg.port).map_err(|e| format!("cannot bind UDP port {}: {}", cfg.port, plain_error(&e)))?;
        sock.set_read_timeout(Some(Duration::from_millis(20))).map_err(|e| plain_error(&e))?;
        Ok(Server {
            cfg,
            sock: Arc::new(sock),
            session: None,
            pending: Vec::new(),
            next_session_id: 1,
            plain: Vec::new(),
            relayed: RelayedPeers::new(),
        })
    }

    /// The set the relay bridge fills with the addresses its clients come
    /// from; the server treats those clients as being on the internet.
    pub fn relayed_peers(&self) -> RelayedPeers {
        self.relayed.clone()
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.sock.local_addr().ok()
    }

    /// Serve until shut down (or, with `--once`, until the first session ends).
    pub fn run(&mut self) -> Result<(), String> {
        let mut buf = vec![0u8; 65536];
        let mut had_session = false;
        loop {
            match self.sock.recv_from(&mut buf) {
                Ok((n, from)) => self.handle(&buf[..n], from),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => {}
                // Windows reports ICMP port-unreachable for earlier sends as a recv error.
                Err(e) if e.kind() == ErrorKind::ConnectionReset => {}
                Err(e) => return Err(format!("socket error: {}", plain_error(&e))),
            }
            if SHUTDOWN.load(Ordering::Relaxed) {
                log!("shutting down");
                self.end_session(Some(bye::QUIT));
                return Ok(());
            }
            self.housekeeping();
            had_session |= self.session.is_some();
            if self.cfg.once && had_session && self.session.is_none() {
                return Ok(());
            }
        }
    }

    fn handle(&mut self, buf: &[u8], from: SocketAddr) {
        match buf.first() {
            Some(&PT_INIT) => self.on_init(buf, from),
            Some(&PT_DATA) => self.on_data(buf, from),
            // Our own probe came back in through the router: note it, answer nothing.
            Some(&PT_PROBE) if buf.len() == 9 => {
                let token = u64::from_le_bytes(buf[1..9].try_into().unwrap());
                if token != 0 && token == PROBE_TOKEN.load(Ordering::Relaxed) {
                    PROBE_SEEN.store(true, Ordering::Relaxed);
                }
            }
            _ => {}
        }
    }

    /// First handshake message. Answered only if it was made with our key.
    fn on_init(&mut self, buf: &[u8], from: SocketAddr) {
        // Retransmissions get the same answer again.
        if let Some(s) = self.session.as_ref().filter(|s| s.init == buf) {
            let _ = self.sock.send_to(&s.resp, from);
            return;
        }
        if let Some(p) = self.pending.iter().find(|p| p.init == buf) {
            let _ = self.sock.send_to(&p.resp, from);
            return;
        }
        let Some((responder, payload)) = Responder::accept(&self.cfg.key, buf) else { return };
        let hello = match wire::parse(&payload) {
            Some(Packet::Hello(h)) => h,
            _ => {
                if wire::is_version_mismatch(&payload) {
                    log!("{from}: client speaks a different protocol version; update both sides");
                    let (_, resp) = responder.finish(&wire::accept(wire::ACCEPT_VERSION_MISMATCH));
                    let _ = self.sock.send_to(&resp, from);
                }
                return;
            }
        };
        let (secure, resp) = responder.finish(&wire::accept(wire::ACCEPT_OK));
        let _ = self.sock.send_to(&resp, from);
        if self.pending.len() >= MAX_PENDING {
            self.pending.remove(0);
        }
        self.pending.push(Pending { init: buf.to_vec(), resp, secure, hello, created: Instant::now() });
    }

    fn on_data(&mut self, buf: &[u8], from: SocketAddr) {
        let mut plain = std::mem::take(&mut self.plain);
        if let Some(s) = self.session.as_mut() {
            if s.shared.secure.open(buf, &mut plain).is_some() {
                if s.shared.addr() != from {
                    // Authenticated packets from a new address: the client moved networks.
                    let (moved, flipped) = roamed(from, self.relayed.contains(from), s.wan);
                    log!("{moved}");
                    *s.shared.addr.write().unwrap() = from;
                    if let Some(wan) = flipped {
                        // The packet size and the start bitrate were set for
                        // the old path. The size cannot change mid-session (the
                        // client reassembles with it) and the relay carries
                        // any size; the client's rate control moves the
                        // bitrate.
                        s.wan = wan;
                        log!(
                            "the client is now {}; this session keeps {}-byte packets",
                            if wan { "across the internet" } else { "on the local network" },
                            s.shared.chunk + DATA_OVERHEAD + FRAG_HEADER_LEN
                        );
                    }
                }
                self.on_packet(&plain);
                self.plain = plain;
                return;
            }
        }
        if let Some(i) = self.pending.iter().position(|p| p.secure.open(buf, &mut plain).is_some()) {
            let p = self.pending.remove(i);
            self.pending.clear();
            self.commit(p, from);
            self.on_packet(&plain);
        }
        self.plain = plain;
    }

    /// A decrypted packet from the session's client.
    fn on_packet(&mut self, plain: &[u8]) {
        let Some(s) = self.session.as_mut() else { return };
        let Some(pkt) = wire::parse(plain) else { return };
        s.last_rx = Instant::now();
        match pkt {
            Packet::Input(evs) => {
                // Cheap, and follows display mode changes mid-session.
                let rect = s.shared.info.lock().unwrap().and_then(|i| i.desktop_rect);
                if rect != s.applied_rect {
                    if let Some(r) = rect {
                        s.injector.set_desktop_rect(r);
                    }
                    s.applied_rect = rect;
                }
                for (seq, ev) in evs.iter() {
                    if s.input_rx.accept(seq) {
                        s.injector.inject(ev);
                    }
                }
                s.shared.send(&wire::input_ack(s.input_rx.last()));
            }
            Packet::Nack(n) => {
                let st = &s.shared.stats;
                if n.kind == pt::VIDEO {
                    st.resend_requests.fetch_add(1, Ordering::Relaxed);
                }
                if !s.shared.retransmit(&n) {
                    st.too_old.fetch_add(1, Ordering::Relaxed);
                    s.ctl.keyframe.store(true, Ordering::Relaxed);
                }
            }
            Packet::RequestKeyframe => {
                s.shared.stats.keyframe_requests.fetch_add(1, Ordering::Relaxed);
                s.ctl.keyframe.store(true, Ordering::Relaxed);
            }
            Packet::RequestWelcome => {
                if let Some(w) = s.shared.welcome.lock().unwrap().as_ref() {
                    s.shared.send(w);
                }
            }
            Packet::SetBitrate(kbps) => {
                if let Some(info) = *s.shared.info.lock().unwrap() {
                    if info.max_bitrate_kbps != 0 {
                        let kbps = kbps.clamp(500.min(info.max_bitrate_kbps), info.max_bitrate_kbps);
                        s.ctl.bitrate_kbps.store(kbps, Ordering::Relaxed);
                    }
                }
            }
            Packet::Ping { id, t_us, cursor_serial } => {
                s.client_cursor_serial = cursor_serial;
                s.shared.send(&wire::pong(id, t_us, now_us()));
            }
            Packet::Bye(reason) => {
                log!("client {} disconnected: {}", pretty(s.shared.addr()), bye::describe(reason));
                self.end_session(None);
            }
            _ => {}
        }
    }

    /// The client proved it holds the session keys: make it the session.
    fn commit(&mut self, p: Pending, from: SocketAddr) {
        if let Some(s) = &self.session {
            log!("new client {} replaces {}", pretty(from), pretty(s.shared.addr()));
            self.end_session(Some(bye::REPLACED));
        }
        let h = p.hello;
        let relayed = self.relayed.contains(from);
        let wan = is_wan(from, relayed);
        let mut datagram = self.cfg.packet_size;
        if wan {
            datagram = datagram.min(wire::WAN_DATAGRAM);
        }
        if h.max_datagram != 0 {
            datagram = datagram.min(h.max_datagram as usize);
        }
        let datagram = datagram.clamp(wire::MIN_DATAGRAM, wire::MAX_DATAGRAM);
        let dump = self.cfg.dump.as_ref().and_then(|p| match std::fs::File::create(p) {
            Ok(f) => Some(f),
            Err(e) => {
                log!("cannot create dump file {}: {}", p.display(), plain_error(&e));
                None
            }
        });
        let shared = Arc::new(Shared {
            sock: self.sock.clone(),
            addr: RwLock::new(from),
            secure: p.secure,
            session: self.next_session_id,
            chunk: datagram - DATA_OVERHEAD - FRAG_HEADER_LEN,
            welcome: Mutex::new(None),
            info: Mutex::new(None),
            video: Mutex::new(VideoTx { dump, ..Default::default() }),
            cursor: Mutex::new(CursorTx { visible: true, ..Default::default() }),
            stats: Stats::default(),
        });
        self.next_session_id += 1;
        let ctl = Arc::new(Control::default());
        let req = StreamRequest { codecs: h.codecs, fps: h.fps as u32, bitrate_kbps: h.bitrate_kbps, wan };
        log!(
            "client {} connected{} (fps {}, bitrate {}, codecs {:#b})",
            pretty(from),
            if relayed {
                " through the relay"
            } else if wan {
                " over the internet"
            } else {
                ""
            },
            if h.fps == 0 { "auto".to_string() } else { h.fps.to_string() },
            if h.bitrate_kbps == 0 { "auto".to_string() } else { format!("{} kbit/s", h.bitrate_kbps) },
            h.codecs
        );
        let thread = {
            let (cfg, ctl, shared) = (self.cfg.clone(), ctl.clone(), shared.clone());
            std::thread::Builder::new()
                .name("pipeline".into())
                .spawn(move || pipeline::run(&cfg, req, ctl, shared))
                .expect("spawn pipeline thread")
        };
        let now = Instant::now();
        self.session = Some(Session {
            shared,
            ctl,
            thread: Some(thread),
            init: p.init,
            resp: p.resp,
            started_at: now,
            wan,
            last_rx: now,
            last_status: now,
            last_stats: now,
            last_frames: 0,
            last_bytes: 0,
            last_repairs: Repairs::default(),
            input_rx: InputReceiver::default(),
            injector: new_injector(self.cfg.view_only),
            applied_rect: None,
            client_cursor_serial: 0,
        });
    }

    fn housekeeping(&mut self) {
        self.pending.retain(|p| p.created.elapsed() < PENDING_TTL);
        let Some(s) = self.session.as_mut() else { return };
        let now = Instant::now();

        if s.thread.as_ref().is_some_and(|t| t.is_finished()) {
            let welcomed = s.shared.welcome.lock().unwrap().is_some();
            match s.thread.take().unwrap().join() {
                Ok(Ok(())) => log!("pipeline stopped"),
                Ok(Err(e)) => log!("pipeline failed: {e}"),
                Err(_) => log!("pipeline thread panicked"),
            }
            self.end_session(Some(if welcomed { bye::STREAM_ENDED } else { bye::INIT_FAILED }));
            return;
        }
        if now.duration_since(s.last_rx) > SESSION_TIMEOUT {
            log!("client {} timed out", pretty(s.shared.addr()));
            self.end_session(Some(bye::TIMEOUT));
            return;
        }
        if now.duration_since(s.last_status) >= STATUS_INTERVAL {
            s.last_status = now;
            let mut c = s.shared.cursor.lock().unwrap();
            s.shared.send(&wire::status(c.serial, c.visible));
            // Cursor shapes are the one host->client message that must arrive.
            if c.serial != 0 && s.client_cursor_serial != c.serial && now_us().saturating_sub(c.last_sent_us) > 250_000 {
                s.shared.send_cursor_shape(&mut c);
            }
        }
        if now.duration_since(s.last_stats) >= STATS_INTERVAL {
            let dt = now.duration_since(s.last_stats).as_secs_f64();
            s.last_stats = now;
            let st = &s.shared.stats;
            let frames = st.frames.load(Ordering::Relaxed);
            let bytes = st.bytes.load(Ordering::Relaxed);
            let df = frames - s.last_frames;
            let db = bytes - s.last_bytes;
            s.last_frames = frames;
            s.last_bytes = bytes;
            let sum = st.latency_sum_us.swap(0, Ordering::Relaxed);
            let max = st.latency_max_us.swap(0, Ordering::Relaxed);
            if df > 0 {
                let repairs = Repairs::now(st);
                log!(
                    "{:.1} fps, {:.2} Mbit/s, capture->wire avg {:.2} ms max {:.2} ms, {} retransmits, {}",
                    df as f64 / dt,
                    db as f64 * 8.0 / dt / 1e6,
                    sum as f64 / df as f64 / 1000.0,
                    max as f64 / 1000.0,
                    st.retransmits.load(Ordering::Relaxed),
                    repairs.text(&s.last_repairs)
                );
                s.last_repairs = repairs;
            }
        }
    }

    /// Tear the session down. `notify` sends a BYE with that reason first.
    fn end_session(&mut self, notify: Option<u8>) {
        let Some(mut s) = self.session.take() else { return };
        s.ctl.stop.store(true, Ordering::Relaxed);
        if let Some(reason) = notify {
            for _ in 0..3 {
                s.shared.send(&wire::bye(reason));
            }
        }
        // Never leave a key or button held down on the host.
        s.injector.release_all();
        if let Some(t) = s.thread.take() {
            match t.join() {
                Ok(Err(e)) => log!("pipeline failed: {e}"),
                Err(_) => log!("pipeline thread panicked"),
                Ok(Ok(())) => {}
            }
        }
        log!(
            "{}",
            ended_line(s.shared.session, s.started_at.elapsed().as_secs_f64(), &s.shared.stats, s.injector.injected())
        );
    }
}

/// Address for log lines (IPv4 peers on the dual-stack socket shown as IPv4).
fn pretty(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_five_second_line_shows_repairs_so_far_and_their_rise() {
        let st = Stats::default();
        let add = |count: &AtomicU64, n: u64| count.fetch_add(n, Ordering::Relaxed);
        // A session's first line: its first keyframe, asked for.
        add(&st.keyframes, 1);
        add(&st.keyframe_requests, 1);
        let first = Repairs::now(&st);
        assert_eq!(
            first.text(&Repairs::default()),
            "1 keyframes (+1), 1 keyframe requests (+1), 0 resend requests (+0), 0 too old to resend (+0)"
        );
        // Then 350 resend requests, one of them for a frame no longer kept,
        // which was answered with a keyframe.
        add(&st.resend_requests, 350);
        add(&st.too_old, 1);
        add(&st.keyframes, 1);
        let second = Repairs::now(&st);
        assert_eq!(
            second.text(&first),
            "2 keyframes (+1), 1 keyframe requests (+0), 350 resend requests (+350), 1 too old to resend (+1)"
        );
        // Nothing new: the totals stay, the rises are 0.
        assert_eq!(
            Repairs::now(&st).text(&second),
            "2 keyframes (+0), 1 keyframe requests (+0), 350 resend requests (+0), 1 too old to resend (+0)"
        );
    }

    #[test]
    fn the_session_ended_line_shows_the_repair_totals() {
        let st = Stats::default();
        let add = |count: &AtomicU64, n: u64| count.fetch_add(n, Ordering::Relaxed);
        add(&st.frames, 369);
        add(&st.keyframes, 14);
        add(&st.bytes, 4_210_000);
        add(&st.retransmits, 84);
        add(&st.keyframe_requests, 13);
        add(&st.resend_requests, 350);
        add(&st.too_old, 1);
        // Totals only: the session is over, there is no rise to show.
        assert_eq!(
            ended_line(3, 12.34, &st, 52),
            "session 3 ended after 12.3s: 369 frames (14 keyframes), 4.2 MB, 84 retransmits, 52 input events, \
             13 keyframe requests, 350 resend requests, 1 too old to resend"
        );
    }

    #[test]
    fn a_client_is_on_the_internet_unless_its_address_is_local() {
        for a in ["192.0.2.7:45800", "[2001:db8::7]:45800", "[::ffff:192.0.2.7]:45800"] {
            assert!(is_wan(a.parse().unwrap(), false), "{a}");
            assert!(is_wan(a.parse().unwrap(), true), "{a}");
        }
        for a in ["127.0.0.1:50000", "192.168.1.20:45800", "10.0.0.2:45800", "[::1]:50000", "[fe80::1]:45800", "[::ffff:192.168.1.20]:45800"] {
            assert!(!is_wan(a.parse().unwrap(), false), "{a}");
        }
        // Through the relay, from a loopback socket of the relay bridge.
        for a in ["127.0.0.1:50000", "[::1]:50000", "[::ffff:127.0.0.1]:50000"] {
            assert!(is_wan(a.parse().unwrap(), true), "{a}");
        }
    }

    #[test]
    fn a_client_that_moves_to_or_from_the_relay_changes_path() {
        let at = |a: &str| -> SocketAddr { a.parse().unwrap() };
        let line = |a: &str| a.to_string();
        // From the local network to the relay, and back.
        assert_eq!(
            roamed(at("127.0.0.1:50000"), true, false),
            (line("client moved to 127.0.0.1:50000 (through the relay)"), Some(true))
        );
        assert_eq!(roamed(at("192.168.1.20:45801"), false, true), (line("client moved to 192.168.1.20:45801"), Some(false)));
        // From the internet to the relay, or to a new socket of the relay
        // bridge after a new relay link: still across the internet.
        assert_eq!(
            roamed(at("[::ffff:127.0.0.1]:50001"), true, true),
            (line("client moved to 127.0.0.1:50001 (through the relay)"), None)
        );
        // From the relay to a direct path across the internet.
        assert_eq!(roamed(at("192.0.2.7:45800"), false, true), (line("client moved to 192.0.2.7:45800"), None));
        // Directly, from the local network to the internet and between two
        // local addresses.
        assert_eq!(roamed(at("[2001:db8::7]:45800"), false, false).1, Some(true));
        assert_eq!(roamed(at("10.0.0.2:45800"), false, false).1, None);
        // A loopback address that is not one of the relay bridge's is local.
        assert_eq!(roamed(at("127.0.0.1:50002"), false, true).1, Some(false));
    }
}
