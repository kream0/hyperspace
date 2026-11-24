//! UDP session server: handshake, retransmits, input, liveness.
//!
//! One client at a time; a new HELLO replaces the current session. The
//! capture/encode pipeline only runs while a client is connected and pushes
//! packets straight onto the socket from its own thread - the server thread
//! handles everything that flows the other way.

use crate::inject::{new_injector, Injector};
use crate::pipeline::{self, Config, Control, Sink, StreamInfo, StreamRequest};
use hyperspace_proto::clock::now_us;
use hyperspace_proto::cursor::CursorShape;
use hyperspace_proto::frag::Fragmenter;
use hyperspace_proto::input::InputReceiver;
use hyperspace_proto::wire::{self, bye, pt, Packet, FLAG_KEYFRAME, FRAG_HEADER_LEN};
use hyperspace_proto::{annexb, log, Codec};
use std::collections::VecDeque;
use std::io::{ErrorKind, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Frames kept for NACK retransmission.
const STORE_FRAMES: usize = 48;
const SESSION_TIMEOUT: Duration = Duration::from_secs(5);
const STATUS_INTERVAL: Duration = Duration::from_millis(200);
const STATS_INTERVAL: Duration = Duration::from_secs(5);

struct Stored {
    id: u32,
    flags: u8,
    ts_us: u64,
    data: Vec<u8>,
}

#[derive(Default)]
struct VideoTx {
    frag: Fragmenter,
    next_id: u32,
    store: VecDeque<Stored>,
    dump: Option<std::fs::File>,
}

#[derive(Default)]
struct CursorTx {
    frag: Fragmenter,
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
    /// Sum / max of capture -> packets-on-the-wire time.
    latency_sum_us: AtomicU64,
    latency_max_us: AtomicU64,
}

/// Per-session state shared with the pipeline thread.
pub struct Shared {
    sock: Arc<UdpSocket>,
    addr: SocketAddr,
    nonce: u32,
    session: u32,
    chunk: usize,
    welcome: Mutex<Option<Vec<u8>>>,
    info: Mutex<Option<StreamInfo>>,
    video: Mutex<VideoTx>,
    cursor: Mutex<CursorTx>,
    stats: Stats,
}

impl Shared {
    fn send(&self, d: &[u8]) {
        let _ = self.sock.send_to(d, self.addr);
    }

    fn send_cursor_shape(&self, c: &mut CursorTx) {
        if c.msg.is_empty() {
            return;
        }
        let CursorTx { frag, serial, msg, .. } = c;
        frag.send_all(pt::CURSOR, FLAG_KEYFRAME, *serial, 0, msg, self.chunk, |d| {
            let _ = self.sock.send_to(d, self.addr);
        });
        c.last_sent_us = now_us();
    }

    /// Resend fragments; false if the frame is no longer available.
    fn retransmit(&self, n: &wire::Nack<'_>) -> bool {
        let mut send = |d: &[u8]| {
            let _ = self.sock.send_to(d, self.addr);
            self.stats.retransmits.fetch_add(1, Ordering::Relaxed);
        };
        match n.kind {
            pt::VIDEO => {
                let mut v = self.video.lock().unwrap();
                let VideoTx { frag, store, .. } = &mut *v;
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
                    let CursorTx { frag, serial, msg, .. } = &mut *c;
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
            nonce: self.nonce,
            session: self.session,
            codec: info.codec,
            width: info.width as u16,
            height: info.height as u16,
            fps: info.fps as u16,
            bitrate_kbps: info.bitrate_kbps,
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
        let mut v = self.video.lock().unwrap();
        let id = v.next_id;
        v.next_id = id.wrapping_add(1);
        let flags = if keyframe { FLAG_KEYFRAME } else { 0 };
        let VideoTx { frag, store, dump, .. } = &mut *v;
        frag.send_all(pt::VIDEO, flags, id, ts_us, data, self.chunk, |d| {
            let _ = self.sock.send_to(d, self.addr);
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

struct Session {
    shared: Arc<Shared>,
    ctl: Arc<Control>,
    thread: Option<JoinHandle<Result<(), String>>>,
    started_at: Instant,
    last_rx: Instant,
    last_status: Instant,
    last_stats: Instant,
    last_frames: u64,
    last_bytes: u64,
    input_rx: InputReceiver,
    injector: Box<dyn Injector>,
    applied_rect: Option<(i32, i32, i32, i32)>,
    client_cursor_serial: u32,
}

pub struct Server {
    cfg: Config,
    sock: Arc<UdpSocket>,
    session: Option<Session>,
    next_session_id: u32,
    last_unknown_reply: Instant,
}

pub fn bind_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    // Big buffers: a keyframe is a burst of a few hundred datagrams.
    for size in [8 << 20, 2 << 20, 512 << 10] {
        if s.set_send_buffer_size(size).is_ok() {
            break;
        }
    }
    let _ = s.set_recv_buffer_size(1 << 20);
    s.bind(&addr.into())?;
    Ok(s.into())
}

impl Server {
    pub fn new(cfg: Config) -> Result<Server, String> {
        let sock = bind_socket(cfg.bind).map_err(|e| format!("cannot bind UDP {}: {e}", cfg.bind))?;
        sock.set_read_timeout(Some(Duration::from_millis(20))).map_err(|e| e.to_string())?;
        Ok(Server {
            cfg,
            sock: Arc::new(sock),
            session: None,
            next_session_id: 1,
            last_unknown_reply: Instant::now(),
        })
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.sock.local_addr().ok()
    }

    /// Serve until the process is killed (or, with `--once`, until the first session ends).
    pub fn run(&mut self) -> Result<(), String> {
        let mut buf = vec![0u8; 65536];
        let mut had_session = false;
        loop {
            match self.sock.recv_from(&mut buf) {
                Ok((n, from)) => self.handle(&buf[..n], from),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => {}
                // Windows reports ICMP port-unreachable for earlier sends as a recv error.
                Err(e) if e.kind() == ErrorKind::ConnectionReset => {}
                Err(e) => return Err(format!("socket error: {e}")),
            }
            self.housekeeping();
            had_session |= self.session.is_some();
            if self.cfg.once && had_session && self.session.is_none() {
                return Ok(());
            }
        }
    }

    fn handle(&mut self, buf: &[u8], from: SocketAddr) {
        let Some(pkt) = wire::parse(buf) else {
            if wire::is_version_mismatch(buf) {
                log!("{from}: protocol version mismatch");
                let _ = self.sock.send_to(&wire::bye(bye::VERSION_MISMATCH), from);
            }
            return;
        };
        if let Packet::Hello(h) = pkt {
            self.on_hello(h, from);
            return;
        }
        let Some(s) = self.session.as_mut().filter(|s| s.shared.addr == from) else {
            // Tell stale clients to go away (rate limited; the reply is smaller than any request).
            if self.last_unknown_reply.elapsed() > Duration::from_millis(200) && !matches!(pkt, Packet::Bye(_)) {
                self.last_unknown_reply = Instant::now();
                let _ = self.sock.send_to(&wire::bye(bye::UNKNOWN_SESSION), from);
            }
            return;
        };
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
                if !s.shared.retransmit(&n) {
                    s.ctl.keyframe.store(true, Ordering::Relaxed);
                }
            }
            Packet::RequestKeyframe => s.ctl.keyframe.store(true, Ordering::Relaxed),
            Packet::Ping { id, t_us, cursor_serial } => {
                s.client_cursor_serial = cursor_serial;
                s.shared.send(&wire::pong(id, t_us, now_us()));
            }
            Packet::Bye(reason) => {
                log!("client {from} disconnected: {}", bye::describe(reason));
                self.end_session(None);
            }
            _ => {}
        }
    }

    fn on_hello(&mut self, h: wire::Hello, from: SocketAddr) {
        if let Some(s) = &self.session {
            if s.shared.addr == from && s.shared.nonce == h.nonce {
                // Retransmitted HELLO: repeat the WELCOME if the pipeline is up.
                if let Some(w) = s.shared.welcome.lock().unwrap().as_ref() {
                    s.shared.send(w);
                }
                return;
            }
            log!("new client {from} replaces {}", s.shared.addr);
            self.end_session(Some(bye::REPLACED));
        }

        let mut datagram = self.cfg.packet_size;
        if h.max_datagram != 0 {
            datagram = datagram.min(h.max_datagram as usize);
        }
        let datagram = datagram.clamp(wire::MIN_DATAGRAM, wire::MAX_DATAGRAM);
        let dump = self.cfg.dump.as_ref().and_then(|p| match std::fs::File::create(p) {
            Ok(f) => Some(f),
            Err(e) => {
                log!("cannot create dump file {}: {e}", p.display());
                None
            }
        });
        let shared = Arc::new(Shared {
            sock: self.sock.clone(),
            addr: from,
            nonce: h.nonce,
            session: self.next_session_id,
            chunk: datagram - FRAG_HEADER_LEN,
            welcome: Mutex::new(None),
            info: Mutex::new(None),
            video: Mutex::new(VideoTx { dump, ..Default::default() }),
            cursor: Mutex::new(CursorTx { visible: true, ..Default::default() }),
            stats: Stats::default(),
        });
        self.next_session_id += 1;
        let ctl = Arc::new(Control::default());
        let req = StreamRequest { codecs: h.codecs, fps: h.fps as u32, bitrate_kbps: h.bitrate_kbps };
        log!(
            "client {from} connecting (fps {}, bitrate {}, codecs {:#b})",
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
            started_at: now,
            last_rx: now,
            last_status: now,
            last_stats: now,
            last_frames: 0,
            last_bytes: 0,
            input_rx: InputReceiver::default(),
            injector: new_injector(self.cfg.view_only),
            applied_rect: None,
            client_cursor_serial: 0,
        });
    }

    fn housekeeping(&mut self) {
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
            log!("client {} timed out", s.shared.addr);
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
                log!(
                    "{:.1} fps, {:.2} Mbit/s, capture->wire avg {:.2} ms max {:.2} ms, {} retransmits",
                    df as f64 / dt,
                    db as f64 * 8.0 / dt / 1e6,
                    sum as f64 / df as f64 / 1000.0,
                    max as f64 / 1000.0,
                    st.retransmits.load(Ordering::Relaxed)
                );
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
        let st = &s.shared.stats;
        log!(
            "session {} ended after {:.1}s: {} frames ({} keyframes), {:.1} MB, {} retransmits, {} input events",
            s.shared.session,
            s.started_at.elapsed().as_secs_f64(),
            st.frames.load(Ordering::Relaxed),
            st.keyframes.load(Ordering::Relaxed),
            st.bytes.load(Ordering::Relaxed) as f64 / 1e6,
            st.retransmits.load(Ordering::Relaxed),
            s.injector.injected()
        );
    }
}
