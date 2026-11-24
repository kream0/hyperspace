//! Platform-independent client session: encrypted handshake, receive loop,
//! loss repair, clock sync, bitrate control and the input sender.

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
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const HOST_TIMEOUT: Duration = Duration::from_secs(5);
const PING_INTERVAL_US: u64 = 200_000;

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
}

fn make_socket(host: SocketAddr) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::for_address(host), Type::DGRAM, Some(Protocol::UDP))?;
    // Room for a burst of keyframe datagrams while the decode thread is busy.
    for size in [8 << 20, 4 << 20, 1 << 20, 256 << 10] {
        if s.set_recv_buffer_size(size).is_ok() {
            break;
        }
    }
    let local: SocketAddr = if host.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { ([0u16; 8], 0).into() };
    s.bind(&local.into())?;
    s.connect(&host.into())?;
    s.set_nonblocking(true)?;
    Ok(s.into())
}

/// Connect: authenticate with the pairing key over whichever address answers
/// first, then wait for the host to start its stream.
pub fn connect(opts: &Options) -> Result<Connection, String> {
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
    if socks.is_empty() && !opts.lookup {
        return Err("no usable address for the host".into());
    }
    log!("connecting to {} ...", if socks.is_empty() { "the host (looking up its address)".to_string() } else { list(&socks) });

    let (tx, rx) = mpsc::channel::<Option<Vec<String>>>();
    let mut lookup_started = false;
    let mut lookup_done = !opts.lookup;
    let mut learned: Vec<String> = Vec::new();
    let start = Instant::now();
    let mut last_send: Option<Instant> = None;
    let mut buf = [0u8; 2048];
    let (session, winner) = 'handshake: loop {
        if start.elapsed() > opts.timeout || (socks.is_empty() && lookup_done) {
            let mut msg = if socks.is_empty() {
                "the host's address is unknown and the lookup found nothing - is hyperspace-host running?".to_string()
            } else {
                format!(
                    "no answer from {}.\n  - is hyperspace-host running, and is this the pairing string it printed?\n  \
                     - from outside its network the host's router must forward the UDP port (the host log says whether that worked)",
                    list(&socks)
                )
            };
            if cfg!(target_os = "macos") {
                msg += "\n  - on macOS: System Settings > Privacy & Security > Local Network must allow the terminal you launched this from";
            }
            return Err(msg);
        }
        if last_send.is_none_or(|t| t.elapsed() >= Duration::from_millis(250)) {
            last_send = Some(Instant::now());
            for (s, _) in &socks {
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
                if let Some((session, payload)) = init.finish(&buf[..n]) {
                    match payload.first() {
                        Some(&wire::ACCEPT_OK) => break 'handshake (session, i),
                        Some(&wire::ACCEPT_VERSION_MISMATCH) => return Err(bye::describe(bye::VERSION_MISMATCH).into()),
                        _ => return Err("the host sent an invalid answer".into()),
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    };

    let (sock, peer) = socks.swap_remove(winner);
    sock.set_nonblocking(false).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_millis(100))).map_err(|e| e.to_string())?;
    let link = Link { sock, secure: session };
    log!("authenticated with {peer}{}", if is_local(peer.ip()) { "" } else { " (over the internet)" });

    // Our first encrypted packet proves to the host that we hold the session
    // keys; it then starts capturing and tells us about the stream.
    let mut plain = Vec::new();
    let start = Instant::now();
    while start.elapsed() < opts.timeout {
        link.send(&wire::req_welcome());
        let n = match link.sock.recv(&mut buf) {
            Ok(n) => n,
            Err(_) => continue,
        };
        match link.secure.open(&buf[..n], &mut plain).and_then(wire::parse) {
            Some(Packet::Welcome(w)) => {
                if (w.chunk as usize) < 64 || w.width == 0 || w.height == 0 {
                    return Err("host sent an invalid WELCOME".into());
                }
                return Ok(Connection { link: Arc::new(link), welcome: w, peer, learned });
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
    link: Arc<Link>,
    state: Mutex<InputState>,
}

struct InputState {
    q: InputQueue,
    buf: Vec<u8>,
    last_send_us: u64,
}

impl InputTx {
    pub fn new(link: Arc<Link>) -> InputTx {
        InputTx {
            link,
            state: Mutex::new(InputState { q: InputQueue::default(), buf: Vec::with_capacity(1500), last_send_us: 0 }),
        }
    }

    /// Queue an event and put it on the wire immediately.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn send(&self, ev: InputEvent) {
        let mut s = self.state.lock().unwrap();
        s.q.push(ev);
        Self::flush(&self.link, &mut s);
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
        Self::flush(&self.link, &mut s);
    }

    fn flush(link: &Link, s: &mut InputState) {
        let InputState { q, buf, last_send_us, .. } = s;
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
            Self::flush(&self.link, &mut s);
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exit {
    /// We were asked to stop (window closed, frame budget reached).
    Local,
    /// The host said goodbye.
    Host(u8),
    HostTimeout,
    Error(String),
}

impl Exit {
    pub fn describe(&self) -> String {
        match self {
            Exit::Local => "disconnected".into(),
            Exit::Host(r) => format!("host closed the session: {}", bye::describe(*r)),
            Exit::HostTimeout => "lost contact with the host".into(),
            Exit::Error(e) => e.clone(),
        }
    }
}

/// Run until `stop` is set, the host goes away, or the socket fails. Sends BYE
/// on the way out when the exit is ours. `keyframe_every_us` periodically asks
/// the host for a keyframe (testing only).
pub fn receive_loop(
    conn: &Connection,
    input: &InputTx,
    stop: &AtomicBool,
    handler: &mut dyn Handler,
    keyframe_every_us: Option<u64>,
) -> Exit {
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
            Err(e) => break Exit::Error(format!("network error: {e}")),
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
        }
    };

    if exit == Exit::Local {
        for _ in 0..3 {
            link.send(&wire::bye(bye::QUIT));
        }
    }
    exit
}
