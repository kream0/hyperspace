//! Platform-independent client session: handshake, receive loop, loss repair,
//! clock sync and the input sender.

use hyperspace_proto::clock::{now_us, ClockSync};
use hyperspace_proto::cursor::CursorShape;
use hyperspace_proto::frag::{Action, Frame, Reassembler};
use hyperspace_proto::input::{InputEvent, InputQueue};
use hyperspace_proto::wire::{self, bye, pt, Hello, Packet, Welcome, FRAG_HEADER_LEN};
use hyperspace_proto::log;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const HOST_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const PING_INTERVAL_US: u64 = 200_000;

#[derive(Clone, Debug)]
pub struct Options {
    pub host: SocketAddr,
    pub fps: u16,
    pub bitrate_kbps: u32,
    pub codecs: u8,
    pub max_datagram: u16,
}

pub struct Connection {
    pub sock: Arc<UdpSocket>,
    pub welcome: Welcome,
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
    Ok(s.into())
}

/// Perform the HELLO/WELCOME handshake.
pub fn connect(opts: &Options) -> Result<Connection, String> {
    let sock = make_socket(opts.host).map_err(|e| format!("socket: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_millis(250))).map_err(|e| e.to_string())?;
    let nonce = {
        // Unique enough to tell our HELLO retries from another client's.
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        (t as u32) ^ ((t >> 32) as u32) ^ std::process::id().rotate_left(16)
    };
    let hello = wire::hello(&Hello {
        nonce,
        codecs: opts.codecs,
        fps: opts.fps,
        bitrate_kbps: opts.bitrate_kbps,
        max_datagram: opts.max_datagram,
    });
    let start = Instant::now();
    let mut buf = [0u8; 2048];
    log!("connecting to {} ...", opts.host);
    while start.elapsed() < CONNECT_TIMEOUT {
        // A refused send (ICMP unreachable) shows up as an error on a connected
        // UDP socket; the host may simply not be running yet, so keep trying.
        let _ = sock.send(&hello);
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => continue,
            Err(e) if matches!(e.kind(), ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset) => {
                std::thread::sleep(Duration::from_millis(250));
                continue;
            }
            Err(e) => return Err(format!("network error: {e}")),
        };
        match wire::parse(&buf[..n]) {
            Some(Packet::Welcome(w)) if w.nonce == nonce => {
                if (w.chunk as usize) < 64 || w.width == 0 || w.height == 0 {
                    return Err("host sent an invalid WELCOME".into());
                }
                return Ok(Connection { sock: Arc::new(sock), welcome: w });
            }
            Some(Packet::Bye(reason)) if reason != bye::UNKNOWN_SESSION => {
                return Err(format!("host refused the connection: {}", bye::describe(reason)));
            }
            None if wire::is_version_mismatch(&buf[..n]) => {
                return Err(bye::describe(bye::VERSION_MISMATCH).into());
            }
            _ => {}
        }
    }
    let mut msg = format!(
        "no answer from {} - is hyperspace-host running there and is UDP port {} allowed through its firewall?",
        opts.host,
        opts.host.port()
    );
    if cfg!(target_os = "macos") {
        msg += "\n(on macOS also check System Settings > Privacy & Security > Local Network: the terminal you launched this from must be allowed)";
    }
    Err(msg)
}

/// Sends input with redundancy until acked. Shared between the UI thread
/// (events) and the network thread (acks, resends).
pub struct InputTx {
    sock: Arc<UdpSocket>,
    state: Mutex<InputState>,
}

struct InputState {
    q: InputQueue,
    buf: Vec<u8>,
    last_send_us: u64,
}

impl InputTx {
    pub fn new(sock: Arc<UdpSocket>) -> InputTx {
        InputTx {
            sock,
            state: Mutex::new(InputState { q: InputQueue::default(), buf: Vec::with_capacity(1500), last_send_us: 0 }),
        }
    }

    /// Queue an event and put it on the wire immediately.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn send(&self, ev: InputEvent) {
        let mut s = self.state.lock().unwrap();
        s.q.push(ev);
        Self::flush(&self.sock, &mut s);
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
        Self::flush(&self.sock, &mut s);
    }

    fn flush(sock: &UdpSocket, s: &mut InputState) {
        let InputState { q, buf, last_send_us, .. } = s;
        if q.encode(buf) {
            let _ = sock.send(buf);
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
            Self::flush(&self.sock, &mut s);
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
    let sock = &*conn.sock;
    let chunk = conn.welcome.chunk as usize;
    let start = now_us();
    let mut video = Reassembler::new(pt::VIDEO, chunk, start);
    let mut cursor = Reassembler::new(pt::CURSOR, chunk, start);
    let mut cursor_serial = 0u32;
    let mut cursor_visible = true;
    let mut clock = ClockSync::default();
    let mut buf = vec![0u8; wire::MAX_DATAGRAM + FRAG_HEADER_LEN + 64];
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
                last_rx = Instant::now();
                match wire::parse(&buf[..n]) {
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
                            }
                            video.recycle(frame.data);
                            if !ok {
                                video.force_keyframe(t1);
                                let _ = sock.send(&wire::req_keyframe());
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
                let _ = sock.send(&out);
            }
            Action::RequestKeyframe => {
                let _ = sock.send(&wire::req_keyframe());
            }
        });
        cursor.poll(now, |a| {
            if let Action::Nack { frame_id, frags } = a {
                wire::nack(&mut out, pt::CURSOR, frame_id, frags);
                let _ = sock.send(&out);
            }
        });

        let rtt = clock.rtt_us().unwrap_or(5_000);
        input.resend_if_stale(now, (rtt + rtt / 2).clamp(4_000, 100_000));

        // Ping fast at first so the clock offset settles, then relax.
        let ping_every = if now - start < 1_000_000 { 50_000 } else { PING_INTERVAL_US };
        if now.saturating_sub(last_ping) >= ping_every {
            last_ping = now;
            ping_id = ping_id.wrapping_add(1);
            let _ = sock.send(&wire::ping(ping_id, now, cursor_serial));
        }

        // Test hook: a static desktop produces no frames; periodic keyframe
        // requests keep the stream flowing and exercise the IDR path.
        if let Some(every) = keyframe_every_us {
            if now - last_forced_kf >= every {
                last_forced_kf = now;
                let _ = sock.send(&wire::req_keyframe());
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
            let _ = sock.send(&wire::bye(bye::QUIT));
        }
    }
    exit
}
