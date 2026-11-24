//! Datagram layouts. All integers little-endian. First byte is the packet type.

use crate::input::InputEvent;

pub const MAGIC: [u8; 4] = *b"HYSP";
pub const PROTOCOL_VERSION: u16 = 1;

/// Largest UDP payload we ever send. 1400 fits a 1500 MTU with room for
/// tunnels; lower it with `--packet-size` for VPNs with small MTUs.
pub const DEFAULT_DATAGRAM: usize = 1400;
pub const MIN_DATAGRAM: usize = 576;
pub const MAX_DATAGRAM: usize = 8192;

pub mod pt {
    pub const HELLO: u8 = 1;
    pub const WELCOME: u8 = 2;
    pub const VIDEO: u8 = 3;
    pub const CURSOR: u8 = 4;
    pub const INPUT: u8 = 5;
    pub const INPUT_ACK: u8 = 6;
    pub const NACK: u8 = 7;
    pub const REQ_KEYFRAME: u8 = 8;
    pub const PING: u8 = 9;
    pub const PONG: u8 = 10;
    pub const BYE: u8 = 11;
    pub const STATUS: u8 = 12;
}

pub mod bye {
    pub const QUIT: u8 = 0;
    pub const REPLACED: u8 = 1;
    pub const INIT_FAILED: u8 = 2;
    pub const TIMEOUT: u8 = 3;
    pub const UNKNOWN_SESSION: u8 = 4;
    pub const VERSION_MISMATCH: u8 = 5;
    pub const STREAM_ENDED: u8 = 6;

    pub fn describe(reason: u8) -> &'static str {
        match reason {
            QUIT => "peer quit",
            REPLACED => "another client connected",
            INIT_FAILED => "host failed to start capture/encoder (see host log)",
            TIMEOUT => "timed out",
            UNKNOWN_SESSION => "host does not know this session (restarted?)",
            VERSION_MISMATCH => "protocol version mismatch - update both sides",
            STREAM_ENDED => "stream ended",
            _ => "unknown reason",
        }
    }
}

/// Frame flags carried in [`FragHeader::flags`].
pub const FLAG_KEYFRAME: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Codec {
    H264 = 1,
    Hevc = 2,
}

impl Codec {
    pub fn from_u8(v: u8) -> Option<Codec> {
        match v {
            1 => Some(Codec::H264),
            2 => Some(Codec::Hevc),
            _ => None,
        }
    }
    pub fn mask(self) -> u8 {
        self as u8
    }
    pub fn name(self) -> &'static str {
        match self {
            Codec::H264 => "h264",
            Codec::Hevc => "hevc",
        }
    }
}

pub const CODEC_MASK_ALL: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hello {
    pub nonce: u32,
    /// Bitmask of [`Codec::mask`] the client can decode.
    pub codecs: u8,
    /// Requested frame rate cap (0 = host default).
    pub fps: u16,
    /// Requested bitrate (0 = host default).
    pub bitrate_kbps: u32,
    /// Largest datagram the client wants to receive (0 = host default).
    pub max_datagram: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Welcome {
    pub nonce: u32,
    pub session: u32,
    pub codec: Codec,
    pub width: u16,
    pub height: u16,
    pub fps: u16,
    pub bitrate_kbps: u32,
    /// Fragment payload size used for every non-final fragment.
    pub chunk: u16,
}

/// Header of VIDEO / CURSOR fragments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragHeader {
    pub kind: u8,
    pub flags: u8,
    pub frag_idx: u16,
    pub frame_id: u32,
    pub frame_len: u32,
    /// Sender's monotonic clock at capture time.
    pub ts_us: u64,
}

pub const FRAG_HEADER_LEN: usize = 20;

impl FragHeader {
    #[inline]
    pub fn write(&self, out: &mut [u8]) {
        out[0] = self.kind;
        out[1] = self.flags;
        out[2..4].copy_from_slice(&self.frag_idx.to_le_bytes());
        out[4..8].copy_from_slice(&self.frame_id.to_le_bytes());
        out[8..12].copy_from_slice(&self.frame_len.to_le_bytes());
        out[12..20].copy_from_slice(&self.ts_us.to_le_bytes());
    }

    #[inline]
    pub fn read(b: &[u8]) -> Option<(FragHeader, &[u8])> {
        if b.len() < FRAG_HEADER_LEN {
            return None;
        }
        Some((
            FragHeader {
                kind: b[0],
                flags: b[1],
                frag_idx: u16::from_le_bytes([b[2], b[3]]),
                frame_id: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
                frame_len: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
                ts_us: u64::from_le_bytes(b[12..20].try_into().unwrap()),
            },
            &b[FRAG_HEADER_LEN..],
        ))
    }
}

/// NACK list: `frags.is_empty()` means "the whole frame".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nack<'a> {
    pub kind: u8,
    pub frame_id: u32,
    raw: &'a [u8],
}

impl<'a> Nack<'a> {
    pub fn whole_frame(&self) -> bool {
        self.raw.is_empty()
    }
    pub fn frags(&self) -> impl Iterator<Item = u16> + 'a {
        self.raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]]))
    }
}

/// Raw view over the events of an INPUT packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputEvents<'a> {
    raw: &'a [u8],
}

pub const INPUT_EVENT_LEN: usize = 9;

impl<'a> InputEvents<'a> {
    pub fn iter(&self) -> impl Iterator<Item = (u32, InputEvent)> + 'a {
        self.raw.chunks_exact(INPUT_EVENT_LEN).filter_map(|c| {
            let seq = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            InputEvent::decode(c[4], [c[5], c[6], c[7], c[8]]).map(|e| (seq, e))
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet<'a> {
    Hello(Hello),
    Welcome(Welcome),
    Frag(FragHeader, &'a [u8]),
    Input(InputEvents<'a>),
    InputAck(u32),
    Nack(Nack<'a>),
    RequestKeyframe,
    Ping { id: u32, t_us: u64, cursor_serial: u32 },
    Pong { id: u32, t_us: u64, peer_t_us: u64 },
    Bye(u8),
    Status { cursor_serial: u32, cursor_visible: bool },
}

struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    }
    fn magic(&mut self) -> Option<()> {
        (self.take(4)? == MAGIC).then_some(())
    }
}

/// Outcome of parsing a HELLO/WELCOME whose magic matched but whose version
/// did not; lets each side answer with a clear error instead of silence.
pub fn is_version_mismatch(buf: &[u8]) -> bool {
    buf.len() >= 7
        && (buf[0] == pt::HELLO || buf[0] == pt::WELCOME)
        && buf[1..5] == MAGIC
        && u16::from_le_bytes([buf[5], buf[6]]) != PROTOCOL_VERSION
}

pub fn parse(buf: &[u8]) -> Option<Packet<'_>> {
    let ty = *buf.first()?;
    let mut r = R(&buf[1..]);
    Some(match ty {
        pt::VIDEO | pt::CURSOR => {
            let (h, payload) = FragHeader::read(buf)?;
            Packet::Frag(h, payload)
        }
        pt::INPUT => {
            let n = r.u8()? as usize;
            Packet::Input(InputEvents { raw: r.take(n * INPUT_EVENT_LEN)? })
        }
        pt::INPUT_ACK => Packet::InputAck(r.u32()?),
        pt::NACK => {
            let kind = r.u8()?;
            let frame_id = r.u32()?;
            let n = r.u16()? as usize;
            Packet::Nack(Nack { kind, frame_id, raw: r.take(n * 2)? })
        }
        pt::REQ_KEYFRAME => Packet::RequestKeyframe,
        pt::PING => Packet::Ping { id: r.u32()?, t_us: r.u64()?, cursor_serial: r.u32()? },
        pt::PONG => Packet::Pong { id: r.u32()?, t_us: r.u64()?, peer_t_us: r.u64()? },
        pt::BYE => Packet::Bye(r.u8()?),
        pt::STATUS => Packet::Status { cursor_serial: r.u32()?, cursor_visible: r.u8()? != 0 },
        pt::HELLO => {
            r.magic()?;
            if r.u16()? != PROTOCOL_VERSION {
                return None;
            }
            Packet::Hello(Hello {
                nonce: r.u32()?,
                codecs: r.u8()?,
                fps: r.u16()?,
                bitrate_kbps: r.u32()?,
                max_datagram: r.u16()?,
            })
        }
        pt::WELCOME => {
            r.magic()?;
            if r.u16()? != PROTOCOL_VERSION {
                return None;
            }
            Packet::Welcome(Welcome {
                nonce: r.u32()?,
                session: r.u32()?,
                codec: Codec::from_u8(r.u8()?)?,
                width: r.u16()?,
                height: r.u16()?,
                fps: r.u16()?,
                bitrate_kbps: r.u32()?,
                chunk: r.u16()?,
            })
        }
        _ => return None,
    })
}

// ---- encoders -------------------------------------------------------------

pub fn hello(h: &Hello) -> Vec<u8> {
    let mut v = Vec::with_capacity(24);
    v.push(pt::HELLO);
    v.extend_from_slice(&MAGIC);
    v.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    v.extend_from_slice(&h.nonce.to_le_bytes());
    v.push(h.codecs);
    v.extend_from_slice(&h.fps.to_le_bytes());
    v.extend_from_slice(&h.bitrate_kbps.to_le_bytes());
    v.extend_from_slice(&h.max_datagram.to_le_bytes());
    v
}

pub fn welcome(w: &Welcome) -> Vec<u8> {
    let mut v = Vec::with_capacity(32);
    v.push(pt::WELCOME);
    v.extend_from_slice(&MAGIC);
    v.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    v.extend_from_slice(&w.nonce.to_le_bytes());
    v.extend_from_slice(&w.session.to_le_bytes());
    v.push(w.codec as u8);
    v.extend_from_slice(&w.width.to_le_bytes());
    v.extend_from_slice(&w.height.to_le_bytes());
    v.extend_from_slice(&w.fps.to_le_bytes());
    v.extend_from_slice(&w.bitrate_kbps.to_le_bytes());
    v.extend_from_slice(&w.chunk.to_le_bytes());
    v
}

pub fn input_ack(seq: u32) -> [u8; 5] {
    let mut b = [pt::INPUT_ACK, 0, 0, 0, 0];
    b[1..].copy_from_slice(&seq.to_le_bytes());
    b
}

/// Append an INPUT packet with the given events to `out` (cleared first).
pub fn input<'e>(out: &mut Vec<u8>, events: impl Iterator<Item = &'e (u32, InputEvent)>) {
    out.clear();
    out.push(pt::INPUT);
    out.push(0);
    let mut n = 0u8;
    for (seq, ev) in events {
        if n == u8::MAX {
            break;
        }
        let (kind, payload) = ev.encode();
        out.extend_from_slice(&seq.to_le_bytes());
        out.push(kind);
        out.extend_from_slice(&payload);
        n += 1;
    }
    out[1] = n;
}

/// `frags` empty = request the whole frame.
pub fn nack(out: &mut Vec<u8>, kind: u8, frame_id: u32, frags: &[u16]) {
    out.clear();
    out.push(pt::NACK);
    out.push(kind);
    out.extend_from_slice(&frame_id.to_le_bytes());
    out.extend_from_slice(&(frags.len() as u16).to_le_bytes());
    for f in frags {
        out.extend_from_slice(&f.to_le_bytes());
    }
}

pub fn req_keyframe() -> [u8; 1] {
    [pt::REQ_KEYFRAME]
}

pub fn ping(id: u32, t_us: u64, cursor_serial: u32) -> [u8; 17] {
    let mut b = [0u8; 17];
    b[0] = pt::PING;
    b[1..5].copy_from_slice(&id.to_le_bytes());
    b[5..13].copy_from_slice(&t_us.to_le_bytes());
    b[13..17].copy_from_slice(&cursor_serial.to_le_bytes());
    b
}

pub fn pong(id: u32, t_us: u64, peer_t_us: u64) -> [u8; 21] {
    let mut b = [0u8; 21];
    b[0] = pt::PONG;
    b[1..5].copy_from_slice(&id.to_le_bytes());
    b[5..13].copy_from_slice(&t_us.to_le_bytes());
    b[13..21].copy_from_slice(&peer_t_us.to_le_bytes());
    b
}

pub fn bye(reason: u8) -> [u8; 2] {
    [pt::BYE, reason]
}

pub fn status(cursor_serial: u32, cursor_visible: bool) -> [u8; 6] {
    let mut b = [0u8; 6];
    b[0] = pt::STATUS;
    b[1..5].copy_from_slice(&cursor_serial.to_le_bytes());
    b[5] = cursor_visible as u8;
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_roundtrip() {
        let h = Hello { nonce: 0xdeadbeef, codecs: 3, fps: 120, bitrate_kbps: 30000, max_datagram: 1400 };
        assert_eq!(parse(&hello(&h)), Some(Packet::Hello(h)));
        let w = Welcome {
            nonce: 7,
            session: 9,
            codec: Codec::Hevc,
            width: 3840,
            height: 2160,
            fps: 120,
            bitrate_kbps: 50000,
            chunk: 1380,
        };
        assert_eq!(parse(&welcome(&w)), Some(Packet::Welcome(w)));
    }

    #[test]
    fn version_mismatch_detected() {
        let mut b = hello(&Hello { nonce: 1, codecs: 1, fps: 0, bitrate_kbps: 0, max_datagram: 0 });
        b[5] = 99;
        assert_eq!(parse(&b), None);
        assert!(is_version_mismatch(&b));
    }

    #[test]
    fn control_roundtrip() {
        assert_eq!(parse(&ping(3, 44, 5)), Some(Packet::Ping { id: 3, t_us: 44, cursor_serial: 5 }));
        assert_eq!(parse(&pong(3, 44, 55)), Some(Packet::Pong { id: 3, t_us: 44, peer_t_us: 55 }));
        assert_eq!(parse(&bye(1)), Some(Packet::Bye(1)));
        assert_eq!(parse(&status(8, true)), Some(Packet::Status { cursor_serial: 8, cursor_visible: true }));
        assert_eq!(parse(&input_ack(77)), Some(Packet::InputAck(77)));
        assert_eq!(parse(&req_keyframe()), Some(Packet::RequestKeyframe));
        let mut v = Vec::new();
        nack(&mut v, pt::VIDEO, 12, &[1, 5, 9]);
        match parse(&v) {
            Some(Packet::Nack(n)) => {
                assert_eq!(n.frame_id, 12);
                assert_eq!(n.frags().collect::<Vec<_>>(), vec![1, 5, 9]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn truncated_packets_rejected() {
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&[pt::PING, 1, 2]), None);
        assert_eq!(parse(&[pt::INPUT, 2, 0, 0]), None);
        assert_eq!(parse(&[pt::VIDEO; 5]), None);
    }
}
