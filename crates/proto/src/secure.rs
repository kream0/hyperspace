//! Authenticated encryption for the whole connection.
//!
//! Host and client share a 32-byte pairing key. A connection starts with a
//! Noise `NNpsk0` handshake (ephemeral X25519 mixed with the pairing key), so
//! only someone holding the key can talk to the host, every session has fresh
//! keys, and recorded traffic stays private even if the key leaks later.
//! Afterwards every datagram is sealed with ChaCha20-Poly1305 under an
//! explicit 64-bit counter, with a sliding window rejecting replays.
//!
//! A host that receives anything it cannot authenticate stays silent: from the
//! outside, the port looks closed.

use snow::{Builder, HandshakeState, StatelessTransportState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

const PARAMS: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"hyperspace remote desktop";

/// Outer packet types (first byte of every datagram).
pub const PT_INIT: u8 = 0x80;
pub const PT_RESP: u8 = 0x81;
pub const PT_DATA: u8 = 0x82;

const TAG_LEN: usize = 16;
/// Bytes added to every data packet: type, counter, authentication tag.
pub const DATA_OVERHEAD: usize = 1 + 8 + TAG_LEN;

/// The shared pairing key.
#[derive(Clone, PartialEq, Eq)]
pub struct Key([u8; 32]);

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(..)")
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

impl Key {
    pub fn generate() -> Key {
        let mut k = [0u8; 32];
        getrandom::fill(&mut k).expect("the operating system's random number generator is unavailable");
        Key(k)
    }

    pub fn from_bytes(b: [u8; 32]) -> Key {
        Key(b)
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// URL-safe base64 without padding (43 characters).
    pub fn encode(&self) -> String {
        let mut out = String::with_capacity(43);
        for chunk in self.0.chunks(3) {
            let n = chunk.iter().fold(0u32, |a, &b| (a << 8) | b as u32) << (8 * (3 - chunk.len()));
            for i in 0..=chunk.len() {
                out.push(B64[(n >> (18 - 6 * i)) as usize & 63] as char);
            }
        }
        out
    }

    pub fn decode(s: &str) -> Option<Key> {
        if s.len() != 43 {
            return None;
        }
        let mut bytes = Vec::with_capacity(33);
        for chunk in s.as_bytes().chunks(4) {
            let mut n = 0u32;
            for &c in chunk {
                n = (n << 6) | B64.iter().position(|&b| b == c)? as u32;
            }
            n <<= 6 * (4 - chunk.len());
            for i in 0..chunk.len() - 1 {
                bytes.push((n >> (16 - 8 * i)) as u8);
            }
        }
        Some(Key(bytes.try_into().ok()?))
    }
}

fn builder(key: &Key) -> Builder<'_> {
    Builder::new(PARAMS.parse().expect("valid noise parameters"))
        .psk(0, &key.0)
        .and_then(|b| b.prologue(PROLOGUE))
        .expect("valid noise configuration")
}

/// Client side of the handshake.
pub struct Initiator {
    hs: Option<HandshakeState>,
    packet: Vec<u8>,
}

impl Initiator {
    /// `payload` travels encrypted inside the first message.
    pub fn new(key: &Key, payload: &[u8]) -> Initiator {
        let mut hs = builder(key).build_initiator().expect("noise initiator");
        let mut packet = vec![0u8; 1 + payload.len() + 96];
        packet[0] = PT_INIT;
        let n = hs.write_message(payload, &mut packet[1..]).expect("handshake message fits");
        packet.truncate(1 + n);
        Initiator { hs: Some(hs), packet }
    }

    /// The datagram to (re)send until the host answers.
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }

    /// Process the host's answer. `None` if it is not a valid answer to this
    /// handshake (the initiator stays usable).
    pub fn finish(&mut self, resp: &[u8]) -> Option<(Session, Vec<u8>)> {
        if resp.first() != Some(&PT_RESP) {
            return None;
        }
        let mut payload = vec![0u8; resp.len()];
        let n = self.hs.as_mut()?.read_message(&resp[1..], &mut payload).ok()?;
        payload.truncate(n);
        let ts = self.hs.take()?.into_stateless_transport_mode().ok()?;
        Some((Session::new(ts), payload))
    }
}

/// Host side of the handshake.
pub struct Responder {
    hs: HandshakeState,
}

impl Responder {
    /// Authenticate a client's first message. `None` for anything not made
    /// with our pairing key. Costs a few hashes and one AEAD: cheap enough to
    /// do for every stray packet.
    pub fn accept(key: &Key, packet: &[u8]) -> Option<(Responder, Vec<u8>)> {
        if packet.first() != Some(&PT_INIT) || packet.len() > 2048 {
            return None;
        }
        let mut hs = builder(key).build_responder().ok()?;
        let mut payload = vec![0u8; packet.len()];
        let n = hs.read_message(&packet[1..], &mut payload).ok()?;
        payload.truncate(n);
        Some((Responder { hs }, payload))
    }

    /// Produce the answer datagram and the session keys.
    pub fn finish(mut self, payload: &[u8]) -> (Session, Vec<u8>) {
        let mut packet = vec![0u8; 1 + payload.len() + 96];
        packet[0] = PT_RESP;
        let n = self.hs.write_message(payload, &mut packet[1..]).expect("handshake message fits");
        packet.truncate(1 + n);
        let ts = self.hs.into_stateless_transport_mode().expect("handshake complete");
        (Session::new(ts), packet)
    }
}

const WINDOW_WORDS: usize = 32;
const WINDOW_BITS: u64 = (WINDOW_WORDS * 64) as u64;

/// Sliding anti-replay window over packet counters (as in IPsec / WireGuard).
struct ReplayWindow {
    /// Highest counter accepted so far, plus one (0 = none yet).
    next: u64,
    bits: [u64; WINDOW_WORDS],
}

impl ReplayWindow {
    fn acceptable(&self, n: u64) -> bool {
        if n >= self.next {
            return true;
        }
        if self.next - n > WINDOW_BITS {
            return false;
        }
        self.bits[(n / 64) as usize % WINDOW_WORDS] & (1 << (n % 64)) == 0
    }

    /// Mark `n` as seen. False if it was seen already or is too old.
    fn accept(&mut self, n: u64) -> bool {
        if !self.acceptable(n) {
            return false;
        }
        if n >= self.next {
            // Clear the slots the window slides over.
            let advance = (n + 1 - self.next).min(WINDOW_BITS);
            for i in 0..advance {
                let c = n - i;
                self.bits[(c / 64) as usize % WINDOW_WORDS] &= !(1 << (c % 64));
            }
            self.next = n + 1;
        }
        self.bits[(n / 64) as usize % WINDOW_WORDS] |= 1 << (n % 64);
        true
    }
}

/// Transport keys of an established connection. Shareable across threads.
pub struct Session {
    ts: StatelessTransportState,
    tx: AtomicU64,
    rx: Mutex<ReplayWindow>,
}

impl Session {
    fn new(ts: StatelessTransportState) -> Session {
        Session { ts, tx: AtomicU64::new(0), rx: Mutex::new(ReplayWindow { next: 0, bits: [0; WINDOW_WORDS] }) }
    }

    /// Encrypt `plain` into `out` (replaced) as a complete datagram.
    pub fn seal(&self, plain: &[u8], out: &mut Vec<u8>) {
        let n = self.tx.fetch_add(1, Ordering::Relaxed);
        out.clear();
        out.resize(DATA_OVERHEAD + plain.len(), 0);
        out[0] = PT_DATA;
        out[1..9].copy_from_slice(&n.to_le_bytes());
        self.ts.write_message(n, plain, &mut out[9..]).expect("datagram within noise limits");
    }

    /// Authenticate and decrypt a datagram into `out`. `None` for forgeries,
    /// replays and packets from other sessions.
    pub fn open<'a>(&self, packet: &[u8], out: &'a mut Vec<u8>) -> Option<&'a [u8]> {
        if packet.len() < DATA_OVERHEAD || packet[0] != PT_DATA {
            return None;
        }
        let n = u64::from_le_bytes(packet[1..9].try_into().unwrap());
        if !self.rx.lock().unwrap().acceptable(n) {
            return None;
        }
        out.clear();
        out.resize(packet.len() - 9, 0);
        let len = self.ts.read_message(n, &packet[9..], out).ok()?;
        // Only authenticated packets may move the window.
        if !self.rx.lock().unwrap().accept(n) {
            return None;
        }
        Some(&out[..len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(key_c: &Key, key_h: &Key) -> Option<(Session, Session)> {
        let mut init = Initiator::new(key_c, b"hello");
        let (resp, payload) = Responder::accept(key_h, init.packet())?;
        assert_eq!(payload, b"hello");
        let (host, packet) = resp.finish(b"welcome");
        let (client, payload) = init.finish(&packet)?;
        assert_eq!(payload, b"welcome");
        Some((client, host))
    }

    #[test]
    fn key_encoding_roundtrip() {
        for _ in 0..20 {
            let k = Key::generate();
            let s = k.encode();
            assert_eq!(s.len(), 43);
            assert!(s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
            assert_eq!(Key::decode(&s), Some(k));
        }
        assert_eq!(Key::decode("short"), None);
        assert_eq!(Key::decode(&"!".repeat(43)), None);
        assert_eq!(Key::from_bytes([0xff; 32]).encode(), "__________________________________________8");
    }

    #[test]
    fn handshake_and_transport() {
        let key = Key::generate();
        let (client, host) = pair(&key, &key).unwrap();
        let (mut wire, mut plain) = (Vec::new(), Vec::new());
        client.seal(b"input event", &mut wire);
        assert_eq!(wire.len(), b"input event".len() + DATA_OVERHEAD);
        assert_eq!(host.open(&wire, &mut plain), Some(&b"input event"[..]));
        host.seal(b"video", &mut wire);
        assert_eq!(client.open(&wire, &mut plain), Some(&b"video"[..]));
        // a session cannot read its own output
        assert_eq!(host.open(&wire, &mut plain), None);
    }

    #[test]
    fn wrong_key_is_rejected_at_the_first_message() {
        let init = Initiator::new(&Key::generate(), b"hello");
        assert!(Responder::accept(&Key::generate(), init.packet()).is_none());
        assert!(Responder::accept(&Key::generate(), &[PT_INIT; 50]).is_none());
        assert!(Responder::accept(&Key::generate(), &[]).is_none());
    }

    #[test]
    fn tampering_and_replay_are_rejected() {
        let key = Key::generate();
        let (client, host) = pair(&key, &key).unwrap();
        let (mut wire, mut plain) = (Vec::new(), Vec::new());
        client.seal(b"click", &mut wire);
        let mut bad = wire.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(host.open(&bad, &mut plain), None);
        let mut bad = wire.clone();
        bad[1] ^= 1; // counter
        assert_eq!(host.open(&bad, &mut plain), None);
        assert!(host.open(&wire, &mut plain).is_some());
        assert_eq!(host.open(&wire, &mut plain), None, "replay");
        // a different session with the same pairing key has different keys
        let (_, other_host) = pair(&key, &key).unwrap();
        client.seal(b"click", &mut wire);
        assert_eq!(other_host.open(&wire, &mut plain), None);
    }

    #[test]
    fn reordering_within_the_window_is_fine() {
        let key = Key::generate();
        let (client, host) = pair(&key, &key).unwrap();
        let mut packets: Vec<Vec<u8>> = (0..5000u32)
            .map(|i| {
                let mut w = Vec::new();
                client.seal(&i.to_le_bytes(), &mut w);
                w
            })
            .collect();
        // swap neighbours, and deliver one very late
        let late = packets.remove(10);
        for pair in packets.chunks_mut(2) {
            pair.swap(0, pair.len() - 1);
        }
        let mut plain = Vec::new();
        let mut ok = 0;
        for p in &packets {
            ok += host.open(p, &mut plain).is_some() as u32;
            assert_eq!(host.open(p, &mut plain), None);
        }
        assert_eq!(ok, 4999);
        assert_eq!(host.open(&late, &mut plain), None, "older than the window");
    }

    #[test]
    fn replay_window_logic() {
        let mut w = ReplayWindow { next: 0, bits: [0; WINDOW_WORDS] };
        assert!(w.accept(0));
        assert!(!w.accept(0));
        assert!(w.accept(5));
        assert!(w.accept(3));
        assert!(!w.accept(3));
        assert!(w.accept(5 + WINDOW_BITS));
        assert!(!w.accept(5), "fell out of the window");
        assert!(w.accept(6 + 1), "still inside");
        assert!(w.accept(u64::MAX - 1));
        assert!(!w.accept(100));
    }
}
