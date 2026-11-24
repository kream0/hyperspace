//! Relay: a fallback path for networks that cannot send UDP at all.
//!
//! Host and client each open an outbound WebSocket to a relay (over TLS on
//! port 443 in practice; TLS ends in front of the relay). The relay pairs the
//! two by *room* and forwards opaque bytes: one binary WebSocket message
//! carries one sealed hyperspace datagram. The Noise handshake still runs end
//! to end inside those datagrams, so the relay never holds the pairing key and
//! only ever sees ciphertext.
//!
//! # Rooms and authentication
//!
//! The room is identified by an Ed25519 public key derived one-way from the
//! pairing key ([`RoomKey::derive`]). Knowing the room id reveals nothing about
//! the pairing key, and it differs from the key used for the DHT rendezvous
//! record. On connect the relay sends a CHALLENGE with a fresh random nonce;
//! the peer answers HELLO with its role, the room id and a signature over
//! `"hyperspace relay auth v1" || role byte || nonce` made with the room key.
//! The relay checks the signature against the room id, which proves the peer
//! holds the pairing key without the relay learning it; the fresh nonce makes
//! a recorded HELLO useless on another connection.
//!
//! A room has at most one host (a newly authenticated host replaces the old
//! one) and several clients. The relay numbers clients with a `peer` id that
//! is only meaningful on the host's link.
//!
//! # Messages
//!
//! Each message is one binary WebSocket message. The first byte is the type
//! ([`mt`]); integers are little-endian. Text messages are ignored.
//!
//! | type | name        | direction             | bytes after the type byte                      |
//! |------|-------------|-----------------------|------------------------------------------------|
//! | 1    | CHALLENGE   | relay → peer          | version u8, nonce \[32\]                       |
//! | 2    | HELLO       | peer → relay          | version u8, role u8, room id \[32\], signature \[64\] |
//! | 3    | OK          | relay → peer          | (none)                                         |
//! | 4    | REFUSED     | relay → peer          | reason u8 ([`refused`]); the relay then closes |
//! | 5    | STATUS      | relay → client        | host_online u8 (0 or 1)                        |
//! | 6    | PEER_OPEN   | relay → host          | peer u32                                       |
//! | 7    | PEER_CLOSE  | host ↔ relay          | peer u32                                       |
//! | 8    | HOST_DATA   | host ↔ relay          | peer u32, datagram                             |
//! | 9    | CLIENT_DATA | client ↔ relay        | datagram                                       |
//!
//! Role bytes: 1 = host, 2 = client. A datagram is at most [`MAX_PAYLOAD`]
//! bytes; anything longer does not decode, and the relay closes a link that
//! sends a message it cannot decode. A bridge must therefore drop an oversize
//! datagram itself instead of sending it.
//!
//! # Conversation
//!
//! 1. relay → peer: CHALLENGE. The peer answers HELLO built with
//!    [`RoomKey::hello`].
//! 2. relay → peer: OK, or REFUSED and the connection closes.
//! 3. Client: the relay sends STATUS right after OK, and again whenever the
//!    host comes or goes. STATUS with host_online = 1 can arrive while the
//!    host is already online: a new host replaced the old one (the client
//!    should treat it as a new host and start a new handshake). CLIENT_DATA
//!    flows both ways; datagrams sent while no host is online are dropped.
//! 4. Host: the relay sends PEER_OPEN for every client already waiting and for
//!    each one that joins later, and PEER_CLOSE when a client leaves. The host
//!    sends HOST_DATA addressed to a peer, and PEER_CLOSE to drop a client.
//!    HOST_DATA for a peer that is not open (or already closed) must be
//!    dropped by both sides.
//!
//! The relay drops datagrams when a link falls behind or a room exceeds its
//! rate, exactly as a congested UDP path would; it never drops control
//! messages (a link that cannot take one is closed instead).
//!
//! # Closing
//!
//! The relay starts a WebSocket close (sends the first close frame) in
//! exactly three cases ([`close`]):
//!
//! | code | reason                 | sent to  | when                                                  |
//! |------|------------------------|----------|-------------------------------------------------------|
//! | 1008 | `"refused"`            | any peer | right after REFUSED, also when it did not authenticate in time ([`refused::TIMEOUT`]) |
//! | 4001 | `"replaced"`           | a host   | a newer host with the same pairing key took the room  |
//! | 1000 | `"closed by the host"` | a client | its host sent PEER_CLOSE for it                       |
//!
//! Before 4001 or 1000 the relay writes what was already queued for the
//! link. A link that does not take that and the close frame within 5
//! seconds is dropped without a close frame. A room has at most 4 such
//! links closing at once: when another one starts closing (a host replaced
//! over and over, say), the oldest is dropped at once, with or without its
//! close frame.
//!
//! Every other end is a dropped TCP connection, with no close frame (in
//! particular no 1009 for a message too big):
//!
//! - a message over the relay's WebSocket size limit, or a data message
//!   with a datagram over [`MAX_PAYLOAD`];
//! - a message that does not decode, or that is not meant for the peer's
//!   role (HOST_DATA from a client, for example);
//! - a link the relay hears nothing from (not even a pong) for 60 seconds
//!   (the default);
//! - a peer that does not take one of the relay's writes within 10 seconds
//!   (the default), or whose queue is too full to take a control message;
//! - before authentication: a message over the size limit, a broken
//!   WebSocket frame, or the peer closing (it gets no REFUSED either).
//!
//! When an authenticated peer closes first, the relay answers its close
//! frame and ends the link.
//!
//! # Rules for a bridge
//!
//! - HTTP 503 instead of the WebSocket upgrade: the relay is busy. Back off
//!   before trying again.
//! - Answer CHALLENGE with HELLO within 5 seconds (the default), or the
//!   relay refuses the connection with [`refused::TIMEOUT`].
//! - Keep reading, and answer pings: the relay pings every 20 seconds (the
//!   default) and drops a link it hears nothing from for 60 seconds.
//! - Drop a datagram over [`MAX_PAYLOAD`] locally: sending it drops the
//!   whole link.
//! - After 1008 `"refused"`, act on the REFUSED reason: retrying soon does
//!   not help for [`refused::NOT_ALLOWED`], [`refused::BAD_SIGNATURE`] or
//!   [`refused::VERSION_MISMATCH`] (say so), nor for [`refused::PROTOCOL`],
//!   which is a bug on the bridge's side (its HELLO did not decode): say
//!   so and retry slowly, as for NOT_ALLOWED. [`refused::ROOM_FULL`],
//!   [`refused::RELAY_FULL`] and [`refused::TIMEOUT`] may pass after a
//!   back-off.
//! - After 1000 `"closed by the host"` (a client): the host let this client
//!   go. Do not reconnect at once.
//! - After 4001 `"replaced"` (a host): back off, or stop and say so.
//!   Reconnecting at once takes the room from the newer host, which then
//!   does the same, in a loop.
//! - Any end without a close frame, or a lost connection: reconnect, with
//!   back-off.

use crate::rendezvous::derive;
use crate::secure::Key;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Version of this protocol, carried by CHALLENGE and HELLO.
pub const VERSION: u8 = 1;
/// HTTP path the relay serves the WebSocket on.
pub const PATH: &str = "/v1";
pub const NONCE_LEN: usize = 32;
pub const ROOM_ID_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
/// Largest datagram a data message may carry.
pub const MAX_PAYLOAD: usize = crate::wire::MAX_DATAGRAM;
/// Largest valid relay message (HOST_DATA with a full datagram).
pub const MAX_MESSAGE: usize = 1 + 4 + MAX_PAYLOAD;

const ROOM_LABEL: &[u8] = b"hyperspace relay room v1";
const AUTH_LABEL: &[u8] = b"hyperspace relay auth v1";

/// Message types (first byte).
pub mod mt {
    pub const CHALLENGE: u8 = 1;
    pub const HELLO: u8 = 2;
    pub const OK: u8 = 3;
    pub const REFUSED: u8 = 4;
    pub const STATUS: u8 = 5;
    pub const PEER_OPEN: u8 = 6;
    pub const PEER_CLOSE: u8 = 7;
    pub const HOST_DATA: u8 = 8;
    pub const CLIENT_DATA: u8 = 9;
}

/// The only WebSocket closes the relay starts (see the module docs,
/// "Closing"). It also answers a peer that closes first; every other end
/// of a link is a dropped TCP connection.
pub mod close {
    /// Right after REFUSED (policy violation); reason text `"refused"`.
    pub const REFUSED: u16 = 1008;
    pub const REFUSED_REASON: &str = "refused";
    /// To a client its host closed with PEER_CLOSE (normal closure); reason
    /// text `"closed by the host"`. Do not reconnect at once.
    pub const CLOSED_BY_HOST: u16 = 1000;
    pub const CLOSED_BY_HOST_REASON: &str = "closed by the host";
    /// To a host: a newer host joined the room; reason text `"replaced"`.
    /// Back off before reconnecting instead of taking the room back at once.
    pub const REPLACED: u16 = 4001;
    pub const REPLACED_REASON: &str = "replaced";
}

/// Why the relay refused a connection (the byte carried by REFUSED).
pub mod refused {
    pub const NOT_ALLOWED: u8 = 1;
    pub const BAD_SIGNATURE: u8 = 2;
    pub const VERSION_MISMATCH: u8 = 3;
    pub const ROOM_FULL: u8 = 4;
    pub const RELAY_FULL: u8 = 5;
    pub const TIMEOUT: u8 = 6;
    pub const PROTOCOL: u8 = 7;

    pub fn describe(reason: u8) -> &'static str {
        match reason {
            NOT_ALLOWED => "this host is not on the relay's allow list",
            BAD_SIGNATURE => "the relay could not verify the pairing key",
            VERSION_MISMATCH => "relay protocol version mismatch - update the relay or this program",
            ROOM_FULL => "too many clients are already connected to this host through the relay",
            RELAY_FULL => "the relay is serving too many hosts",
            TIMEOUT => "timed out while authenticating with the relay",
            PROTOCOL => "unexpected message during authentication",
            _ => "unknown reason",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    Host,
    Client,
}

impl Role {
    pub fn to_u8(self) -> u8 {
        match self {
            Role::Host => 1,
            Role::Client => 2,
        }
    }
    pub fn from_u8(v: u8) -> Option<Role> {
        match v {
            1 => Some(Role::Host),
            2 => Some(Role::Client),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Role::Host => "host",
            Role::Client => "client",
        }
    }
}

/// Public identity of a room: an Ed25519 public key. `Debug` prints only the
/// masked form so a full id never lands in a log by accident.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoomId([u8; ROOM_ID_LEN]);

impl std::fmt::Debug for RoomId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RoomId({})", self.masked())
    }
}

impl RoomId {
    pub fn from_bytes(b: [u8; ROOM_ID_LEN]) -> RoomId {
        RoomId(b)
    }

    pub fn bytes(&self) -> &[u8; ROOM_ID_LEN] {
        &self.0
    }

    /// Lowercase hex, 64 characters: the form used in the relay's allow list.
    pub fn hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(2 * ROOM_ID_LEN);
        for b in self.0 {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 15) as usize] as char);
        }
        s
    }

    /// Parse 64 hex digits (either case, surrounding whitespace ignored).
    pub fn from_hex(s: &str) -> Option<RoomId> {
        let s = s.trim().as_bytes();
        if s.len() != 2 * ROOM_ID_LEN {
            return None;
        }
        let digit = |c: u8| -> Option<u8> {
            match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                b'A'..=b'F' => Some(c - b'A' + 10),
                _ => None,
            }
        };
        let mut out = [0u8; ROOM_ID_LEN];
        for (i, pair) in s.chunks_exact(2).enumerate() {
            out[i] = (digit(pair[0])? << 4) | digit(pair[1])?;
        }
        Some(RoomId(out))
    }

    /// First 8 hex digits and an ellipsis, for logs.
    pub fn masked(&self) -> String {
        let mut s = self.hex();
        s.truncate(8);
        s.push('…');
        s
    }
}

/// Secret signing key of a room, derived from the pairing key. Held by host
/// and client, never by the relay.
pub struct RoomKey(SigningKey);

impl std::fmt::Debug for RoomKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RoomKey(..)")
    }
}

impl RoomKey {
    /// One-way derivation: Ed25519 key seeded with
    /// BLAKE2s("hyperspace relay room v1" || pairing key).
    pub fn derive(key: &Key) -> RoomKey {
        RoomKey(SigningKey::from_bytes(&derive(key, ROOM_LABEL)))
    }

    pub fn id(&self) -> RoomId {
        RoomId(self.0.verifying_key().to_bytes())
    }

    /// The HELLO answering a CHALLENGE that carried `nonce`.
    pub fn hello(&self, role: Role, nonce: &[u8; NONCE_LEN]) -> Hello {
        Hello {
            version: VERSION,
            role,
            room: self.id(),
            signature: self.0.sign(&auth_message(role, nonce)).to_bytes(),
        }
    }
}

fn auth_message(role: Role, nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut m = Vec::with_capacity(AUTH_LABEL.len() + 1 + NONCE_LEN);
    m.extend_from_slice(AUTH_LABEL);
    m.push(role.to_u8());
    m.extend_from_slice(nonce);
    m
}

/// A fresh random challenge nonce.
pub fn new_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    getrandom::fill(&mut n).expect("system randomness");
    n
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hello {
    pub version: u8,
    pub role: Role,
    pub room: RoomId,
    pub signature: [u8; SIGNATURE_LEN],
}

impl Hello {
    /// True if the signature was made with the key of `self.room` over this
    /// role and `nonce`. Never panics, whatever the bytes.
    pub fn verify(&self, nonce: &[u8; NONCE_LEN]) -> bool {
        let Ok(public) = VerifyingKey::from_bytes(self.room.bytes()) else { return false };
        let signature = Signature::from_bytes(&self.signature);
        public.verify_strict(&auth_message(self.role, nonce), &signature).is_ok()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Msg<'a> {
    Challenge { version: u8, nonce: [u8; NONCE_LEN] },
    Hello(Hello),
    Ok,
    Refused(u8),
    Status { host_online: bool },
    PeerOpen(u32),
    PeerClose(u32),
    HostData { peer: u32, payload: &'a [u8] },
    ClientData(&'a [u8]),
}

fn exact(b: &[u8], n: usize) -> Option<&[u8]> {
    (b.len() == n).then_some(b)
}

fn le32(b: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?))
}

impl<'a> Msg<'a> {
    /// Parse one message. Returns None for anything malformed: unknown type,
    /// wrong length, invalid field, or a payload over [`MAX_PAYLOAD`].
    /// HELLO and CHALLENGE decode whatever their version byte, so the caller
    /// can tell a version mismatch from garbage.
    pub fn decode(b: &'a [u8]) -> Option<Msg<'a>> {
        let (&ty, r) = b.split_first()?;
        Some(match ty {
            mt::CHALLENGE => {
                let r = exact(r, 1 + NONCE_LEN)?;
                Msg::Challenge { version: r[0], nonce: r[1..].try_into().ok()? }
            }
            mt::HELLO => {
                let r = exact(r, 2 + ROOM_ID_LEN + SIGNATURE_LEN)?;
                Msg::Hello(Hello {
                    version: r[0],
                    role: Role::from_u8(r[1])?,
                    room: RoomId(r[2..2 + ROOM_ID_LEN].try_into().ok()?),
                    signature: r[2 + ROOM_ID_LEN..].try_into().ok()?,
                })
            }
            mt::OK => {
                exact(r, 0)?;
                Msg::Ok
            }
            mt::REFUSED => Msg::Refused(exact(r, 1)?[0]),
            mt::STATUS => Msg::Status {
                host_online: match exact(r, 1)?[0] {
                    0 => false,
                    1 => true,
                    _ => return None,
                },
            },
            mt::PEER_OPEN => Msg::PeerOpen(le32(exact(r, 4)?)?),
            mt::PEER_CLOSE => Msg::PeerClose(le32(exact(r, 4)?)?),
            mt::HOST_DATA => {
                let peer = le32(r)?;
                let payload = &r[4..];
                if payload.len() > MAX_PAYLOAD {
                    return None;
                }
                Msg::HostData { peer, payload }
            }
            mt::CLIENT_DATA => {
                if r.len() > MAX_PAYLOAD {
                    return None;
                }
                Msg::ClientData(r)
            }
            _ => return None,
        })
    }

    /// Append the encoded message to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match *self {
            Msg::Challenge { version, nonce } => {
                out.push(mt::CHALLENGE);
                out.push(version);
                out.extend_from_slice(&nonce);
            }
            Msg::Hello(h) => {
                out.push(mt::HELLO);
                out.push(h.version);
                out.push(h.role.to_u8());
                out.extend_from_slice(h.room.bytes());
                out.extend_from_slice(&h.signature);
            }
            Msg::Ok => out.push(mt::OK),
            Msg::Refused(reason) => {
                out.push(mt::REFUSED);
                out.push(reason);
            }
            Msg::Status { host_online } => {
                out.push(mt::STATUS);
                out.push(host_online as u8);
            }
            Msg::PeerOpen(peer) => {
                out.push(mt::PEER_OPEN);
                out.extend_from_slice(&peer.to_le_bytes());
            }
            Msg::PeerClose(peer) => {
                out.push(mt::PEER_CLOSE);
                out.extend_from_slice(&peer.to_le_bytes());
            }
            Msg::HostData { peer, payload } => {
                out.push(mt::HOST_DATA);
                out.extend_from_slice(&peer.to_le_bytes());
                out.extend_from_slice(payload);
            }
            Msg::ClientData(payload) => {
                out.push(mt::CLIENT_DATA);
                out.extend_from_slice(payload);
            }
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(match self {
            Msg::HostData { payload, .. } => 5 + payload.len(),
            Msg::ClientData(payload) => 1 + payload.len(),
            _ => 2 + ROOM_ID_LEN + SIGNATURE_LEN + 1,
        });
        self.encode_into(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> Vec<Msg<'static>> {
        let key = RoomKey::derive(&Key::from_bytes([7; 32]));
        vec![
            Msg::Challenge { version: VERSION, nonce: [9; NONCE_LEN] },
            Msg::Hello(key.hello(Role::Host, &[1; NONCE_LEN])),
            Msg::Hello(key.hello(Role::Client, &[2; NONCE_LEN])),
            Msg::Ok,
            Msg::Refused(refused::NOT_ALLOWED),
            Msg::Status { host_online: true },
            Msg::Status { host_online: false },
            Msg::PeerOpen(1),
            Msg::PeerClose(0xdead_beef),
            Msg::HostData { peer: 42, payload: b"sealed datagram" },
            Msg::HostData { peer: 3, payload: b"" },
            Msg::ClientData(b"another sealed datagram"),
            Msg::ClientData(&[0x55; MAX_PAYLOAD]),
        ]
    }

    #[test]
    fn every_message_round_trips() {
        for m in samples() {
            let bytes = m.encode();
            assert_eq!(Msg::decode(&bytes), Some(m), "{m:?}");
            let mut appended = vec![0xaa];
            m.encode_into(&mut appended);
            assert_eq!(&appended[1..], &bytes[..]);
        }
        // the documented layouts
        assert_eq!(Msg::Ok.encode(), [3]);
        assert_eq!(Msg::Refused(6).encode(), [4, 6]);
        assert_eq!(Msg::Status { host_online: true }.encode(), [5, 1]);
        assert_eq!(Msg::PeerOpen(0x0403_0201).encode(), [6, 1, 2, 3, 4]);
        assert_eq!(Msg::PeerClose(1).encode(), [7, 1, 0, 0, 0]);
        assert_eq!(Msg::HostData { peer: 2, payload: b"xy" }.encode(), [8, 2, 0, 0, 0, b'x', b'y']);
        assert_eq!(Msg::ClientData(b"z").encode(), [9, b'z']);
        assert_eq!(Msg::Challenge { version: 1, nonce: [0; NONCE_LEN] }.encode().len(), 34);
        let h = RoomKey::derive(&Key::generate()).hello(Role::Client, &[0; NONCE_LEN]);
        let hb = Msg::Hello(h).encode();
        assert_eq!(hb.len(), 99);
        assert_eq!(&hb[..3], &[2, VERSION, 2]);
    }

    #[test]
    fn malformed_input_is_rejected() {
        assert_eq!(Msg::decode(&[]), None);
        for ty in [0u8, 10, 0x80, 0x82, 255] {
            assert_eq!(Msg::decode(&[ty, 0, 0, 0, 0, 0]), None, "type {ty}");
        }
        for m in samples() {
            let bytes = m.encode();
            let fixed = !matches!(m, Msg::HostData { .. } | Msg::ClientData(_));
            // truncated: fixed-size messages need every byte, data needs its header
            let min = if fixed { bytes.len() } else { bytes.len() - data_len(&m) };
            for n in 0..min {
                assert_eq!(Msg::decode(&bytes[..n]), None, "{m:?} cut to {n}");
            }
            // trailing garbage after a fixed-size message
            if fixed {
                let mut longer = bytes.clone();
                longer.push(0);
                assert_eq!(Msg::decode(&longer), None, "{m:?} + 1 byte");
            }
        }
        // invalid fields
        assert_eq!(Msg::decode(&[mt::STATUS, 2]), None);
        let mut hello = Msg::Hello(RoomKey::derive(&Key::generate()).hello(Role::Host, &[0; 32])).encode();
        hello[2] = 3;
        assert_eq!(Msg::decode(&hello), None);
        // oversize datagrams
        let big = [0u8; MAX_PAYLOAD + 1];
        assert_eq!(Msg::decode(&Msg::ClientData(&big).encode()), None);
        assert_eq!(Msg::decode(&Msg::HostData { peer: 1, payload: &big }.encode()), None);
        assert!(Msg::HostData { peer: 1, payload: &big[1..] }.encode().len() == MAX_MESSAGE);
        // a HELLO from another version still decodes, so it can be answered
        let mut other = Msg::Hello(RoomKey::derive(&Key::generate()).hello(Role::Host, &[0; 32])).encode();
        other[1] = VERSION + 1;
        assert!(matches!(Msg::decode(&other), Some(Msg::Hello(h)) if h.version == VERSION + 1));
    }

    fn data_len(m: &Msg) -> usize {
        match m {
            Msg::HostData { payload, .. } | Msg::ClientData(payload) => payload.len(),
            _ => 0,
        }
    }

    #[test]
    fn decode_never_panics_on_garbage() {
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut buf = Vec::new();
        for _ in 0..20_000 {
            let len = (next() % 140) as usize;
            buf.clear();
            buf.extend((0..len).map(|_| next() as u8));
            if let Some(first) = buf.first_mut() {
                *first %= 12; // mostly valid types
            }
            if let Some(m) = Msg::decode(&buf) {
                assert_eq!(m.encode(), buf);
            }
        }
    }

    #[test]
    fn signature_proves_the_key_for_this_role_and_nonce() {
        let key = Key::generate();
        let room = RoomKey::derive(&key);
        let nonce = new_nonce();
        let hello = room.hello(Role::Host, &nonce);
        assert_eq!(hello.room, room.id());
        assert_eq!(hello.version, VERSION);
        assert!(hello.verify(&nonce));
        assert!(room.hello(Role::Client, &nonce).verify(&nonce));

        // replayed on a connection with another nonce
        let mut other_nonce = nonce;
        other_nonce[0] ^= 1;
        assert!(!hello.verify(&other_nonce));

        // presented for the other role
        assert!(!Hello { role: Role::Client, ..hello }.verify(&nonce));

        // signed with a different pairing key but claiming this room
        let stranger = RoomKey::derive(&Key::generate()).hello(Role::Host, &nonce);
        assert!(!Hello { room: room.id(), ..stranger }.verify(&nonce));
        assert!(!Hello { signature: stranger.signature, ..hello }.verify(&nonce));

        // tampered signature, garbage room id
        let mut sig = hello.signature;
        sig[10] ^= 0x40;
        assert!(!Hello { signature: sig, ..hello }.verify(&nonce));
        assert!(!Hello { room: RoomId::from_bytes([0xff; 32]), ..hello }.verify(&nonce));
        assert!(!Hello { signature: [0; 64], ..hello }.verify(&nonce));
    }

    #[test]
    fn room_id_is_per_key_and_stable() {
        let (a, b) = (Key::generate(), Key::generate());
        assert_eq!(RoomKey::derive(&a).id(), RoomKey::derive(&a).id());
        assert_ne!(RoomKey::derive(&a).id(), RoomKey::derive(&b).id());
    }

    /// Known answers, computed outside this code (BLAKE2s-256 of the label and
    /// key as the Ed25519 seed, RFC 8032 public key). Changing the derivation
    /// would strand every allow list, so these must never change.
    #[test]
    fn room_id_known_answers() {
        assert_eq!(
            RoomKey::derive(&Key::from_bytes([0; 32])).id().hex(),
            "f7558a583c0dee0f56cf8bcfef1dc698f4790c3c06f4027fdb9610dda58b5827"
        );
        let mut counting = [0u8; 32];
        for (i, b) in counting.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(
            RoomKey::derive(&Key::from_bytes(counting)).id().hex(),
            "33eb4770427788769c5b3ada16afda4bf2d5be265a266a0bd920ac20495ad4c9"
        );
    }

    #[test]
    fn room_id_is_not_the_dht_key_nor_the_pairing_key() {
        let key = Key::generate();
        let room = RoomKey::derive(&key).id();
        let dht = crate::rendezvous::signing_key(&key).verifying_key().to_bytes();
        assert_ne!(room.bytes(), &dht);
        assert_ne!(room.bytes(), key.bytes());
        assert_ne!(&RoomKey::derive(&key).0.to_bytes(), key.bytes());
        assert_ne!(RoomKey::derive(&key).0.to_bytes(), crate::rendezvous::signing_key(&key).to_bytes());
    }

    #[test]
    fn hex_forms() {
        let id = RoomKey::derive(&Key::generate()).id();
        let hex = id.hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(RoomId::from_hex(&hex), Some(id));
        assert_eq!(RoomId::from_hex(&format!("  {}\n", hex.to_uppercase())), Some(id));
        assert_eq!(RoomId::from_hex(&hex[1..]), None);
        assert_eq!(RoomId::from_hex(&format!("{}g", &hex[1..])), None);
        assert_eq!(RoomId::from_hex("é"), None);
        let masked = id.masked();
        assert_eq!(masked, format!("{}…", &hex[..8]));
        assert!(!format!("{id:?}").contains(&hex[8..]));
        assert_eq!(RoomId::from_bytes(*id.bytes()), id);
    }
}
