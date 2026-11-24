//! hyperspace wire protocol.
//!
//! Everything rides on a single UDP flow. Video frames are fragmented into
//! fixed-size chunks; loss is repaired with immediate NACK retransmits and, as
//! a last resort, a fresh keyframe. Input is sent redundantly until acked so a
//! lost datagram never costs a retransmit timeout.

pub mod annexb;
pub mod clock;
pub mod cursor;
pub mod frag;
pub mod input;
pub mod wire;

pub use wire::{Codec, FragHeader, Hello, Packet, Welcome};

/// Default UDP port the host listens on.
pub const DEFAULT_PORT: u16 = 45800;

/// Timestamped stderr logging shared by both binaries.
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {{
        let t = $crate::clock::now_us();
        eprintln!("[{:>4}.{:03}] {}", t / 1_000_000, (t / 1000) % 1000, format_args!($($arg)*));
    }};
}
