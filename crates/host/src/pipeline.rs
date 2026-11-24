//! Interface between the session server and a video source.

use hyperspace_proto::cursor::CursorShape;
use hyperspace_proto::Codec;
use std::path::PathBuf;
use hyperspace_proto::secure::Key;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncoderPref {
    Auto,
    Hardware,
    Software,
}

#[derive(Clone, Debug)]
pub enum SourceKind {
    Desktop,
    /// Replay an Annex B elementary stream (testing / benchmarking the transport).
    File(PathBuf),
}

#[derive(Clone, Debug)]
pub struct Config {
    /// `None`: all interfaces, IPv4 and IPv6.
    pub bind: Option<std::net::SocketAddr>,
    pub port: u16,
    pub key: Key,
    pub source: SourceKind,
    pub display: usize,
    pub codec: Option<Codec>,
    pub encoder: EncoderPref,
    /// 0 = derive from resolution.
    pub bitrate_kbps: u32,
    /// Upper bound on the frame rate regardless of what the client asks for (0 = none).
    pub max_fps: u32,
    pub packet_size: usize,
    pub dump: Option<PathBuf>,
    pub once: bool,
    pub view_only: bool,
    pub file_size: (u32, u32),
}

/// What the client asked for.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(windows), allow(dead_code))]
pub struct StreamRequest {
    pub codecs: u8,
    pub fps: u32,
    pub bitrate_kbps: u32,
    /// The client is reaching us across the internet.
    pub wan: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct StreamInfo {
    pub codec: Codec,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_kbps: u32,
    /// Highest bitrate the client may ask for during the session.
    pub max_bitrate_kbps: u32,
    /// Captured display rectangle in virtual-desktop pixels (left, top, width, height).
    pub desktop_rect: Option<(i32, i32, i32, i32)>,
}

/// Receives the pipeline's output. Called from pipeline threads.
pub trait Sink: Send + Sync {
    /// The pipeline is ready. Called before the first frame, and again if the
    /// stream geometry changes mid-session (display mode switch).
    fn started(&self, info: &StreamInfo);
    /// One encoded access unit (Annex B). `ts_us` is `clock::now_us()` at capture.
    fn frame(&self, data: &[u8], keyframe: bool, ts_us: u64);
    /// Cursor changed. `shape` is `Some` when the image changed.
    #[cfg_attr(not(windows), allow(dead_code))]
    fn cursor(&self, shape: Option<&CursorShape>, visible: bool);
}

/// Server -> pipeline signalling.
#[derive(Default)]
pub struct Control {
    pub stop: AtomicBool,
    pub keyframe: AtomicBool,
    /// Non-zero: the client asked for this bitrate (kbit/s). Taken with `swap(0)`.
    pub bitrate_kbps: AtomicU32,
}

/// Default bitrate for a resolution / frame rate: generous, since this is
/// meant for LANs, but sub-linear in fps because inter-frame deltas shrink.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn default_bitrate_kbps(width: u32, height: u32, fps: u32) -> u32 {
    let px = width as f64 * height as f64;
    let kbps = px * 8.5 * (fps.max(1) as f64 / 60.0).sqrt() / 1000.0;
    (kbps as u32).clamp(5_000, 150_000)
}

/// Bitrate to start a WAN session at when nobody chose one; the client's
/// controller raises it while the path keeps up.
pub const WAN_START_KBPS: u32 = 10_000;

/// (starting bitrate, ceiling) for a session.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn choose_bitrate(cfg: &Config, req: &StreamRequest, width: u32, height: u32, fps: u32) -> (u32, u32) {
    if cfg.bitrate_kbps != 0 {
        return (cfg.bitrate_kbps, cfg.bitrate_kbps);
    }
    if req.bitrate_kbps != 0 {
        return (req.bitrate_kbps, req.bitrate_kbps);
    }
    let max = default_bitrate_kbps(width, height, fps);
    (if req.wan { max.min(WAN_START_KBPS) } else { max }, max)
}

/// Run the configured source until `ctl.stop` is set or it fails.
pub fn run(cfg: &Config, req: StreamRequest, ctl: Arc<Control>, sink: Arc<dyn Sink>) -> Result<(), String> {
    match &cfg.source {
        SourceKind::File(path) => crate::file_source::run(cfg, path, req, &ctl, &*sink),
        SourceKind::Desktop => {
            #[cfg(windows)]
            {
                crate::win::run(cfg, req, ctl, sink)
            }
            #[cfg(not(windows))]
            {
                let _ = (req, ctl, sink);
                Err("desktop capture is only implemented for Windows; use --file <stream.h264> on this platform".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitrate_defaults_are_sane() {
        assert_eq!(default_bitrate_kbps(1920, 1080, 60), 17_625);
        assert_eq!(default_bitrate_kbps(2560, 1440, 60), 31_334);
        assert!(default_bitrate_kbps(2560, 1440, 120) > 40_000);
        assert_eq!(default_bitrate_kbps(640, 480, 30), 5_000);
        assert_eq!(default_bitrate_kbps(7680, 4320, 240), 150_000);
    }

    #[test]
    fn bitrate_choice() {
        let mut cfg = Config {
            bind: None,
            port: 1,
            key: Key::generate(),
            source: SourceKind::Desktop,
            display: 0,
            codec: None,
            encoder: EncoderPref::Auto,
            bitrate_kbps: 0,
            max_fps: 0,
            packet_size: 1400,
            dump: None,
            once: false,
            view_only: false,
            file_size: (1280, 720),
        };
        let mut req = StreamRequest { codecs: 3, fps: 60, bitrate_kbps: 0, wan: false };
        assert_eq!(choose_bitrate(&cfg, &req, 2560, 1440, 60), (31_334, 31_334));
        req.wan = true;
        assert_eq!(choose_bitrate(&cfg, &req, 2560, 1440, 60), (10_000, 31_334));
        assert_eq!(choose_bitrate(&cfg, &req, 640, 480, 30), (5_000, 5_000));
        req.bitrate_kbps = 20_000;
        assert_eq!(choose_bitrate(&cfg, &req, 2560, 1440, 60), (20_000, 20_000));
        cfg.bitrate_kbps = 8_000;
        assert_eq!(choose_bitrate(&cfg, &req, 2560, 1440, 60), (8_000, 8_000));
    }
}
