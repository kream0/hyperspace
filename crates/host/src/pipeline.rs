//! Interface between the session server and a video source.

use hyperspace_proto::cursor::CursorShape;
use hyperspace_proto::Codec;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
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
    pub bind: std::net::SocketAddr,
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
}

#[derive(Clone, Copy, Debug)]
pub struct StreamInfo {
    pub codec: Codec,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_kbps: u32,
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
}

/// Default bitrate for a resolution / frame rate: generous, since this is
/// meant for LANs, but sub-linear in fps because inter-frame deltas shrink.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn default_bitrate_kbps(width: u32, height: u32, fps: u32) -> u32 {
    let px = width as f64 * height as f64;
    let kbps = px * 8.5 * (fps.max(1) as f64 / 60.0).sqrt() / 1000.0;
    (kbps as u32).clamp(5_000, 150_000)
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
}
