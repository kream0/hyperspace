//! Replays an Annex B elementary stream as if it were a live encoder. Lets the
//! transport and the client be exercised on any OS without a capture stack.

use crate::pipeline::{Config, Control, Sink, StreamInfo, StreamRequest};
use hyperspace_proto::{annexb, clock::now_us};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

pub fn run(cfg: &Config, path: &Path, req: StreamRequest, ctl: &Control, sink: &dyn Sink) -> Result<(), String> {
    let data = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let codec = annexb::sniff_codec(&data).ok_or("file is not an H.264/HEVC Annex B elementary stream")?;
    if let Some(forced) = cfg.codec {
        if forced != codec {
            return Err(format!("file is {} but --codec {} was requested", codec.name(), forced.name()));
        }
    }
    if req.codecs & codec.mask() == 0 {
        return Err(format!("client cannot decode {}", codec.name()));
    }
    let units = annexb::split_access_units(codec, &data);
    let keys: Vec<bool> = units.iter().map(|u| annexb::inspect(codec, u).keyframe).collect();
    if units.is_empty() || !keys[0] {
        return Err("stream must start with a keyframe".into());
    }

    let mut fps = if req.fps == 0 { 60 } else { req.fps };
    if cfg.max_fps != 0 {
        fps = fps.min(cfg.max_fps);
    }
    let info = StreamInfo {
        codec,
        width: cfg.file_size.0,
        height: cfg.file_size.1,
        fps,
        bitrate_kbps: 0,
        max_bitrate_kbps: 0,
        desktop_rect: None,
    };
    hyperspace_proto::log!(
        "file source: {} access units ({} keyframes), {} @ {} fps",
        units.len(),
        keys.iter().filter(|k| **k).count(),
        codec.name(),
        fps
    );
    sink.started(&info);

    let interval = Duration::from_secs_f64(1.0 / fps as f64);
    let mut next = Instant::now();
    let mut i = 0usize;
    while !ctl.stop.load(Ordering::Relaxed) {
        if ctl.keyframe.swap(false, Ordering::Relaxed) && !keys[i] {
            // Skip ahead to the next keyframe (wrapping), like a forced IDR.
            i = (i..units.len()).find(|&j| keys[j]).unwrap_or(0);
        }
        sink.frame(units[i], keys[i], now_us());
        i = (i + 1) % units.len();
        next += interval;
        let now = Instant::now();
        if next > now {
            std::thread::sleep(next - now);
        } else {
            next = now;
        }
    }
    Ok(())
}
