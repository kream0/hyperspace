//! Windows pipeline: Desktop Duplication -> (GPU colour convert) -> Media
//! Foundation encoder -> sink.

mod capture;
mod convert;
mod encoder;
pub mod input;

use crate::pipeline::{default_bitrate_kbps, Config, Control, EncoderPref, Sink, StreamInfo, StreamRequest};
use capture::{Acquired, Capture};
use convert::GpuConverter;
use encoder::{Encoder, EncoderParams};
use hyperspace_proto::clock::now_us;
use hyperspace_proto::{log, Codec};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::*;
use windows::Win32::Media::MediaFoundation::{MFShutdown, MFStartup, MFSTARTUP_FULL, MF_VERSION};
use windows::Win32::Media::timeBeginPeriod;
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};
use windows::Win32::System::Power::{SetThreadExecutionState, ES_CONTINUOUS, ES_DISPLAY_REQUIRED, ES_SYSTEM_REQUIRED};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, SetPriorityClass, SetThreadPriority, HIGH_PRIORITY_CLASS, THREAD_PRIORITY_HIGHEST,
};
use windows::Win32::UI::HiDpi::{SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2};

pub(crate) fn hr_str(e: &windows::core::Error) -> String {
    let msg = e.message();
    if msg.is_empty() {
        format!("0x{:08X}", e.code().0 as u32)
    } else {
        format!("{} (0x{:08X})", msg.trim(), e.code().0 as u32)
    }
}

pub(crate) fn wide_to_string(w: &[u16]) -> String {
    let len = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..len])
}

/// One-time process configuration.
pub fn process_setup() {
    unsafe {
        // Physical pixels everywhere: capture size and input coordinates must agree.
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        // Stay responsive when a game is eating the CPU.
        let _ = SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
        // 1 ms scheduler granularity for accurate short waits.
        timeBeginPeriod(1);
    }
}

/// COM (multithreaded apartment) + Media Foundation for the current thread.
struct MediaRuntime {
    mf: bool,
}

impl MediaRuntime {
    fn new(mf: bool) -> Result<MediaRuntime, String> {
        unsafe {
            let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
            if hr.is_err() {
                return Err(format!("CoInitializeEx: 0x{:08X}", hr.0 as u32));
            }
            if mf {
                MFStartup(MF_VERSION, MFSTARTUP_FULL).map_err(|e| {
                    CoUninitialize();
                    format!("MFStartup: {} (is the Media Feature Pack installed?)", hr_str(&e))
                })?;
            }
        }
        Ok(MediaRuntime { mf })
    }
}

impl Drop for MediaRuntime {
    fn drop(&mut self) {
        unsafe {
            if self.mf {
                let _ = MFShutdown();
            }
            CoUninitialize();
        }
    }
}

pub fn list() -> Result<(), String> {
    process_setup();
    let _rt = MediaRuntime::new(true)?;
    println!("Displays:");
    for o in capture::enumerate_outputs()? {
        println!(
            "  {}: {} {}x{} @ {} Hz at ({}, {}){} on {}",
            o.index,
            o.name,
            o.rect.2,
            o.rect.3,
            o.refresh_hz,
            o.rect.0,
            o.rect.1,
            if o.primary { " [primary]" } else { "" },
            o.adapter_name
        );
    }
    println!("Encoders:");
    let encs = encoder::describe_encoders();
    if encs.is_empty() {
        println!("  none found");
    }
    for e in encs {
        println!("  {e}");
    }
    Ok(())
}

enum Outcome {
    Stopped,
    /// Display mode changed: rebuild the pipeline at the new size.
    ModeChanged,
    /// The hardware encoder path failed; retry in software.
    HardwareFailed(String),
}

/// Software path: read the frame back and convert on the CPU.
struct CpuPath {
    staging: ID3D11Texture2D,
    nv12: Vec<u8>,
    valid: bool,
}

impl CpuPath {
    fn new(cap: &Capture) -> Result<CpuPath, String> {
        let desc = D3D11_TEXTURE2D_DESC {
            Width: cap.width,
            Height: cap.height,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM,
            SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            MiscFlags: 0,
        };
        let mut tex = None;
        unsafe { cap.device.CreateTexture2D(&desc, None, Some(&mut tex)) }.map_err(|e| format!("staging texture: {}", hr_str(&e)))?;
        Ok(CpuPath { staging: tex.ok_or("no staging texture")?, nv12: Vec::new(), valid: false })
    }

    fn update(&mut self, cap: &Capture, target: &ID3D11Texture2D, w: u32, h: u32) -> Result<(), String> {
        unsafe {
            cap.context.CopyResource(&self.staging, target);
            let mut map = D3D11_MAPPED_SUBRESOURCE::default();
            cap.context.Map(&self.staging, 0, D3D11_MAP_READ, 0, Some(&mut map)).map_err(|e| format!("Map: {}", hr_str(&e)))?;
            let pitch = map.RowPitch as usize;
            let src = std::slice::from_raw_parts(map.pData as *const u8, pitch * (cap.height as usize - 1) + cap.width as usize * 4);
            crate::yuv::bgra_to_nv12(src, pitch, w as usize, h as usize, &mut self.nv12);
            cap.context.Unmap(&self.staging, 0);
        }
        self.valid = true;
        Ok(())
    }
}

fn round_refresh(hz: u32) -> u32 {
    // 59.94 Hz and friends are reported truncated.
    if hz % 10 == 9 || hz % 24 == 23 {
        hz + 1
    } else {
        hz
    }
}

pub fn run(cfg: &Config, req: StreamRequest, ctl: Arc<Control>, sink: Arc<dyn Sink>) -> Result<(), String> {
    let _rt = MediaRuntime::new(true)?;
    unsafe {
        // Keep the display on while someone is watching it remotely.
        SetThreadExecutionState(ES_CONTINUOUS | ES_DISPLAY_REQUIRED | ES_SYSTEM_REQUIRED);
        let _ = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    }
    let result = (|| {
        let mut cap = Capture::new(cfg.display)?;
        log!(
            "capturing {} ({}x{} @ {} Hz) on {}{}",
            cap.output_name,
            cap.width,
            cap.height,
            cap.refresh_hz,
            cap.adapter_name,
            if cap.software_adapter { " [software adapter]" } else { "" }
        );
        let mut force_software = cfg.encoder == EncoderPref::Software;
        loop {
            match run_mode(cfg, req, &ctl, &sink, &mut cap, force_software)? {
                Outcome::Stopped => return Ok(()),
                Outcome::ModeChanged => log!("display mode changed to {}x{}: restarting encoder", cap.width, cap.height),
                Outcome::HardwareFailed(e) => {
                    if cfg.encoder == EncoderPref::Hardware || force_software {
                        return Err(e);
                    }
                    log!("hardware encoding failed ({e}); falling back to the software encoder");
                    force_software = true;
                }
            }
        }
    })();
    unsafe {
        SetThreadExecutionState(ES_CONTINUOUS);
    }
    result
}

fn run_mode(
    cfg: &Config,
    req: StreamRequest,
    ctl: &Arc<Control>,
    sink: &Arc<dyn Sink>,
    cap: &mut Capture,
    force_software: bool,
) -> Result<Outcome, String> {
    let (cap_w, cap_h) = (cap.width, cap.height);
    let (w, h) = (cap_w & !1, cap_h & !1);
    if w < 64 || h < 64 {
        return Err(format!("display is too small to encode ({cap_w}x{cap_h})"));
    }
    let mut fps = if req.fps == 0 { 60 } else { req.fps };
    fps = fps.min(round_refresh(cap.refresh_hz).max(24));
    if cfg.max_fps != 0 {
        fps = fps.min(cfg.max_fps);
    }
    let fps = fps.max(1);
    let bitrate_kbps = if cfg.bitrate_kbps != 0 {
        cfg.bitrate_kbps
    } else if req.bitrate_kbps != 0 {
        req.bitrate_kbps
    } else {
        default_bitrate_kbps(w, h, fps)
    };
    let codecs: Vec<Codec> = match cfg.codec {
        Some(c) => vec![c],
        None => vec![Codec::Hevc, Codec::H264],
    }
    .into_iter()
    .filter(|c| req.codecs & c.mask() != 0)
    .collect();
    if codecs.is_empty() {
        return Err("the client cannot decode any codec this host is allowed to use".into());
    }

    let target = cap.create_target()?;
    let params = EncoderParams { width: w, height: h, fps, bitrate_kbps };
    let hw_possible = !cap.software_adapter && !force_software;
    let pref = if force_software || cap.software_adapter {
        if cfg.encoder == EncoderPref::Hardware {
            return Err("hardware encoding was requested but this display adapter has no GPU".into());
        }
        EncoderPref::Software
    } else {
        cfg.encoder
    };
    let enc = Arc::new(Encoder::open(hw_possible.then_some(&cap.device), pref, &codecs, &params)?);

    let mut gpu = None;
    let mut cpu = None;
    if enc.uses_d3d {
        // Four NV12 surfaces: one being written, up to two inside the encoder, one spare.
        match GpuConverter::new(&cap.device, &cap.context, &target, (cap_w, cap_h), (w, h), fps, 4) {
            Ok(g) => gpu = Some(g),
            Err(e) => return Ok(Outcome::HardwareFailed(format!("GPU colour conversion unavailable: {e}"))),
        }
    } else {
        cpu = Some(CpuPath::new(cap)?);
    }

    sink.started(&StreamInfo { codec: enc.codec, width: w, height: h, fps, bitrate_kbps, desktop_rect: Some(cap.rect) });

    let event_thread = enc.is_async.then(|| {
        let (enc, sink) = (enc.clone(), sink.clone());
        std::thread::Builder::new()
            .name("encoder-events".into())
            .spawn(move || {
                let _rt = MediaRuntime::new(false);
                unsafe {
                    let _ = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
                }
                enc.event_loop(&*sink);
            })
            .expect("spawn encoder event thread")
    });

    let outcome = frame_loop(cap, ctl, sink, &enc, &target, gpu.as_mut(), cpu.as_mut(), fps, (w, h));

    // Wind the encoder down; never let a misbehaving driver hang the session teardown.
    enc.begin_shutdown();
    if let Some(t) = event_thread {
        let wait = |ms: u64| {
            let end = Instant::now() + Duration::from_millis(ms);
            while !t.is_finished() && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(5));
            }
            t.is_finished()
        };
        if !wait(400) {
            enc.force_shutdown();
            if !wait(600) {
                log!("warning: encoder event thread did not exit; abandoning it");
            }
        }
        if t.is_finished() {
            let _ = t.join();
        }
    }

    match outcome {
        Err(e) if enc.hardware => Ok(Outcome::HardwareFailed(e)),
        other => other,
    }
}

#[allow(clippy::too_many_arguments)]
fn frame_loop(
    cap: &mut Capture,
    ctl: &Control,
    sink: &Arc<dyn Sink>,
    enc: &Encoder,
    target: &ID3D11Texture2D,
    mut gpu: Option<&mut GpuConverter>,
    mut cpu: Option<&mut CpuPath>,
    fps: u32,
    (w, h): (u32, u32),
) -> Result<Outcome, String> {
    let (cap_w, cap_h) = (cap.width, cap.height);
    let interval = Duration::from_secs_f64(1.0 / fps as f64);
    // Slightly under the nominal interval so a source running at exactly `fps`
    // is never held back by timer jitter.
    let min_gap = interval.mul_f64(0.9);
    let mut last_submit = Instant::now() - interval;
    let mut have_image = false;
    let mut pending_image = false;
    let mut pending_ts = 0u64;
    let mut converted = false;
    let mut force_key = true;
    let mut submitted = 0u64;
    let mut first_submit: Option<Instant> = None;
    let sink_ref: &dyn Sink = &**sink;

    loop {
        if ctl.stop.load(Ordering::Relaxed) {
            return Ok(Outcome::Stopped);
        }
        if let Some(e) = enc.failure() {
            return Err(e);
        }
        if let Some(t0) = first_submit {
            if submitted >= 3 && enc.frames_out.load(Ordering::Relaxed) == 0 && t0.elapsed() > Duration::from_secs(3) {
                return Err("encoder accepted frames but produced no output".into());
            }
        }

        // While a captured frame waits for its slot, only wait that long;
        // a newer frame arriving meanwhile simply replaces it.
        let since = last_submit.elapsed();
        let wait_ms = if pending_image || force_key { min_gap.saturating_sub(since).as_millis().min(4) as u32 } else { 4 };
        match cap.acquire(wait_ms, target, &mut |shape, visible| sink_ref.cursor(shape, visible))? {
            Acquired::Frame { image: true } => {
                pending_ts = now_us();
                pending_image = true;
                have_image = true;
                converted = false;
            }
            Acquired::Frame { image: false } | Acquired::Timeout => {}
            Acquired::Lost => {
                log!("desktop duplication lost; reacquiring");
                loop {
                    if ctl.stop.load(Ordering::Relaxed) {
                        return Ok(Outcome::Stopped);
                    }
                    match cap.reopen() {
                        Ok(()) => break,
                        Err(_) => std::thread::sleep(Duration::from_millis(100)),
                    }
                }
                if cap.width != cap_w || cap.height != cap_h {
                    return Ok(Outcome::ModeChanged);
                }
                force_key = true;
                continue;
            }
        }
        if ctl.keyframe.swap(false, Ordering::Relaxed) {
            force_key = true;
        }
        if !have_image || !(pending_image || force_key) || last_submit.elapsed() < min_gap {
            continue;
        }

        // A forced keyframe with no new image re-encodes the previous frame.
        let ts = if pending_image { pending_ts } else { now_us() };
        let accepted = if let Some(g) = gpu.as_deref_mut() {
            let tex = if !converted || g.last().is_none() {
                converted = true;
                g.convert()?
            } else {
                g.last().unwrap()
            };
            enc.submit_texture(tex, ts, force_key, interval, sink_ref)?
        } else {
            let c = cpu.as_deref_mut().expect("either gpu or cpu path exists");
            if !converted || !c.valid {
                c.update(cap, target, w, h)?;
                converted = true;
            }
            enc.submit_nv12(&c.nv12, ts, force_key, interval, sink_ref)?
        };
        if accepted {
            pending_image = false;
            force_key = false;
            last_submit = Instant::now();
            submitted += 1;
            first_submit.get_or_insert(last_submit);
        }
    }
}
