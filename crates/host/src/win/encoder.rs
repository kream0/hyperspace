//! H.264 / HEVC encoding through Media Foundation transforms.
//!
//! Hardware MFTs are the GPU vendor's encoder (NVENC, AMF, Quick Sync) behind
//! one API: they take D3D11 textures directly, so a frame never leaves the GPU
//! until it is a compressed bitstream. They are asynchronous: the transform
//! raises NeedInput / HaveOutput events which a dedicated thread services, so
//! encoded frames go to the network the instant they exist. The software MFT
//! is the fallback for machines without a usable hardware encoder.

use super::hr_str;
use crate::pipeline::{EncoderPref, Sink};
use hyperspace_proto::{annexb, log, Codec};
use std::collections::VecDeque;
use std::mem::ManuallyDrop;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;
use windows::core::{Interface, GUID, PWSTR};
use windows::Win32::Graphics::Direct3D11::{ID3D11Device, ID3D11Texture2D};
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Variant::VARIANT;

#[derive(Clone, Copy, Debug)]
pub struct EncoderParams {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_kbps: u32,
}

pub struct Encoder {
    mft: IMFTransform,
    codec_api: Option<ICodecAPI>,
    _manager: Option<IMFDXGIDeviceManager>,
    pub name: String,
    pub codec: Codec,
    pub hardware: bool,
    pub is_async: bool,
    /// Accepts D3D11 textures (otherwise NV12 in system memory).
    pub uses_d3d: bool,
    in_id: u32,
    out_id: u32,
    /// (MFT allocates output samples, output buffer size); queried once streaming has begun.
    out_info: Mutex<Option<(bool, u32)>>,
    /// Set if the transform rejected an on-demand keyframe request.
    pub keyframe_unsupported: AtomicBool,
    params: EncoderParams,
    seq_header: Mutex<Vec<u8>>,
    credits: Mutex<u32>,
    credit_cv: Condvar,
    pending_ts: Mutex<VecDeque<u64>>,
    pub in_flight: AtomicU32,
    draining: AtomicBool,
    error: Mutex<Option<String>>,
    scratch: Mutex<Vec<u8>>,
    pub frames_out: AtomicU32,
}

// Media Foundation transforms are free-threaded; we serialise our own state.
unsafe impl Send for Encoder {}
unsafe impl Sync for Encoder {}

fn subtype(codec: Codec) -> GUID {
    match codec {
        Codec::H264 => MFVideoFormat_H264,
        Codec::Hevc => MFVideoFormat_HEVC,
    }
}

struct Candidate {
    activate: IMFActivate,
    name: String,
    codec: Codec,
    hardware: bool,
}

fn enumerate(codec: Codec, hardware: bool) -> Vec<Candidate> {
    let out_type = MFT_REGISTER_TYPE_INFO { guidMajorType: MFMediaType_Video, guidSubtype: subtype(codec) };
    let flags = if hardware {
        MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER
    } else {
        MFT_ENUM_FLAG_SYNCMFT | MFT_ENUM_FLAG_SORTANDFILTER
    };
    let mut list: *mut Option<IMFActivate> = std::ptr::null_mut();
    let mut count = 0u32;
    let mut out = Vec::new();
    unsafe {
        if MFTEnumEx(MFT_CATEGORY_VIDEO_ENCODER, flags, None, Some(&out_type), &mut list, &mut count).is_err() || list.is_null() {
            return out;
        }
        for i in 0..count as usize {
            let Some(activate) = (*list.add(i)).take() else { continue };
            let mut name = PWSTR::null();
            let mut len = 0u32;
            let friendly = if activate.GetAllocatedString(&MFT_FRIENDLY_NAME_Attribute, &mut name, &mut len).is_ok() && !name.is_null() {
                let s = name.to_string().unwrap_or_default();
                CoTaskMemFree(Some(name.0 as *const _));
                s
            } else {
                "unnamed encoder".to_string()
            };
            out.push(Candidate { activate, name: friendly, codec, hardware });
        }
        CoTaskMemFree(Some(list as *const _));
    }
    out
}

/// Human-readable list of available encoders (for `--list`).
pub fn describe_encoders() -> Vec<String> {
    let mut v = Vec::new();
    for codec in [Codec::Hevc, Codec::H264] {
        for hw in [true, false] {
            for c in enumerate(codec, hw) {
                v.push(format!("{:5} {:8} {}", codec.name(), if hw { "hardware" } else { "software" }, c.name));
            }
        }
    }
    v
}

fn pack(hi: u32, lo: u32) -> u64 {
    ((hi as u64) << 32) | lo as u64
}

fn media_type(sub: GUID, p: &EncoderParams, output: bool, codec: Codec, color: bool) -> windows::core::Result<IMFMediaType> {
    unsafe {
        let t = MFCreateMediaType()?;
        t.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
        t.SetGUID(&MF_MT_SUBTYPE, &sub)?;
        t.SetUINT64(&MF_MT_FRAME_SIZE, pack(p.width, p.height))?;
        t.SetUINT64(&MF_MT_FRAME_RATE, pack(p.fps, 1))?;
        t.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack(1, 1))?;
        t.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
        if output {
            t.SetUINT32(&MF_MT_AVG_BITRATE, p.bitrate_kbps.saturating_mul(1000))?;
            let profile = match codec {
                Codec::H264 => eAVEncH264VProfile_High.0 as u32,
                Codec::Hevc => eAVEncH265VProfile_Main_420_8.0 as u32,
            };
            t.SetUINT32(&MF_MT_MPEG2_PROFILE, profile)?;
        }
        if color {
            t.SetUINT32(&MF_MT_VIDEO_NOMINAL_RANGE, MFNominalRange_16_235.0 as u32)?;
            t.SetUINT32(&MF_MT_YUV_MATRIX, MFVideoTransferMatrix_BT709.0 as u32)?;
            t.SetUINT32(&MF_MT_VIDEO_PRIMARIES, MFVideoPrimaries_BT709.0 as u32)?;
            t.SetUINT32(&MF_MT_TRANSFER_FUNCTION, MFVideoTransFunc_709.0 as u32)?;
        }
        Ok(t)
    }
}

impl Encoder {
    /// Open the best available encoder. `device` enables zero-copy hardware
    /// encoding; without it only software encoders are considered.
    pub fn open(device: Option<&ID3D11Device>, pref: EncoderPref, codecs: &[Codec], p: &EncoderParams) -> Result<Encoder, String> {
        let mut candidates = Vec::new();
        if pref != EncoderPref::Software && device.is_some() {
            for &c in codecs {
                candidates.extend(enumerate(c, true));
            }
        }
        if pref != EncoderPref::Hardware {
            // In software, H.264 is far cheaper than HEVC: try it first.
            let mut sw: Vec<Codec> = codecs.to_vec();
            sw.sort_by_key(|c| *c != Codec::H264);
            for c in sw {
                candidates.extend(enumerate(c, false));
            }
        }
        if candidates.is_empty() {
            return Err(format!(
                "no {} encoder found for {:?} (encoder preference: {pref:?})",
                codecs.iter().map(|c| c.name()).collect::<Vec<_>>().join("/"),
                (p.width, p.height)
            ));
        }
        let mut errors = Vec::new();
        for c in candidates {
            match Self::try_open(&c, device, p) {
                Ok(enc) => {
                    log!(
                        "encoder: {} ({}, {}, {})",
                        enc.name,
                        enc.codec.name(),
                        if enc.hardware { "hardware" } else { "software" },
                        if enc.uses_d3d { "zero-copy D3D11 input" } else { "system-memory input" }
                    );
                    return Ok(enc);
                }
                Err(e) => {
                    log!("encoder '{}' ({}) unusable: {e}", c.name, c.codec.name());
                    errors.push(format!("{}: {e}", c.name));
                }
            }
        }
        Err(format!("no encoder could be initialised: {}", errors.join("; ")))
    }

    fn try_open(c: &Candidate, device: Option<&ID3D11Device>, p: &EncoderParams) -> Result<Encoder, String> {
        let e = |what: &str, e: windows::core::Error| format!("{what}: {}", hr_str(&e));
        unsafe {
            let mft: IMFTransform = c.activate.ActivateObject().map_err(|x| e("ActivateObject", x))?;
            let attrs = mft.GetAttributes().ok();
            let is_async = attrs.as_ref().is_some_and(|a| a.GetUINT32(&MF_TRANSFORM_ASYNC).unwrap_or(0) != 0);
            if let Some(a) = &attrs {
                if is_async {
                    a.SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1).map_err(|x| e("async unlock", x))?;
                }
                let _ = a.SetUINT32(&MF_LOW_LATENCY, 1);
            }

            let mut manager = None;
            let mut uses_d3d = false;
            if c.hardware {
                let device = device.ok_or("no D3D11 device")?;
                let aware = attrs.as_ref().is_some_and(|a| a.GetUINT32(&MF_SA_D3D11_AWARE).unwrap_or(0) != 0);
                if aware {
                    let mut token = 0u32;
                    let mut m: Option<IMFDXGIDeviceManager> = None;
                    MFCreateDXGIDeviceManager(&mut token, &mut m).map_err(|x| e("MFCreateDXGIDeviceManager", x))?;
                    let m = m.ok_or("no device manager")?;
                    m.ResetDevice(device, token).map_err(|x| e("ResetDevice", x))?;
                    mft.ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, m.as_raw() as usize)
                        .map_err(|x| e("SET_D3D_MANAGER (encoder belongs to another GPU?)", x))?;
                    manager = Some(m);
                    uses_d3d = true;
                }
            }

            let (mut in_id, mut out_id) = (0u32, 0u32);
            let _ = mft.GetStreamIDs(std::slice::from_mut(&mut in_id), std::slice::from_mut(&mut out_id));

            let codec_api: Option<ICodecAPI> = mft.cast().ok();
            let enc = Encoder {
                mft,
                codec_api,
                _manager: manager,
                name: c.name.clone(),
                codec: c.codec,
                hardware: c.hardware,
                is_async,
                uses_d3d,
                in_id,
                out_id,
                out_info: Mutex::new(None),
                keyframe_unsupported: AtomicBool::new(false),
                params: *p,
                seq_header: Mutex::new(Vec::new()),
                credits: Mutex::new(0),
                credit_cv: Condvar::new(),
                pending_ts: Mutex::new(VecDeque::new()),
                in_flight: AtomicU32::new(0),
                draining: AtomicBool::new(false),
                error: Mutex::new(None),
                scratch: Mutex::new(Vec::new()),
                frames_out: AtomicU32::new(0),
            };
            // Some encoders only honour rate-control settings made before the
            // types are set, others only after: do both.
            enc.configure(false);
            let mut last = String::new();
            let mut ok = false;
            for color in [true, false] {
                let r = (|| -> windows::core::Result<()> {
                    let out_t = media_type(subtype(c.codec), p, true, c.codec, color)?;
                    enc.mft.SetOutputType(enc.out_id, &out_t, 0)?;
                    let in_t = media_type(MFVideoFormat_NV12, p, false, c.codec, color)?;
                    enc.mft.SetInputType(enc.in_id, &in_t, 0)?;
                    Ok(())
                })();
                match r {
                    Ok(()) => {
                        ok = true;
                        break;
                    }
                    Err(x) => last = hr_str(&x),
                }
            }
            if !ok {
                return Err(format!("rejected {}x{} @ {} fps NV12: {last}", p.width, p.height, p.fps));
            }
            enc.configure(true);

            enc.read_sequence_header();

            enc.mft.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0).map_err(|x| e("BEGIN_STREAMING", x))?;
            enc.mft.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0).map_err(|x| e("START_OF_STREAM", x))?;
            Ok(enc)
        }
    }

    fn set(&self, api: &GUID, value: VARIANT, what: &str, verbose: bool) -> bool {
        let Some(c) = &self.codec_api else { return false };
        unsafe {
            match c.SetValue(api, &value) {
                Ok(()) => true,
                Err(e) => {
                    if verbose {
                        log!("  encoder option {what} not applied: {}", hr_str(&e));
                    }
                    false
                }
            }
        }
    }

    /// Low-latency configuration: constant bitrate, no B-frames, no lookahead,
    /// effectively infinite GOP (keyframes only on demand).
    fn configure(&self, verbose: bool) {
        let p = &self.params;
        self.set(&CODECAPI_AVEncCommonRateControlMode, VARIANT::from(eAVEncCommonRateControlMode_CBR.0 as u32), "rate control CBR", verbose);
        self.set(&CODECAPI_AVEncCommonMeanBitRate, VARIANT::from(p.bitrate_kbps.saturating_mul(1000)), "bitrate", verbose);
        self.set(&CODECAPI_AVLowLatencyMode, VARIANT::from(true), "low latency mode", verbose);
        self.set(&CODECAPI_AVEncMPVDefaultBPictureCount, VARIANT::from(0u32), "no B-frames", verbose);
        self.set(&CODECAPI_AVEncMPVGOPSize, VARIANT::from(p.fps.max(1) * 600), "long GOP", verbose);
        if !self.hardware {
            // The software encoder must keep up in real time: favour speed.
            self.set(&CODECAPI_AVEncCommonQualityVsSpeed, VARIANT::from(0u32), "speed preset", false);
        }
        if self.codec == Codec::H264 {
            self.set(&CODECAPI_AVEncH264CABACEnable, VARIANT::from(true), "CABAC", false);
        }
    }

    fn read_sequence_header(&self) {
        unsafe {
            let Ok(t) = self.mft.GetOutputCurrentType(self.out_id) else { return };
            let Ok(size) = t.GetBlobSize(&MF_MT_MPEG_SEQUENCE_HEADER) else { return };
            if size == 0 || size > 4096 {
                return;
            }
            let mut buf = vec![0u8; size as usize];
            if t.GetBlob(&MF_MT_MPEG_SEQUENCE_HEADER, &mut buf, None).is_ok() && annexb::nal_units(&buf).next().is_some() {
                *self.seq_header.lock().unwrap() = buf;
            }
        }
    }

    /// Change the target bitrate while streaming. False if the transform does
    /// not support that (the caller then restarts the encoder).
    pub fn set_bitrate(&self, kbps: u32) -> bool {
        self.set(&CODECAPI_AVEncCommonMeanBitRate, VARIANT::from(kbps.saturating_mul(1000)), "bitrate", false)
    }

    pub fn failure(&self) -> Option<String> {
        self.error.lock().unwrap().clone()
    }

    fn fail(&self, msg: String) {
        let mut e = self.error.lock().unwrap();
        if e.is_none() {
            *e = Some(msg);
        }
        drop(e);
        // Hold the lock so a waiter between its predicate check and its sleep cannot miss this.
        let _guard = self.credits.lock().unwrap();
        self.credit_cv.notify_all();
    }

    /// Wait until the transform wants a frame. False if it did not within `wait`.
    fn take_credit(&self, wait: Duration) -> bool {
        if !self.is_async {
            return true;
        }
        let guard = self.credits.lock().unwrap();
        let (mut guard, _) = self
            .credit_cv
            .wait_timeout_while(guard, wait, |c| *c == 0 && self.error.lock().unwrap().is_none())
            .unwrap();
        if *guard == 0 {
            return false;
        }
        *guard -= 1;
        true
    }

    fn feed(&self, buffer: &IMFMediaBuffer, ts_us: u64, force_key: bool) -> Result<(), String> {
        unsafe {
            if force_key
                && !self.set(&CODECAPI_AVEncVideoForceKeyFrame, VARIANT::from(1u32), "force keyframe", false)
                && !self.keyframe_unsupported.swap(true, Ordering::Relaxed)
            {
                log!("encoder '{}' rejects on-demand keyframes; it will be restarted when one is needed", self.name);
            }
            let sample = MFCreateSample().map_err(|e| format!("MFCreateSample: {}", hr_str(&e)))?;
            sample.AddBuffer(buffer).map_err(|e| format!("AddBuffer: {}", hr_str(&e)))?;
            // Capture time doubles as the presentation timestamp (100 ns units).
            let _ = sample.SetSampleTime(ts_us as i64 * 10);
            let _ = sample.SetSampleDuration(10_000_000 / self.params.fps.max(1) as i64);
            self.pending_ts.lock().unwrap().push_back(ts_us);
            self.in_flight.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = self.mft.ProcessInput(self.in_id, &sample, 0) {
                self.pending_ts.lock().unwrap().pop_back();
                self.in_flight.fetch_sub(1, Ordering::Relaxed);
                return Err(format!("ProcessInput: {}", hr_str(&e)));
            }
        }
        Ok(())
    }

    /// Submit a GPU frame. Returns false if the encoder was not ready in time
    /// (the frame is dropped; the next one supersedes it).
    pub fn submit_texture(&self, tex: &ID3D11Texture2D, ts_us: u64, force_key: bool, wait: Duration, sink: &dyn Sink) -> Result<bool, String> {
        if let Some(e) = self.failure() {
            return Err(e);
        }
        if !self.take_credit(wait) {
            return Ok(false);
        }
        unsafe {
            let buffer = MFCreateDXGISurfaceBuffer(&ID3D11Texture2D::IID, tex, 0, false)
                .map_err(|e| format!("MFCreateDXGISurfaceBuffer: {}", hr_str(&e)))?;
            if let Ok(b2d) = buffer.cast::<IMF2DBuffer>() {
                if let Ok(len) = b2d.GetContiguousLength() {
                    let _ = buffer.SetCurrentLength(len);
                }
            }
            self.feed(&buffer, ts_us, force_key)?;
        }
        self.after_input(sink)?;
        Ok(true)
    }

    /// Submit a tightly packed NV12 frame from system memory.
    pub fn submit_nv12(&self, nv12: &[u8], ts_us: u64, force_key: bool, wait: Duration, sink: &dyn Sink) -> Result<bool, String> {
        if let Some(e) = self.failure() {
            return Err(e);
        }
        if !self.take_credit(wait) {
            return Ok(false);
        }
        unsafe {
            let buffer = MFCreateMemoryBuffer(nv12.len() as u32).map_err(|e| format!("MFCreateMemoryBuffer: {}", hr_str(&e)))?;
            let mut ptr = std::ptr::null_mut();
            buffer.Lock(&mut ptr, None, None).map_err(|e| format!("Lock: {}", hr_str(&e)))?;
            std::ptr::copy_nonoverlapping(nv12.as_ptr(), ptr, nv12.len());
            let _ = buffer.Unlock();
            buffer.SetCurrentLength(nv12.len() as u32).map_err(|e| format!("SetCurrentLength: {}", hr_str(&e)))?;
            self.feed(&buffer, ts_us, force_key)?;
        }
        self.after_input(sink)?;
        Ok(true)
    }

    fn after_input(&self, sink: &dyn Sink) -> Result<(), String> {
        if !self.is_async {
            // Synchronous transform: collect whatever it produced right now.
            while self.pull_output(sink)? {}
        }
        Ok(())
    }

    /// Fetch one encoded frame and hand it to the sink. False if none was ready.
    fn pull_output(&self, sink: &dyn Sink) -> Result<bool, String> {
        unsafe {
            let mut out = MFT_OUTPUT_DATA_BUFFER {
                dwStreamID: self.out_id,
                pSample: ManuallyDrop::new(None),
                dwStatus: 0,
                pEvents: ManuallyDrop::new(None),
            };
            // Whether we or the transform allocate output samples is only
            // reliable once the types are committed and streaming has started.
            let (provides_samples, out_size) = *self.out_info.lock().unwrap().get_or_insert_with(|| {
                match self.mft.GetOutputStreamInfo(self.out_id) {
                    Ok(info) => (
                        info.dwFlags & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32 | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0 as u32) != 0,
                        info.cbSize,
                    ),
                    Err(_) => (self.is_async, 0),
                }
            });
            if !provides_samples {
                let sample = MFCreateSample().map_err(|e| format!("MFCreateSample: {}", hr_str(&e)))?;
                let size = out_size.max(self.params.width * self.params.height * 2).max(1 << 20);
                let buf = MFCreateMemoryBuffer(size).map_err(|e| format!("MFCreateMemoryBuffer: {}", hr_str(&e)))?;
                sample.AddBuffer(&buf).map_err(|e| format!("AddBuffer: {}", hr_str(&e)))?;
                out.pSample = ManuallyDrop::new(Some(sample));
            }
            let mut status = 0u32;
            let r = self.mft.ProcessOutput(0, std::slice::from_mut(&mut out), &mut status);
            let sample = ManuallyDrop::take(&mut out.pSample);
            drop(ManuallyDrop::take(&mut out.pEvents));
            if let Err(e) = r {
                if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT {
                    return Ok(false);
                }
                if e.code() == MF_E_TRANSFORM_STREAM_CHANGE {
                    // The encoder refined its output type; accept and carry on.
                    let t = self.mft.GetOutputAvailableType(self.out_id, 0).map_err(|e| format!("stream change: {}", hr_str(&e)))?;
                    self.mft.SetOutputType(self.out_id, &t, 0).map_err(|e| format!("stream change: {}", hr_str(&e)))?;
                    *self.out_info.lock().unwrap() = None;
                    self.read_sequence_header();
                    return Ok(true);
                }
                return Err(format!("ProcessOutput: {}", hr_str(&e)));
            }
            let sample = sample.ok_or("encoder returned no sample")?;
            let sample_ts = sample.GetSampleTime().map(|t| (t / 10) as u64).ok();
            let buf = sample.ConvertToContiguousBuffer().map_err(|e| format!("ConvertToContiguousBuffer: {}", hr_str(&e)))?;
            let mut ptr = std::ptr::null_mut();
            let mut len = 0u32;
            buf.Lock(&mut ptr, None, Some(&mut len)).map_err(|e| format!("Lock: {}", hr_str(&e)))?;
            let data = std::slice::from_raw_parts(ptr, len as usize);
            self.emit(data, sample_ts, sink);
            let _ = buf.Unlock();
        }
        Ok(true)
    }

    fn emit(&self, data: &[u8], sample_ts: Option<u64>, sink: &dyn Sink) {
        let info = annexb::inspect(self.codec, data);
        if info.slices == 0 {
            // Parameter sets delivered on their own: keep them for the next keyframe.
            if info.has_param_sets {
                *self.seq_header.lock().unwrap() = data.to_vec();
            }
            return;
        }
        // Match the output to its capture timestamp (outputs are in input order).
        let ts = {
            let mut q = self.pending_ts.lock().unwrap();
            match sample_ts.and_then(|t| q.iter().position(|&p| p == t)) {
                Some(i) => {
                    q.drain(..i);
                    q.pop_front().unwrap()
                }
                None => q.pop_front().unwrap_or_else(hyperspace_proto::clock::now_us),
            }
        };
        // Only this thread decrements, so load-then-sub cannot underflow.
        if self.in_flight.load(Ordering::Relaxed) > 0 {
            self.in_flight.fetch_sub(1, Ordering::Relaxed);
        }
        self.frames_out.fetch_add(1, Ordering::Relaxed);
        if info.keyframe && info.has_param_sets {
            // Remember the parameter sets in case a later keyframe omits them.
            let ps = annexb::param_sets(self.codec, data);
            if ps.complete(self.codec) {
                let mut hdr = self.seq_header.lock().unwrap();
                hdr.clear();
                for nal in [&ps.vps, &ps.sps, &ps.pps] {
                    if !nal.is_empty() {
                        hdr.extend_from_slice(&[0, 0, 0, 1]);
                        hdr.extend_from_slice(nal);
                    }
                }
            }
        } else if info.keyframe {
            // The decoder needs SPS/PPS in-band with every keyframe. Hardware
            // encoders often only publish the header once they have produced output.
            if self.seq_header.lock().unwrap().is_empty() {
                self.read_sequence_header();
            }
            let hdr = self.seq_header.lock().unwrap();
            if !hdr.is_empty() {
                let mut s = self.scratch.lock().unwrap();
                s.clear();
                s.extend_from_slice(&hdr);
                s.extend_from_slice(data);
                sink.frame(&s, true, ts);
                return;
            }
        }
        sink.frame(data, info.keyframe, ts);
    }

    /// Body of the event thread for asynchronous transforms. Returns when the
    /// transform is drained, shut down, or fails.
    pub fn event_loop(&self, sink: &dyn Sink) {
        let events: IMFMediaEventGenerator = match self.mft.cast() {
            Ok(g) => g,
            Err(e) => return self.fail(format!("IMFMediaEventGenerator: {}", hr_str(&e))),
        };
        loop {
            let ev = match unsafe { events.GetEvent(MEDIA_EVENT_GENERATOR_GET_EVENT_FLAGS(0)) } {
                Ok(ev) => ev,
                Err(e) => {
                    if !self.draining.load(Ordering::Relaxed) {
                        self.fail(format!("encoder event queue: {}", hr_str(&e)));
                    }
                    break;
                }
            };
            let ty = unsafe { ev.GetType() }.unwrap_or(0);
            if ty == METransformNeedInput.0 as u32 {
                *self.credits.lock().unwrap() += 1;
                self.credit_cv.notify_one();
            } else if ty == METransformHaveOutput.0 as u32 {
                if let Err(e) = self.pull_output(sink) {
                    self.fail(e);
                    break;
                }
            } else if ty == METransformDrainComplete.0 as u32 {
                break;
            } else if ty == MEError.0 as u32 {
                let hr = unsafe { ev.GetStatus() }.map(|h| format!("0x{:08X}", h.0 as u32)).unwrap_or_default();
                self.fail(format!("encoder reported an error: {hr}"));
                break;
            }
        }
        self.credit_cv.notify_all();
    }

    /// Ask the transform to finish; the event thread exits on DrainComplete.
    pub fn begin_shutdown(&self) {
        self.draining.store(true, Ordering::Relaxed);
        unsafe {
            if self.is_async {
                let _ = self.mft.ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN, 0);
            }
        }
    }

    /// Last resort if draining does not complete: fails the event queue.
    pub fn force_shutdown(&self) {
        self.draining.store(true, Ordering::Relaxed);
        unsafe {
            if let Ok(s) = self.mft.cast::<IMFShutdown>() {
                let _ = s.Shutdown();
            }
        }
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        unsafe {
            let _ = self.mft.ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            let _ = self.mft.ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
            // Asynchronous transforms must be shut down explicitly or their event
            // queue, worker threads and the GPU encode session outlive the object
            // (consumer NVIDIA cards only allow a few concurrent sessions).
            if self.is_async {
                if let Ok(s) = self.mft.cast::<IMFShutdown>() {
                    let _ = s.Shutdown();
                }
            }
        }
    }
}
