//! Hardware video decoding with VideoToolbox.
//!
//! Decoding is synchronous: `VTDecompressionSessionDecodeFrame` invokes the
//! output callback on the calling thread before it returns, so a frame goes
//! network -> decoder -> renderer without changing threads or waiting in a queue.

use hyperspace_proto::annexb::{self, ParamSets};
use hyperspace_proto::{log, Codec};
use objc2_core_foundation::{CFBoolean, CFDictionary, CFNumber, CFRetained, CFString, CFType};
use objc2_core_media::{
    kCMBlockBufferAssureMemoryNowFlag, CMBlockBuffer, CMFormatDescription, CMSampleBuffer, CMTime,
    CMVideoFormatDescriptionCreateFromH264ParameterSets, CMVideoFormatDescriptionCreateFromHEVCParameterSets,
};
use objc2_core_video::{
    kCVPixelBufferMetalCompatibilityKey, kCVPixelBufferPixelFormatTypeKey, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
    CVImageBuffer, CVPixelBuffer,
};
use objc2_video_toolbox::{
    kVTDecompressionPropertyKey_RealTime, VTDecodeFrameFlags, VTDecodeInfoFlags, VTDecompressionOutputCallbackRecord,
    VTDecompressionSession, VTSessionSetProperty,
};
use std::ffi::c_void;
use std::ptr::NonNull;

/// Where the output callback leaves the decoded frame.
#[derive(Default)]
struct Slot {
    image: Option<CFRetained<CVPixelBuffer>>,
    status: i32,
}

unsafe extern "C-unwind" fn output_callback(
    refcon: *mut c_void,
    _frame_refcon: *mut c_void,
    status: i32,
    _flags: VTDecodeInfoFlags,
    image: *mut CVImageBuffer,
    _pts: CMTime,
    _duration: CMTime,
) {
    let slot = unsafe { &mut *(refcon as *mut Slot) };
    slot.status = status;
    slot.image = NonNull::new(image).map(|p| unsafe { CFRetained::retain(p) });
}

pub struct Decoder {
    codec: Codec,
    params: ParamSets,
    format: Option<CFRetained<CMFormatDescription>>,
    session: Option<CFRetained<VTDecompressionSession>>,
    /// Heap slot the output callback writes through; owned, freed in Drop.
    slot: *mut Slot,
    sample: Vec<u8>,
}

impl Decoder {
    pub fn new(codec: Codec) -> Decoder {
        Decoder {
            codec,
            params: ParamSets::default(),
            format: None,
            session: None,
            slot: Box::into_raw(Box::<Slot>::default()),
            sample: Vec::new(),
        }
    }

    fn make_format(codec: Codec, ps: &ParamSets) -> Result<CFRetained<CMFormatDescription>, String> {
        let mut out: *const CMFormatDescription = std::ptr::null();
        let nn = |v: &Vec<u8>| NonNull::new(v.as_ptr() as *mut u8).unwrap();
        let status = unsafe {
            match codec {
                Codec::H264 => {
                    let mut ptrs = [nn(&ps.sps), nn(&ps.pps)];
                    let mut sizes = [ps.sps.len(), ps.pps.len()];
                    CMVideoFormatDescriptionCreateFromH264ParameterSets(
                        None,
                        2,
                        NonNull::new(ptrs.as_mut_ptr()).unwrap(),
                        NonNull::new(sizes.as_mut_ptr()).unwrap(),
                        4,
                        NonNull::from(&mut out),
                    )
                }
                Codec::Hevc => {
                    let mut ptrs = [nn(&ps.vps), nn(&ps.sps), nn(&ps.pps)];
                    let mut sizes = [ps.vps.len(), ps.sps.len(), ps.pps.len()];
                    CMVideoFormatDescriptionCreateFromHEVCParameterSets(
                        None,
                        3,
                        NonNull::new(ptrs.as_mut_ptr()).unwrap(),
                        NonNull::new(sizes.as_mut_ptr()).unwrap(),
                        4,
                        None,
                        NonNull::from(&mut out),
                    )
                }
            }
        };
        match NonNull::new(out as *mut CMFormatDescription) {
            Some(p) if status == 0 => Ok(unsafe { CFRetained::from_raw(p) }),
            _ => Err(format!("cannot build a format description from the stream's parameter sets (status {status})")),
        }
    }

    fn open_session(&mut self, ps: ParamSets) -> Result<(), String> {
        self.close();
        let format = Self::make_format(self.codec, &ps)?;

        // NV12 output backed by an IOSurface Metal can sample directly: no copies.
        let pixel_format = CFNumber::new_i32(kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange as i32);
        let keys: [&CFString; 2] = unsafe { [kCVPixelBufferPixelFormatTypeKey, kCVPixelBufferMetalCompatibilityKey] };
        let values: [&CFType; 2] = [pixel_format.as_ref(), CFBoolean::new(true).as_ref()];
        let attrs = CFDictionary::<CFString, CFType>::from_slices(&keys, &values);

        let record = VTDecompressionOutputCallbackRecord {
            decompressionOutputCallback: Some(output_callback),
            decompressionOutputRefCon: self.slot.cast(),
        };
        let mut session: *mut VTDecompressionSession = std::ptr::null_mut();
        let status = unsafe {
            VTDecompressionSession::create(None, &format, None, Some(attrs.as_opaque()), &record, NonNull::from(&mut session))
        };
        let Some(session) = NonNull::new(session).filter(|_| status == 0) else {
            return Err(format!("VTDecompressionSessionCreate failed (status {status})"));
        };
        let session = unsafe { CFRetained::from_raw(session) };
        unsafe {
            let on: &CFType = CFBoolean::new(true).as_ref();
            VTSessionSetProperty(session.as_ref(), kVTDecompressionPropertyKey_RealTime, Some(on));
        }
        log!("decoder: VideoToolbox {} session created", self.codec.name());
        self.format = Some(format);
        self.session = Some(session);
        self.params = ps;
        Ok(())
    }

    fn close(&mut self) {
        if let Some(s) = self.session.take() {
            unsafe { s.invalidate() };
        }
        self.format = None;
        unsafe { (*self.slot).image = None };
    }

    /// Decode one access unit (Annex B). `Ok(None)` means the unit produced no
    /// picture; `Err` means the decoder needs a keyframe to continue.
    pub fn decode(&mut self, au: &[u8], keyframe: bool) -> Result<Option<CFRetained<CVPixelBuffer>>, String> {
        if keyframe {
            let ps = annexb::param_sets(self.codec, au);
            if ps.complete(self.codec) && (self.session.is_none() || ps != self.params) {
                self.open_session(ps)?;
            }
        }
        let (Some(session), Some(format)) = (&self.session, &self.format) else {
            return Err("no decoder session yet (waiting for a keyframe with parameter sets)".into());
        };

        annexb::to_length_prefixed(self.codec, au, &mut self.sample);
        if self.sample.is_empty() {
            return Ok(None);
        }
        let len = self.sample.len();

        let sample_buffer = unsafe {
            let mut block: *mut CMBlockBuffer = std::ptr::null_mut();
            let st = CMBlockBuffer::create_with_memory_block(
                None,
                std::ptr::null_mut(),
                len,
                None,
                std::ptr::null(),
                0,
                len,
                kCMBlockBufferAssureMemoryNowFlag,
                NonNull::from(&mut block),
            );
            let Some(block) = NonNull::new(block).filter(|_| st == 0) else {
                return Err(format!("CMBlockBufferCreateWithMemoryBlock failed (status {st})"));
            };
            let block = CFRetained::from_raw(block);
            let st = CMBlockBuffer::replace_data_bytes(NonNull::new(self.sample.as_mut_ptr().cast()).unwrap(), &block, 0, len);
            if st != 0 {
                return Err(format!("CMBlockBufferReplaceDataBytes failed (status {st})"));
            }
            let mut sb: *mut CMSampleBuffer = std::ptr::null_mut();
            let sizes = [len];
            let st = CMSampleBuffer::create_ready(
                None,
                Some(&block),
                Some(format),
                1,
                0,
                std::ptr::null(),
                1,
                sizes.as_ptr(),
                NonNull::from(&mut sb),
            );
            let Some(sb) = NonNull::new(sb).filter(|_| st == 0) else {
                return Err(format!("CMSampleBufferCreateReady failed (status {st})"));
            };
            CFRetained::from_raw(sb)
        };

        unsafe {
            (*self.slot).image = None;
            (*self.slot).status = 0;
        }
        let mut info = VTDecodeInfoFlags(0);
        // No async flag: the callback has completed by the time this returns.
        // No 1x-realtime flag either: that would let the decoder idle in a low-power mode.
        let status = unsafe {
            session.decode_frame(&sample_buffer, VTDecodeFrameFlags::empty(), std::ptr::null_mut(), &mut info)
        };
        let (cb_status, image) = unsafe { ((*self.slot).status, (*self.slot).image.take()) };
        if status != 0 || cb_status != 0 {
            // -12903 (invalid session) follows sleep or a GPU change; any error
            // means the reference chain is gone, so start over on the next keyframe.
            let code = if status != 0 { status } else { cb_status };
            self.close();
            return Err(format!("VideoToolbox decode failed (status {code})"));
        }
        Ok(image)
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        self.close();
        // The session is invalidated, so the callback can no longer run.
        drop(unsafe { Box::from_raw(self.slot) });
    }
}
