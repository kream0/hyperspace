//! Presentation with Metal.
//!
//! The decoder's NV12 IOSurface is wrapped as two Metal textures (no copy),
//! converted to RGB in a fragment shader and presented with display sync off,
//! so a decoded frame reaches the compositor immediately instead of waiting
//! for the next vsync slot of a swap chain.

use super::UiShared;
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2_core_foundation::{CFRetained, CGSize};
use objc2_core_graphics::{kCGColorSpaceSRGB, CGColorSpace};
use objc2_core_video::{
    CVMetalTexture, CVMetalTextureCache, CVMetalTextureGetTexture, CVPixelBuffer, CVPixelBufferGetHeight,
    CVPixelBufferGetHeightOfPlane, CVPixelBufferGetWidth, CVPixelBufferGetWidthOfPlane,
};
use objc2_foundation::NSString;
use objc2_metal::{
    MTLClearColor, MTLCommandBuffer, MTLCommandEncoder, MTLCommandQueue, MTLCreateSystemDefaultDevice, MTLDevice, MTLDrawable,
    MTLLibrary, MTLLoadAction, MTLPixelFormat, MTLPrimitiveType, MTLRenderCommandEncoder, MTLRenderPassDescriptor,
    MTLRenderPipelineDescriptor, MTLRenderPipelineState, MTLStoreAction, MTLViewport,
};
use objc2_quartz_core::{CAMetalDrawable, CAMetalLayer};
use std::collections::VecDeque;
use std::ptr::NonNull;
use std::sync::atomic::Ordering;

const SHADER: &str = r#"
#include <metal_stdlib>
using namespace metal;

struct VOut {
    float4 pos [[position]];
    float2 uv;
};

// One oversized triangle covering the viewport.
vertex VOut vs(uint vid [[vertex_id]]) {
    float2 p = float2((vid << 1) & 2, vid & 2);
    VOut o;
    o.pos = float4(p * 2.0 - 1.0, 0.0, 1.0);
    o.uv = float2(p.x, 1.0 - p.y);
    return o;
}

// NV12, BT.709, limited range -> RGB.
fragment float4 fs(VOut in [[stage_in]],
                   texture2d<float> luma [[texture(0)]],
                   texture2d<float> chroma [[texture(1)]]) {
    constexpr sampler s(filter::linear, address::clamp_to_edge);
    float y = (luma.sample(s, in.uv).r - 16.0 / 255.0) * (255.0 / 219.0);
    float2 c = (chroma.sample(s, in.uv).rg - 128.0 / 255.0) * (255.0 / 224.0);
    float3 rgb = float3(y + 1.5748 * c.y,
                        y - 0.1873 * c.x - 0.4681 * c.y,
                        y + 1.8556 * c.x);
    return float4(saturate(rgb), 1.0);
}
"#;

/// Where the video sits inside a surface of `dw` x `dh` pixels (aspect-fit, centred).
pub fn letterbox(dw: f64, dh: f64, vw: f64, vh: f64) -> (f64, f64, f64, f64) {
    if dw <= 0.0 || dh <= 0.0 || vw <= 0.0 || vh <= 0.0 {
        return (0.0, 0.0, dw.max(0.0), dh.max(0.0));
    }
    let scale = (dw / vw).min(dh / vh);
    let (w, h) = (vw * scale, vh * scale);
    ((dw - w) / 2.0, (dh - h) / 2.0, w, h)
}

pub struct Renderer {
    layer: Retained<CAMetalLayer>,
    queue: Retained<ProtocolObject<dyn MTLCommandQueue>>,
    pipeline: Retained<ProtocolObject<dyn MTLRenderPipelineState>>,
    cache: CFRetained<CVMetalTextureCache>,
    /// Textures (and their pixel buffer) must outlive the GPU's use of them.
    keep: VecDeque<(CFRetained<CVMetalTexture>, CFRetained<CVMetalTexture>, CFRetained<CVPixelBuffer>)>,
    drawable_size: (u32, u32),
    warned: bool,
    pub presented: u64,
}

// The layer and Metal objects are only touched from the render thread after setup.
unsafe impl Send for Renderer {}

impl Renderer {
    pub fn new(layer: Retained<CAMetalLayer>) -> Result<Renderer, String> {
        let device = MTLCreateSystemDefaultDevice().ok_or("no Metal device available")?;
        unsafe {
            layer.setDevice(Some(&device));
            layer.setPixelFormat(MTLPixelFormat::BGRA8Unorm);
            layer.setFramebufferOnly(true);
            layer.setOpaque(true);
            // Present as soon as a frame is ready rather than queueing for vsync.
            layer.setDisplaySyncEnabled(false);
            layer.setMaximumDrawableCount(2);
            // The host desktop is sRGB; let the system colour-match to this display.
            if let Some(cs) = CGColorSpace::with_name(Some(kCGColorSpaceSRGB)) {
                layer.setColorspace(Some(&cs));
            }
        }
        let queue = device.newCommandQueue().ok_or("cannot create a Metal command queue")?;
        let library = device
            .newLibraryWithSource_options_error(&NSString::from_str(SHADER), None)
            .map_err(|e| format!("shader compilation failed: {}", e.localizedDescription()))?;
        let vs = library.newFunctionWithName(&NSString::from_str("vs")).ok_or("vertex function missing")?;
        let fs = library.newFunctionWithName(&NSString::from_str("fs")).ok_or("fragment function missing")?;
        let desc = MTLRenderPipelineDescriptor::new();
        desc.setVertexFunction(Some(&vs));
        desc.setFragmentFunction(Some(&fs));
        unsafe {
            desc.colorAttachments().objectAtIndexedSubscript(0).setPixelFormat(MTLPixelFormat::BGRA8Unorm);
        }
        let pipeline = device
            .newRenderPipelineStateWithDescriptor_error(&desc)
            .map_err(|e| format!("render pipeline creation failed: {}", e.localizedDescription()))?;

        let mut cache: *mut CVMetalTextureCache = std::ptr::null_mut();
        let st = unsafe { CVMetalTextureCache::create(None, None, &device, None, NonNull::from(&mut cache)) };
        let cache = NonNull::new(cache).filter(|_| st == 0).ok_or(format!("CVMetalTextureCacheCreate failed ({st})"))?;
        let cache = unsafe { CFRetained::from_raw(cache) };

        Ok(Renderer { layer, queue, pipeline, cache, keep: VecDeque::new(), drawable_size: (0, 0), warned: false, presented: 0 })
    }

    fn plane_texture(&self, pb: &CVPixelBuffer, format: MTLPixelFormat, plane: usize) -> Option<CFRetained<CVMetalTexture>> {
        let w = CVPixelBufferGetWidthOfPlane(pb, plane);
        let h = CVPixelBufferGetHeightOfPlane(pb, plane);
        let mut out: *mut CVMetalTexture = std::ptr::null_mut();
        let st = unsafe {
            CVMetalTextureCache::create_texture_from_image(None, &self.cache, pb, None, format, w, h, plane, NonNull::from(&mut out))
        };
        NonNull::new(out).filter(|_| st == 0).map(|p| unsafe { CFRetained::from_raw(p) })
    }

    /// Draw the frame and present it. Returns false if it could not be shown
    /// (window hidden, no drawable): not an error, the stream goes on.
    pub fn present(&mut self, pb: &CFRetained<CVPixelBuffer>, shared: &UiShared) -> bool {
        let (vw, vh) = (CVPixelBufferGetWidth(pb) as u32, CVPixelBufferGetHeight(pb) as u32);
        shared.video_w.store(vw, Ordering::Relaxed);
        shared.video_h.store(vh, Ordering::Relaxed);
        if shared.occluded.load(Ordering::Relaxed) {
            return false;
        }
        let want = (shared.surface_w.load(Ordering::Relaxed), shared.surface_h.load(Ordering::Relaxed));
        if want.0 == 0 || want.1 == 0 {
            return false;
        }
        if want != self.drawable_size {
            self.layer.setDrawableSize(CGSize { width: want.0 as f64, height: want.1 as f64 });
            self.drawable_size = want;
        }

        let (Some(ty), Some(tc)) =
            (self.plane_texture(pb, MTLPixelFormat::R8Unorm, 0), self.plane_texture(pb, MTLPixelFormat::RG8Unorm, 1))
        else {
            if !self.warned {
                self.warned = true;
                hyperspace_proto::log!("cannot wrap the decoded frame as Metal textures; nothing will be shown");
            }
            return false;
        };
        let (Some(luma), Some(chroma)) = (CVMetalTextureGetTexture(&ty), CVMetalTextureGetTexture(&tc)) else {
            return false;
        };
        let Some(drawable) = self.layer.nextDrawable() else { return false };

        let pass = MTLRenderPassDescriptor::renderPassDescriptor();
        unsafe {
            let att = pass.colorAttachments().objectAtIndexedSubscript(0);
            att.setTexture(Some(&drawable.texture()));
            att.setLoadAction(MTLLoadAction::Clear);
            att.setStoreAction(MTLStoreAction::Store);
            att.setClearColor(MTLClearColor { red: 0.0, green: 0.0, blue: 0.0, alpha: 1.0 });
        }
        let Some(cmd) = self.queue.commandBuffer() else { return false };
        let Some(enc) = cmd.renderCommandEncoderWithDescriptor(&pass) else { return false };
        let (x, y, w, h) = letterbox(want.0 as f64, want.1 as f64, vw as f64, vh as f64);
        enc.setRenderPipelineState(&self.pipeline);
        enc.setViewport(MTLViewport { originX: x, originY: y, width: w, height: h, znear: 0.0, zfar: 1.0 });
        unsafe {
            enc.setFragmentTexture_atIndex(Some(&luma), 0);
            enc.setFragmentTexture_atIndex(Some(&chroma), 1);
            enc.drawPrimitives_vertexStart_vertexCount(MTLPrimitiveType::Triangle, 0, 3);
        }
        enc.endEncoding();
        let d: &ProtocolObject<dyn MTLDrawable> = ProtocolObject::from_ref(&*drawable);
        cmd.presentDrawable(d);
        cmd.commit();

        self.keep.push_back((ty, tc, pb.clone()));
        while self.keep.len() > 3 {
            self.keep.pop_front();
        }
        self.presented += 1;
        true
    }

    /// Redraw the last frame if the window changed while the stream was idle
    /// (the host sends nothing while its desktop is still).
    pub fn refresh(&mut self, shared: &UiShared) {
        let want = (shared.surface_w.load(Ordering::Relaxed), shared.surface_h.load(Ordering::Relaxed));
        if shared.redraw.swap(false, Ordering::Relaxed) || want != self.drawable_size {
            if let Some(pb) = self.keep.back().map(|k| k.2.clone()) {
                if self.present(&pb, shared) {
                    self.presented -= 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::letterbox;

    #[test]
    fn letterbox_fits_and_centres() {
        assert_eq!(letterbox(1920.0, 1080.0, 1920.0, 1080.0), (0.0, 0.0, 1920.0, 1080.0));
        assert_eq!(letterbox(2000.0, 1000.0, 1000.0, 1000.0), (500.0, 0.0, 1000.0, 1000.0));
        assert_eq!(letterbox(1000.0, 2000.0, 1000.0, 500.0), (0.0, 750.0, 1000.0, 500.0));
    }
}
