//! BGRA -> NV12 on the GPU with the D3D11 video processor (fixed-function
//! colour conversion hardware; well under a millisecond and no readback).

use super::hr_str;
use std::mem::ManuallyDrop;
use windows::core::Interface;
use windows::Win32::Foundation::RECT;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::*;

pub struct GpuConverter {
    vctx: ID3D11VideoContext,
    vp: ID3D11VideoProcessor,
    in_view: ID3D11VideoProcessorInputView,
    out_views: Vec<ID3D11VideoProcessorOutputView>,
    textures: Vec<ID3D11Texture2D>,
    next: usize,
    last: Option<usize>,
}

impl GpuConverter {
    /// `pool` NV12 textures are cycled so the encoder can still be reading
    /// frame N while N+1 is being converted.
    pub fn new(
        device: &ID3D11Device,
        context: &ID3D11DeviceContext,
        bgra: &ID3D11Texture2D,
        src: (u32, u32),
        out: (u32, u32),
        fps: u32,
        pool: usize,
    ) -> Result<GpuConverter, String> {
        let e = |what: &str, e: windows::core::Error| format!("{what}: {}", hr_str(&e));
        let vdev: ID3D11VideoDevice = device.cast().map_err(|x| e("ID3D11VideoDevice", x))?;
        let vctx: ID3D11VideoContext = context.cast().map_err(|x| e("ID3D11VideoContext", x))?;
        let rate = DXGI_RATIONAL { Numerator: fps.max(1), Denominator: 1 };
        let content = D3D11_VIDEO_PROCESSOR_CONTENT_DESC {
            InputFrameFormat: D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
            InputFrameRate: rate,
            InputWidth: src.0,
            InputHeight: src.1,
            OutputFrameRate: rate,
            OutputWidth: out.0,
            OutputHeight: out.1,
            Usage: D3D11_VIDEO_USAGE_PLAYBACK_NORMAL,
        };
        unsafe {
            let en = vdev.CreateVideoProcessorEnumerator(&content).map_err(|x| e("CreateVideoProcessorEnumerator", x))?;
            let vp = vdev.CreateVideoProcessor(&en, 0).map_err(|x| e("CreateVideoProcessor", x))?;

            let ivd = D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
                FourCC: 0,
                ViewDimension: D3D11_VPIV_DIMENSION_TEXTURE2D,
                Anonymous: D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0 { Texture2D: D3D11_TEX2D_VPIV { MipSlice: 0, ArraySlice: 0 } },
            };
            let mut in_view = None;
            vdev.CreateVideoProcessorInputView(bgra, &en, &ivd, Some(&mut in_view))
                .map_err(|x| e("CreateVideoProcessorInputView", x))?;
            let in_view = in_view.ok_or("no input view")?;

            let mut textures = Vec::new();
            let mut out_views = Vec::new();
            for _ in 0..pool {
                let desc = D3D11_TEXTURE2D_DESC {
                    Width: out.0,
                    Height: out.1,
                    MipLevels: 1,
                    ArraySize: 1,
                    Format: DXGI_FORMAT_NV12,
                    SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
                    Usage: D3D11_USAGE_DEFAULT,
                    BindFlags: (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32,
                    CPUAccessFlags: 0,
                    MiscFlags: 0,
                };
                let mut tex = None;
                device.CreateTexture2D(&desc, None, Some(&mut tex)).map_err(|x| e("CreateTexture2D(NV12)", x))?;
                let tex = tex.ok_or("no NV12 texture")?;
                let ovd = D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
                    ViewDimension: D3D11_VPOV_DIMENSION_TEXTURE2D,
                    Anonymous: D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0 { Texture2D: D3D11_TEX2D_VPOV { MipSlice: 0 } },
                };
                let mut ov = None;
                vdev.CreateVideoProcessorOutputView(&tex, &en, &ovd, Some(&mut ov))
                    .map_err(|x| e("CreateVideoProcessorOutputView", x))?;
                out_views.push(ov.ok_or("no output view")?);
                textures.push(tex);
            }

            // Desktop is full-range sRGB; encode as BT.709 limited range, which is
            // what every decoder assumes for HD video.
            // Bitfield layout: Usage:1 RGB_Range:1 YCbCr_Matrix:1 YCbCr_xvYCC:1 Nominal_Range:2
            let rgb_full = D3D11_VIDEO_PROCESSOR_COLOR_SPACE { _bitfield: 0 };
            let ycbcr_709_limited = D3D11_VIDEO_PROCESSOR_COLOR_SPACE { _bitfield: (1 << 2) | (1 << 4) };
            vctx.VideoProcessorSetStreamColorSpace(&vp, 0, &rgb_full);
            vctx.VideoProcessorSetOutputColorSpace(&vp, &ycbcr_709_limited);
            vctx.VideoProcessorSetStreamFrameFormat(&vp, 0, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE);
            // No driver "enhancements" (denoise, edge enhancement ...): pixels in, pixels out.
            vctx.VideoProcessorSetStreamAutoProcessingMode(&vp, 0, false);
            let rect = RECT { left: 0, top: 0, right: out.0 as i32, bottom: out.1 as i32 };
            vctx.VideoProcessorSetStreamSourceRect(&vp, 0, true, Some(&rect));
            vctx.VideoProcessorSetStreamDestRect(&vp, 0, true, Some(&rect));
            vctx.VideoProcessorSetOutputTargetRect(&vp, true, Some(&rect));

            Ok(GpuConverter { vctx, vp, in_view, out_views, textures, next: 0, last: None })
        }
    }

    /// Convert the current contents of the BGRA texture; returns the NV12 texture.
    pub fn convert(&mut self) -> Result<&ID3D11Texture2D, String> {
        let i = self.next;
        self.next = (self.next + 1) % self.textures.len();
        let mut stream = D3D11_VIDEO_PROCESSOR_STREAM {
            Enable: true.into(),
            pInputSurface: ManuallyDrop::new(Some(self.in_view.clone())),
            ..Default::default()
        };
        let r = unsafe { self.vctx.VideoProcessorBlt(&self.vp, &self.out_views[i], 0, std::slice::from_ref(&stream)) };
        unsafe { ManuallyDrop::drop(&mut stream.pInputSurface) };
        r.map_err(|e| format!("VideoProcessorBlt: {}", hr_str(&e)))?;
        self.last = Some(i);
        Ok(&self.textures[i])
    }

    /// The most recently converted frame (for re-encoding as a keyframe).
    pub fn last(&self) -> Option<&ID3D11Texture2D> {
        self.last.map(|i| &self.textures[i])
    }
}
