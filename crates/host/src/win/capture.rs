//! Screen capture with DXGI Desktop Duplication.
//!
//! Desktop Duplication hands us the compositor's own GPU texture the moment a
//! new frame is presented: no polling, no readback, no extra vsync of delay.

use super::{hr_str, wide_to_string};
use hyperspace_proto::cursor::CursorShape;
use hyperspace_proto::log;
use windows::core::Interface;
use windows::Win32::Foundation::{E_ACCESSDENIED, HMODULE};
use windows::Win32::Graphics::Direct3D::*;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::*;
use windows::Win32::Graphics::Dxgi::*;
use windows::Win32::Graphics::Gdi::{EnumDisplaySettingsW, DEVMODEW, ENUM_CURRENT_SETTINGS};

pub struct OutputInfo {
    pub index: usize,
    pub adapter: IDXGIAdapter1,
    pub adapter_name: String,
    pub output: IDXGIOutput,
    pub name: String,
    /// left, top, width, height in virtual-desktop pixels
    pub rect: (i32, i32, i32, i32),
    pub refresh_hz: u32,
    pub primary: bool,
}

/// Every display attached to the desktop, in adapter/output enumeration order.
pub fn enumerate_outputs() -> Result<Vec<OutputInfo>, String> {
    let factory: IDXGIFactory1 = unsafe { CreateDXGIFactory1() }.map_err(|e| format!("CreateDXGIFactory1: {}", hr_str(&e)))?;
    let mut outs = Vec::new();
    let mut a = 0;
    while let Ok(adapter) = unsafe { factory.EnumAdapters1(a) } {
        a += 1;
        let adapter_name = unsafe { adapter.GetDesc1() }.map(|d| wide_to_string(&d.Description)).unwrap_or_default();
        let mut o = 0;
        while let Ok(output) = unsafe { adapter.EnumOutputs(o) } {
            o += 1;
            let Ok(desc) = (unsafe { output.GetDesc() }) else { continue };
            if !desc.AttachedToDesktop.as_bool() {
                continue;
            }
            let r = desc.DesktopCoordinates;
            let mut mode = DEVMODEW { dmSize: std::mem::size_of::<DEVMODEW>() as u16, ..Default::default() };
            let refresh_hz = unsafe {
                if EnumDisplaySettingsW(windows::core::PCWSTR(desc.DeviceName.as_ptr()), ENUM_CURRENT_SETTINGS, &mut mode).as_bool()
                    && mode.dmDisplayFrequency > 1
                {
                    mode.dmDisplayFrequency
                } else {
                    60
                }
            };
            outs.push(OutputInfo {
                index: outs.len(),
                adapter: adapter.clone(),
                adapter_name: adapter_name.clone(),
                output,
                name: wide_to_string(&desc.DeviceName),
                rect: (r.left, r.top, r.right - r.left, r.bottom - r.top),
                refresh_hz,
                primary: r.left == 0 && r.top == 0,
            });
        }
    }
    Ok(outs)
}

pub enum Acquired {
    /// Nothing changed within the timeout.
    Timeout,
    /// Duplication was invalidated (mode change, secure desktop, ...): call `reopen`.
    Lost,
    /// `image` is true when the desktop image changed and was copied to the target texture.
    Frame { image: bool },
}

pub struct Capture {
    pub device: ID3D11Device,
    pub context: ID3D11DeviceContext,
    output: IDXGIOutput1,
    dupl: Option<IDXGIOutputDuplication>,
    pub width: u32,
    pub height: u32,
    pub rect: (i32, i32, i32, i32),
    pub refresh_hz: u32,
    pub adapter_name: String,
    pub output_name: String,
    /// True when the adapter has no real GPU behind it (WARP / basic display).
    pub software_adapter: bool,
    shape_buf: Vec<u8>,
    cursor_visible: bool,
    holding_frame: bool,
    /// The first frame after (re)opening is always a full image.
    first_after_open: bool,
}

impl Capture {
    /// `display == usize::MAX` selects the primary display.
    pub fn new(display: usize) -> Result<Capture, String> {
        let mut outs = enumerate_outputs()?;
        if outs.is_empty() {
            return Err("no display is attached to the desktop (headless machine or disconnected session?)".into());
        }
        let pick = if display == usize::MAX {
            outs.iter().position(|o| o.primary).unwrap_or(0)
        } else if display < outs.len() {
            display
        } else {
            return Err(format!("--display {display} does not exist ({} displays, see --list)", outs.len()));
        };
        let out = outs.swap_remove(pick);

        let levels = [D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0];
        let mut device = None;
        let mut context = None;
        let mut last_err = String::new();
        // VIDEO_SUPPORT is needed for the GPU colour converter; adapters without
        // it (software rasterizer) still work through the CPU path.
        for flags in [D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT, D3D11_CREATE_DEVICE_BGRA_SUPPORT] {
            let r = unsafe {
                D3D11CreateDevice(
                    &out.adapter,
                    D3D_DRIVER_TYPE_UNKNOWN,
                    HMODULE::default(),
                    flags,
                    Some(&levels),
                    D3D11_SDK_VERSION,
                    Some(&mut device),
                    None,
                    Some(&mut context),
                )
            };
            match r {
                Ok(()) => break,
                Err(e) => last_err = hr_str(&e),
            }
        }
        let (Some(device), Some(context)) = (device, context) else {
            return Err(format!("D3D11CreateDevice on '{}' failed: {last_err}", out.adapter_name));
        };
        // Media Foundation and our threads share the immediate context.
        match context.cast::<ID3D11Multithread>() {
            Ok(mt) => unsafe {
                let _ = mt.SetMultithreadProtected(true);
            },
            Err(_) => log!("warning: cannot enable D3D11 multithread protection (Windows 10 1607+ required)"),
        }
        if let Ok(dxgi) = device.cast::<IDXGIDevice1>() {
            unsafe {
                let _ = dxgi.SetMaximumFrameLatency(1);
                // Keep capture/convert work ahead of whatever else is using the GPU.
                let _ = dxgi.SetGPUThreadPriority(7);
            }
        }
        let software_adapter = unsafe { out.adapter.GetDesc1() }
            .map(|d| (d.Flags & DXGI_ADAPTER_FLAG_SOFTWARE.0 as u32) != 0 || (d.VendorId == 0x1414 && d.DeviceId == 0x8c))
            .unwrap_or(false);

        let output: IDXGIOutput1 = out.output.cast().map_err(|e| format!("IDXGIOutput1: {}", hr_str(&e)))?;
        let mut cap = Capture {
            device,
            context,
            output,
            dupl: None,
            width: 0,
            height: 0,
            rect: out.rect,
            refresh_hz: out.refresh_hz,
            adapter_name: out.adapter_name,
            output_name: out.name,
            software_adapter,
            shape_buf: Vec::new(),
            cursor_visible: true,
            holding_frame: false,
            first_after_open: true,
        };
        cap.reopen().map_err(|e| format!("cannot start desktop duplication on {}: {e}", cap.output_name))?;
        Ok(cap)
    }

    /// (Re)create the duplication. Fails while the secure desktop (UAC prompt,
    /// lock screen) is showing; the caller retries.
    pub fn reopen(&mut self) -> Result<(), String> {
        self.dupl = None;
        self.holding_frame = false;
        self.first_after_open = true;
        let dupl = unsafe { self.output.DuplicateOutput(&self.device) }.map_err(|e| {
            if e.code() == E_ACCESSDENIED {
                "access denied (secure desktop is active)".to_string()
            } else {
                hr_str(&e)
            }
        })?;
        let desc = unsafe { dupl.GetDesc() };
        self.width = desc.ModeDesc.Width;
        self.height = desc.ModeDesc.Height;
        if let Ok(d) = unsafe { self.output.GetDesc() } {
            let r = d.DesktopCoordinates;
            self.rect = (r.left, r.top, r.right - r.left, r.bottom - r.top);
        }
        if desc.ModeDesc.Format != DXGI_FORMAT_B8G8R8A8_UNORM {
            log!("note: desktop format is {:?}, expected BGRA8", desc.ModeDesc.Format);
        }
        self.dupl = Some(dupl);
        Ok(())
    }

    /// Texture the desktop image gets copied into.
    pub fn create_target(&self) -> Result<ID3D11Texture2D, String> {
        let desc = D3D11_TEXTURE2D_DESC {
            Width: self.width,
            Height: self.height,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM,
            SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
            Usage: D3D11_USAGE_DEFAULT,
            BindFlags: (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32,
            CPUAccessFlags: 0,
            MiscFlags: 0,
        };
        let mut tex = None;
        unsafe { self.device.CreateTexture2D(&desc, None, Some(&mut tex)) }
            .map_err(|e| format!("CreateTexture2D(BGRA {}x{}): {}", self.width, self.height, hr_str(&e)))?;
        tex.ok_or_else(|| "CreateTexture2D returned nothing".to_string())
    }

    /// Wait up to `timeout_ms` for the desktop or the pointer to change.
    pub fn acquire(
        &mut self,
        timeout_ms: u32,
        target: &ID3D11Texture2D,
        cursor: &mut dyn FnMut(Option<&CursorShape>, bool),
    ) -> Result<Acquired, String> {
        let Some(dupl) = self.dupl.clone() else { return Ok(Acquired::Lost) };
        if self.holding_frame {
            unsafe {
                let _ = dupl.ReleaseFrame();
            }
            self.holding_frame = false;
        }
        let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;
        if let Err(e) = unsafe { dupl.AcquireNextFrame(timeout_ms, &mut info, &mut resource) } {
            return if e.code() == DXGI_ERROR_WAIT_TIMEOUT {
                Ok(Acquired::Timeout)
            } else if e.code() == DXGI_ERROR_ACCESS_LOST || e.code() == DXGI_ERROR_INVALID_CALL {
                self.dupl = None;
                Ok(Acquired::Lost)
            } else {
                Err(format!("AcquireNextFrame: {}", hr_str(&e)))
            };
        }
        self.holding_frame = true;

        let mut image = false;
        if info.LastPresentTime != 0 || info.AccumulatedFrames != 0 || self.first_after_open {
            self.first_after_open = false;
            if let Some(tex) = resource.as_ref().and_then(|r| r.cast::<ID3D11Texture2D>().ok()) {
                unsafe { self.context.CopyResource(target, &tex) };
                image = true;
            }
        }

        if info.LastMouseUpdateTime != 0 {
            let visible = info.PointerPosition.Visible.as_bool();
            let mut shape = None;
            if info.PointerShapeBufferSize > 0 {
                self.shape_buf.resize(info.PointerShapeBufferSize as usize, 0);
                let mut required = 0u32;
                let mut si = DXGI_OUTDUPL_POINTER_SHAPE_INFO::default();
                let ok = unsafe {
                    dupl.GetFramePointerShape(
                        self.shape_buf.len() as u32,
                        self.shape_buf.as_mut_ptr().cast(),
                        &mut required,
                        &mut si,
                    )
                };
                if ok.is_ok() {
                    let hot = (si.HotSpot.x.max(0) as u32, si.HotSpot.y.max(0) as u32);
                    let pitch = si.Pitch as usize;
                    shape = match DXGI_OUTDUPL_POINTER_SHAPE_TYPE(si.Type as i32) {
                        DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME => {
                            CursorShape::from_monochrome(si.Width, si.Height, pitch, hot, &self.shape_buf)
                        }
                        DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR => {
                            CursorShape::from_bgra(si.Width, si.Height, pitch, hot, &self.shape_buf)
                        }
                        DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR => {
                            CursorShape::from_masked_color(si.Width, si.Height, pitch, hot, &self.shape_buf)
                        }
                        _ => None,
                    };
                }
            }
            if shape.is_some() || visible != self.cursor_visible {
                self.cursor_visible = visible;
                cursor(shape.as_ref(), visible);
            }
        }

        // The image is copied; give the frame back so the compositor is never blocked on us.
        unsafe {
            let _ = dupl.ReleaseFrame();
        }
        self.holding_frame = false;
        Ok(Acquired::Frame { image })
    }
}
