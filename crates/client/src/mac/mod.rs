//! macOS front end: a winit window whose content is a Metal layer fed by
//! VideoToolbox, plus input capture.
//!
//! Threads: the main thread owns the window and forwards input straight to the
//! socket; the network thread receives, decodes and presents. A frame never
//! crosses a thread boundary between arriving and being shown.

mod render;
mod video;

use crate::keymap::{scancode, SC_CAPS};
use crate::session::{self, Exit, Handler, InputTx, Options, Stats};
use crate::Args;
use hyperspace_proto::cursor::CursorShape;
use hyperspace_proto::frag::Frame;
use hyperspace_proto::input::InputEvent;
use hyperspace_proto::log;
use objc2::rc::{autoreleasepool, Retained};
use objc2_quartz_core::CAMetalLayer;
use render::{letterbox, Renderer};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use video::Decoder;
use winit::application::ApplicationHandler;
use winit::dpi::PhysicalSize;
use winit::event::{ElementState, MouseButton, MouseScrollDelta, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::keyboard::{Key, ModifiersState, PhysicalKey};
use winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS};
use winit::platform::modifier_supplement::KeyEventExtModifierSupplement;
use winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
use winit::window::{CustomCursor, Fullscreen, Window, WindowId};

/// State shared between the UI thread and the render thread.
#[derive(Default)]
pub struct UiShared {
    /// Window content size in physical pixels.
    pub surface_w: AtomicU32,
    pub surface_h: AtomicU32,
    /// Decoded picture size.
    pub video_w: AtomicU32,
    pub video_h: AtomicU32,
    pub occluded: AtomicBool,
}

enum UserEvent {
    Cursor(CursorShape),
    CursorVisible(bool),
    Stats(Stats),
    Ended { exit: Exit, decoded: u64, presented: u64 },
}

struct NetHandler {
    decoder: Decoder,
    renderer: Renderer,
    shared: Arc<UiShared>,
    proxy: EventLoopProxy<UserEvent>,
    stop: Arc<AtomicBool>,
    max_frames: Option<u64>,
    decoded: u64,
    print_stats: bool,
}

impl Handler for NetHandler {
    fn video_frame(&mut self, frame: &Frame) -> bool {
        // Metal and CoreVideo hand out autoreleased objects; drain them per frame.
        autoreleasepool(|_| match self.decoder.decode(&frame.data, frame.is_keyframe()) {
            Ok(Some(image)) => {
                self.decoded += 1;
                self.renderer.present(&image, &self.shared);
                if self.max_frames.is_some_and(|m| self.decoded >= m) {
                    self.stop.store(true, Ordering::Relaxed);
                }
                true
            }
            Ok(None) => true,
            Err(e) => {
                log!("{e}; requesting a keyframe");
                false
            }
        })
    }

    fn cursor_shape(&mut self, shape: CursorShape) {
        let _ = self.proxy.send_event(UserEvent::Cursor(shape));
    }

    fn cursor_visible(&mut self, visible: bool) {
        let _ = self.proxy.send_event(UserEvent::CursorVisible(visible));
    }

    fn stats(&mut self, stats: &Stats) {
        if self.print_stats {
            log!("{}", stats.summary());
        }
        let _ = self.proxy.send_event(UserEvent::Stats(*stats));
    }
}

struct Running {
    window: Window,
    input: Arc<InputTx>,
    stop: Arc<AtomicBool>,
    shared: Arc<UiShared>,
    net: Option<JoinHandle<()>>,
    mods: ModifiersState,
    pressed: Vec<u16>,
    buttons: u8,
    wheel: (f64, f64),
    title: String,
    show_stats: bool,
    cursor_shape: Option<CursorShape>,
    cursor_scale: f64,
    stopping_since: Option<Instant>,
    fallback_video: (u32, u32),
}

struct App {
    args: Args,
    proxy: EventLoopProxy<UserEvent>,
    running: Option<Running>,
    exit_code: i32,
}

pub fn run(args: &Args) -> i32 {
    let mut builder = EventLoop::<UserEvent>::with_user_event();
    // No default menu: its Cmd+Q / Cmd+H / Cmd+W shortcuts belong to the remote machine.
    builder.with_default_menu(false);
    builder.with_activation_policy(ActivationPolicy::Regular);
    builder.with_activate_ignoring_other_apps(true);
    let event_loop = match builder.build() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: cannot start the UI: {e}");
            return 1;
        }
    };
    let mut app = App { args: args.clone(), proxy: event_loop.create_proxy(), running: None, exit_code: 0 };
    if let Err(e) = event_loop.run_app(&mut app) {
        eprintln!("error: {e}");
        return 1;
    }
    app.exit_code
}

impl App {
    fn start(&mut self, el: &ActiveEventLoop) -> Result<Running, String> {
        let monitor = el.primary_monitor().or_else(|| el.available_monitors().next());
        let fps = if self.args.fps != 0 {
            self.args.fps
        } else {
            // Match this display: more would be wasted, less would add latency.
            let hz = monitor.as_ref().and_then(|m| m.refresh_rate_millihertz()).map(|m| (m + 500) / 1000).unwrap_or(60);
            hz.clamp(30, 240) as u16
        };
        let conn = session::connect(&Options {
            host: self.args.host,
            fps,
            bitrate_kbps: self.args.bitrate_kbps,
            codecs: self.args.codecs,
            max_datagram: self.args.max_datagram,
        })?;
        let w = conn.welcome;
        log!(
            "connected: {}x{} @ {} fps, {}, {:.1} Mbit/s",
            w.width,
            w.height,
            w.fps,
            w.codec.name(),
            w.bitrate_kbps as f64 / 1000.0
        );

        // Pixel-exact when it fits, otherwise the largest size that does.
        let (vw, vh) = (w.width as f64, w.height as f64);
        let mut scale = 1.0f64;
        if let Some(m) = &monitor {
            let s = m.size();
            if s.width > 0 && s.height > 0 {
                scale = scale.min(s.width as f64 * 0.92 / vw).min(s.height as f64 * 0.82 / vh);
            }
        }
        let title = format!("hyperspace - {}", self.args.host_name);
        let mut attrs = Window::default_attributes()
            .with_title(title.clone())
            .with_inner_size(PhysicalSize::new((vw * scale).round().max(320.0) as u32, (vh * scale).round().max(200.0) as u32));
        if self.args.fullscreen {
            attrs = attrs.with_fullscreen(Some(Fullscreen::Borderless(None)));
        }
        let window = el.create_window(attrs).map_err(|e| format!("cannot create window: {e}"))?;

        let layer: Retained<CAMetalLayer> = match window.window_handle().map(|h| h.as_raw()) {
            Ok(RawWindowHandle::AppKit(h)) => unsafe {
                let layer = raw_window_metal::Layer::from_ns_view(h.ns_view);
                Retained::from_raw(layer.into_raw().as_ptr().cast()).ok_or("no Metal layer")?
            },
            _ => return Err("window has no AppKit handle".into()),
        };
        let renderer = Renderer::new(layer)?;

        let shared = Arc::new(UiShared::default());
        let size = window.inner_size();
        shared.surface_w.store(size.width, Ordering::Relaxed);
        shared.surface_h.store(size.height, Ordering::Relaxed);

        let input = Arc::new(InputTx::new(conn.sock.clone()));
        let stop = Arc::new(AtomicBool::new(false));
        let net = {
            let (input, stop, shared, proxy) = (input.clone(), stop.clone(), shared.clone(), self.proxy.clone());
            let (max_frames, print_stats, codec) = (self.args.frames, self.args.stats, w.codec);
            std::thread::Builder::new()
                .name("net-decode-present".into())
                .spawn(move || {
                    let mut h = NetHandler {
                        decoder: Decoder::new(codec),
                        renderer,
                        shared,
                        proxy: proxy.clone(),
                        stop: stop.clone(),
                        max_frames,
                        decoded: 0,
                        print_stats,
                    };
                    let exit = session::receive_loop(&conn, &input, &stop, &mut h, None);
                    let _ = proxy.send_event(UserEvent::Ended { exit, decoded: h.decoded, presented: h.renderer.presented });
                })
                .map_err(|e| format!("cannot start network thread: {e}"))?
        };
        window.focus_window();
        Ok(Running {
            window,
            input,
            stop,
            shared,
            net: Some(net),
            mods: ModifiersState::empty(),
            pressed: Vec::new(),
            buttons: 0,
            wheel: (0.0, 0.0),
            title,
            show_stats: true,
            cursor_shape: None,
            cursor_scale: 0.0,
            stopping_since: None,
            fallback_video: (w.width as u32, w.height as u32),
        })
    }
}

impl Running {
    fn video_size(&self) -> (f64, f64) {
        let (w, h) = (self.shared.video_w.load(Ordering::Relaxed), self.shared.video_h.load(Ordering::Relaxed));
        if w == 0 || h == 0 {
            (self.fallback_video.0 as f64, self.fallback_video.1 as f64)
        } else {
            (w as f64, h as f64)
        }
    }

    /// Video rectangle inside the window, physical pixels.
    fn video_rect(&self) -> (f64, f64, f64, f64) {
        let s = self.window.inner_size();
        let (vw, vh) = self.video_size();
        letterbox(s.width as f64, s.height as f64, vw, vh)
    }

    fn release_all(&mut self) {
        let mut evs: Vec<InputEvent> =
            self.pressed.drain(..).rev().map(|scancode| InputEvent::Key { scancode, down: false }).collect();
        for button in 0..8u8 {
            if self.buttons & (1 << button) != 0 {
                evs.push(InputEvent::Button { button, down: false });
            }
        }
        self.buttons = 0;
        self.input.send_all(&evs);
    }

    fn begin_stop(&mut self, el: &ActiveEventLoop) {
        if self.stopping_since.is_none() {
            self.release_all();
            self.stop.store(true, Ordering::Relaxed);
            self.stopping_since = Some(Instant::now());
            // The network thread says goodbye to the host and reports back;
            // don't wait forever if it cannot.
            el.set_control_flow(ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(700)));
        }
    }

    /// Show the host's cursor image, sized to match the video's on-screen scale.
    fn apply_cursor(&mut self, el: &ActiveEventLoop) {
        let Some(shape) = &self.cursor_shape else { return };
        let (_, _, w, _) = self.video_rect();
        let (vw, _) = self.video_size();
        // Cursor images are sized in points; the video is scaled in pixels.
        let scale = (w / vw / self.window.scale_factor()).clamp(0.1, 4.0);
        let scaled = shape.scaled(scale);
        if let Ok(src) = CustomCursor::from_rgba(scaled.rgba, scaled.width, scaled.height, scaled.hot_x, scaled.hot_y) {
            self.window.set_cursor(el.create_custom_cursor(src));
            self.cursor_scale = scale;
        }
    }

    fn on_window_event(&mut self, el: &ActiveEventLoop, event: WindowEvent, cmd_as_ctrl: bool) {
        match event {
            WindowEvent::CloseRequested => self.begin_stop(el),
            WindowEvent::Resized(size) => {
                self.shared.surface_w.store(size.width, Ordering::Relaxed);
                self.shared.surface_h.store(size.height, Ordering::Relaxed);
                let (_, _, w, _) = self.video_rect();
                let scale = w / self.video_size().0 / self.window.scale_factor();
                if self.cursor_shape.is_some() && (scale / self.cursor_scale.max(1e-6) - 1.0).abs() > 0.08 {
                    self.apply_cursor(el);
                }
            }
            WindowEvent::Occluded(o) => self.shared.occluded.store(o, Ordering::Relaxed),
            WindowEvent::Focused(false) => self.release_all(),
            WindowEvent::ModifiersChanged(m) => self.mods = m.state(),
            WindowEvent::CursorMoved { position, .. } => {
                let (x, y, w, h) = self.video_rect();
                if w > 0.0 && h > 0.0 {
                    let nx = ((position.x - x) / w).clamp(0.0, 1.0);
                    let ny = ((position.y - y) / h).clamp(0.0, 1.0);
                    self.input.send(InputEvent::MouseAbs { x: (nx * 65535.0).round() as u16, y: (ny * 65535.0).round() as u16 });
                }
            }
            WindowEvent::MouseInput { state, button, .. } => {
                let b = match button {
                    MouseButton::Left => 0u8,
                    MouseButton::Right => 1,
                    MouseButton::Middle => 2,
                    MouseButton::Back => 3,
                    MouseButton::Forward => 4,
                    MouseButton::Other(_) => return,
                };
                let down = state == ElementState::Pressed;
                if down {
                    self.buttons |= 1 << b;
                } else {
                    self.buttons &= !(1 << b);
                }
                self.input.send(InputEvent::Button { button: b, down });
            }
            WindowEvent::MouseWheel { delta, .. } => {
                // Host units: 120 per wheel detent, positive = up / right.
                let (dx, dy) = match delta {
                    MouseScrollDelta::LineDelta(x, y) => (-(x as f64) * 120.0, y as f64 * 120.0),
                    MouseScrollDelta::PixelDelta(p) => {
                        let k = 1.5 / self.window.scale_factor();
                        (-p.x * k, p.y * k)
                    }
                };
                self.wheel.0 += dx;
                self.wheel.1 += dy;
                let (ix, iy) = (self.wheel.0.trunc(), self.wheel.1.trunc());
                if ix != 0.0 || iy != 0.0 {
                    self.wheel.0 -= ix;
                    self.wheel.1 -= iy;
                    self.input.send(InputEvent::Wheel {
                        dx: ix.clamp(-32000.0, 32000.0) as i16,
                        dy: iy.clamp(-32000.0, 32000.0) as i16,
                    });
                }
            }
            WindowEvent::KeyboardInput { event, is_synthetic, .. } => {
                if is_synthetic {
                    return;
                }
                let down = event.state == ElementState::Pressed;
                // Local shortcuts: Ctrl+Option+Cmd + letter (by the letter the
                // layout prints, so they work on any keyboard layout).
                if down && self.mods.control_key() && self.mods.alt_key() && self.mods.super_key() {
                    if let Key::Character(c) = event.key_without_modifiers() {
                        match c.to_lowercase().as_str() {
                            "q" => return self.begin_stop(el),
                            "f" => {
                                if !event.repeat {
                                    let fs = self.window.fullscreen().is_some();
                                    self.window.set_fullscreen((!fs).then_some(Fullscreen::Borderless(None)));
                                }
                                return;
                            }
                            "s" => {
                                if !event.repeat {
                                    self.show_stats = !self.show_stats;
                                    if !self.show_stats {
                                        self.window.set_title(&self.title);
                                    }
                                }
                                return;
                            }
                            _ => {}
                        }
                    }
                }
                let PhysicalKey::Code(code) = event.physical_key else { return };
                let Some(sc) = scancode(code, cmd_as_ctrl) else { return };
                if sc == SC_CAPS {
                    // macOS reports Caps Lock as one event per toggle (down when
                    // it turns on, up when it turns off); the host wants a tap each time.
                    self.input.send_all(&[
                        InputEvent::Key { scancode: sc, down: true },
                        InputEvent::Key { scancode: sc, down: false },
                    ]);
                    return;
                }
                if down {
                    if !self.pressed.contains(&sc) {
                        self.pressed.push(sc);
                    }
                } else if let Some(i) = self.pressed.iter().position(|&k| k == sc) {
                    self.pressed.swap_remove(i);
                } else {
                    return; // release of a key we never forwarded (local shortcut)
                }
                self.input.send(InputEvent::Key { scancode: sc, down });
            }
            _ => {}
        }
    }
}

impl ApplicationHandler<UserEvent> for App {
    fn resumed(&mut self, el: &ActiveEventLoop) {
        if self.running.is_some() {
            return;
        }
        match self.start(el) {
            Ok(r) => self.running = Some(r),
            Err(e) => {
                eprintln!("error: {e}");
                self.exit_code = 1;
                el.exit();
            }
        }
    }

    fn window_event(&mut self, el: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        let cmd_as_ctrl = self.args.cmd_as_ctrl;
        if let Some(r) = self.running.as_mut() {
            r.on_window_event(el, event, cmd_as_ctrl);
        }
    }

    fn user_event(&mut self, el: &ActiveEventLoop, event: UserEvent) {
        let Some(r) = self.running.as_mut() else { return };
        match event {
            UserEvent::Cursor(shape) => {
                r.cursor_shape = Some(shape);
                r.apply_cursor(el);
            }
            UserEvent::CursorVisible(v) => r.window.set_cursor_visible(v),
            UserEvent::Stats(s) => {
                if r.show_stats {
                    r.window.set_title(&format!("{} - {}", r.title, s.summary()));
                }
            }
            UserEvent::Ended { exit, decoded, presented } => {
                if let Some(t) = r.net.take() {
                    let _ = t.join();
                }
                log!("{} ({decoded} frames decoded, {presented} presented)", exit.describe());
                let wanted = self.args.frames;
                self.exit_code = match (&exit, wanted) {
                    (Exit::Local, Some(n)) if decoded < n => 1,
                    (Exit::Local, _) => 0,
                    (Exit::Host(hyperspace_proto::wire::bye::QUIT), None) => 0,
                    _ => 1,
                };
                if self.exit_code == 0 && wanted.is_some() {
                    println!("CLIENT OK decoded={decoded} presented={presented}");
                }
                el.exit();
            }
        }
    }

    fn about_to_wait(&mut self, el: &ActiveEventLoop) {
        if let Some(r) = &self.running {
            if r.stopping_since.is_some_and(|t| t.elapsed() > Duration::from_millis(600)) {
                el.exit();
            }
        }
    }
}
