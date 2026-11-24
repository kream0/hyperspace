//! Input injection through SendInput.

use crate::inject::{HeldState, Injector};
use hyperspace_proto::input::InputEvent;
use windows::Win32::UI::Input::KeyboardAndMouse::*;
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};

const XBUTTON1: u32 = 1;
const XBUTTON2: u32 = 2;

pub struct WinInjector {
    held: HeldState,
    /// Captured display in virtual-desktop pixels.
    rect: (i32, i32, i32, i32),
    count: u64,
}

impl WinInjector {
    pub fn new() -> Self {
        let rect = unsafe { (0, 0, GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN)) };
        Self { held: HeldState::default(), rect, count: 0 }
    }

    fn mouse(&self, dx: i32, dy: i32, data: i32, flags: MOUSE_EVENT_FLAGS) {
        let input = INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT { dx, dy, mouseData: data as u32, dwFlags: flags, time: 0, dwExtraInfo: 0 },
            },
        };
        unsafe {
            SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
        }
    }

    fn apply(&self, ev: InputEvent) {
        match ev {
            InputEvent::MouseAbs { x, y } => {
                // Normalized over the captured display -> normalized over the
                // whole virtual desktop, which is what SendInput wants.
                let (vx, vy, vw, vh) = unsafe {
                    (
                        GetSystemMetrics(SM_XVIRTUALSCREEN),
                        GetSystemMetrics(SM_YVIRTUALSCREEN),
                        GetSystemMetrics(SM_CXVIRTUALSCREEN).max(2),
                        GetSystemMetrics(SM_CYVIRTUALSCREEN).max(2),
                    )
                };
                let (l, t, w, h) = self.rect;
                let px = l as f64 + x as f64 / 65535.0 * (w.max(1) - 1) as f64;
                let py = t as f64 + y as f64 / 65535.0 * (h.max(1) - 1) as f64;
                let nx = ((px - vx as f64) * 65535.0 / (vw - 1) as f64).round() as i32;
                let ny = ((py - vy as f64) * 65535.0 / (vh - 1) as f64).round() as i32;
                self.mouse(
                    nx.clamp(0, 65535),
                    ny.clamp(0, 65535),
                    0,
                    MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                );
            }
            InputEvent::MouseRel { dx, dy } => self.mouse(dx as i32, dy as i32, 0, MOUSEEVENTF_MOVE),
            InputEvent::Button { button, down } => {
                let (flags, data) = match (button, down) {
                    (0, true) => (MOUSEEVENTF_LEFTDOWN, 0),
                    (0, false) => (MOUSEEVENTF_LEFTUP, 0),
                    (1, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
                    (1, false) => (MOUSEEVENTF_RIGHTUP, 0),
                    (2, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
                    (2, false) => (MOUSEEVENTF_MIDDLEUP, 0),
                    (3, true) => (MOUSEEVENTF_XDOWN, XBUTTON1),
                    (3, false) => (MOUSEEVENTF_XUP, XBUTTON1),
                    (4, true) => (MOUSEEVENTF_XDOWN, XBUTTON2),
                    (4, false) => (MOUSEEVENTF_XUP, XBUTTON2),
                    _ => return,
                };
                self.mouse(0, 0, data as i32, flags);
            }
            InputEvent::Wheel { dx, dy } => {
                if dy != 0 {
                    self.mouse(0, 0, dy as i32, MOUSEEVENTF_WHEEL);
                }
                if dx != 0 {
                    self.mouse(0, 0, dx as i32, MOUSEEVENTF_HWHEEL);
                }
            }
            InputEvent::Key { scancode, down } => {
                let mut flags = KEYEVENTF_SCANCODE;
                if scancode & 0x100 != 0 {
                    flags |= KEYEVENTF_EXTENDEDKEY;
                }
                if !down {
                    flags |= KEYEVENTF_KEYUP;
                }
                let input = INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: VIRTUAL_KEY(0),
                            wScan: scancode & 0xff,
                            dwFlags: flags,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                };
                unsafe {
                    SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
                }
            }
        }
    }
}

impl Injector for WinInjector {
    fn set_desktop_rect(&mut self, rect: (i32, i32, i32, i32)) {
        self.rect = rect;
    }

    fn inject(&mut self, ev: InputEvent) {
        self.held.track(&ev);
        self.count += 1;
        self.apply(ev);
    }

    fn release_all(&mut self) {
        for ev in self.held.drain_releases() {
            self.apply(ev);
        }
    }

    fn injected(&self) -> u64 {
        self.count
    }
}
