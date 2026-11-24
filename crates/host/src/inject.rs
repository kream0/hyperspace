//! Remote input injection.

use hyperspace_proto::input::InputEvent;

pub trait Injector {
    /// Display rectangle (left, top, width, height) absolute pointer events map onto.
    fn set_desktop_rect(&mut self, rect: (i32, i32, i32, i32));
    fn inject(&mut self, ev: InputEvent);
    /// Release every key and button still held (called when a session ends so
    /// nothing stays stuck).
    fn release_all(&mut self);
    fn injected(&self) -> u64;
}

/// Tracks which keys / buttons are down so they can be released on disconnect.
#[derive(Default)]
#[cfg_attr(not(windows), allow(dead_code))]
pub struct HeldState {
    keys: Vec<u16>,
    buttons: u8,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl HeldState {
    pub fn track(&mut self, ev: &InputEvent) {
        match *ev {
            InputEvent::Key { scancode, down } => {
                self.keys.retain(|&k| k != scancode);
                if down {
                    self.keys.push(scancode);
                }
            }
            InputEvent::Button { button, down } if button < 8 => {
                if down {
                    self.buttons |= 1 << button;
                } else {
                    self.buttons &= !(1 << button);
                }
            }
            _ => {}
        }
    }

    /// Events that release everything currently held; clears the state.
    pub fn drain_releases(&mut self) -> Vec<InputEvent> {
        let mut out: Vec<InputEvent> =
            self.keys.drain(..).rev().map(|scancode| InputEvent::Key { scancode, down: false }).collect();
        for button in 0..8 {
            if self.buttons & (1 << button) != 0 {
                out.push(InputEvent::Button { button, down: false });
            }
        }
        self.buttons = 0;
        out
    }
}

/// Used where injection is unavailable (non-Windows builds, `--view-only`).
#[derive(Default)]
pub struct NullInjector {
    count: u64,
    log: bool,
}

impl NullInjector {
    pub fn new(log: bool) -> Self {
        Self { count: 0, log }
    }
}

impl Injector for NullInjector {
    fn set_desktop_rect(&mut self, _rect: (i32, i32, i32, i32)) {}
    fn inject(&mut self, ev: InputEvent) {
        self.count += 1;
        if self.log {
            hyperspace_proto::log!("input: {ev:?}");
        }
    }
    fn release_all(&mut self) {}
    fn injected(&self) -> u64 {
        self.count
    }
}

pub fn new_injector(view_only: bool) -> Box<dyn Injector> {
    if view_only {
        return Box::new(NullInjector::new(false));
    }
    #[cfg(windows)]
    {
        Box::new(crate::win::input::WinInjector::new())
    }
    #[cfg(not(windows))]
    {
        Box::new(NullInjector::new(std::env::var_os("HYPERSPACE_LOG_INPUT").is_some()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn held_state_releases_everything_once() {
        let mut h = HeldState::default();
        h.track(&InputEvent::Key { scancode: 0x1d, down: true });
        h.track(&InputEvent::Key { scancode: 0x1e, down: true });
        h.track(&InputEvent::Key { scancode: 0x1e, down: true }); // auto-repeat
        h.track(&InputEvent::Key { scancode: 0x2a, down: true });
        h.track(&InputEvent::Key { scancode: 0x2a, down: false });
        h.track(&InputEvent::Button { button: 0, down: true });
        h.track(&InputEvent::Button { button: 1, down: true });
        h.track(&InputEvent::Button { button: 1, down: false });
        let rel = h.drain_releases();
        assert_eq!(
            rel,
            vec![
                InputEvent::Key { scancode: 0x1e, down: false },
                InputEvent::Key { scancode: 0x1d, down: false },
                InputEvent::Button { button: 0, down: false },
            ]
        );
        assert!(h.drain_releases().is_empty());
    }
}
