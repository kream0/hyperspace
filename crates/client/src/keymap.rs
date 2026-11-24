//! Physical key -> PC "set 1" scancode. Keys are forwarded by position, so
//! the host's keyboard layout decides which character each key produces.

use winit::keyboard::KeyCode;

/// Extended-key flag (0xE0 prefix) understood by the host.
pub const EXT: u16 = 0x100;

pub const SC_LCTRL: u16 = 0x1d;
pub const SC_RCTRL: u16 = EXT | 0x1d;
pub const SC_CAPS: u16 = 0x3a;

pub fn scancode(key: KeyCode, cmd_as_ctrl: bool) -> Option<u16> {
    use KeyCode::*;
    Some(match key {
        Escape => 0x01,
        Digit1 => 0x02,
        Digit2 => 0x03,
        Digit3 => 0x04,
        Digit4 => 0x05,
        Digit5 => 0x06,
        Digit6 => 0x07,
        Digit7 => 0x08,
        Digit8 => 0x09,
        Digit9 => 0x0a,
        Digit0 => 0x0b,
        Minus => 0x0c,
        Equal => 0x0d,
        Backspace => 0x0e,
        Tab => 0x0f,
        KeyQ => 0x10,
        KeyW => 0x11,
        KeyE => 0x12,
        KeyR => 0x13,
        KeyT => 0x14,
        KeyY => 0x15,
        KeyU => 0x16,
        KeyI => 0x17,
        KeyO => 0x18,
        KeyP => 0x19,
        BracketLeft => 0x1a,
        BracketRight => 0x1b,
        Enter => 0x1c,
        ControlLeft => SC_LCTRL,
        KeyA => 0x1e,
        KeyS => 0x1f,
        KeyD => 0x20,
        KeyF => 0x21,
        KeyG => 0x22,
        KeyH => 0x23,
        KeyJ => 0x24,
        KeyK => 0x25,
        KeyL => 0x26,
        Semicolon => 0x27,
        Quote => 0x28,
        Backquote => 0x29,
        ShiftLeft => 0x2a,
        Backslash => 0x2b,
        KeyZ => 0x2c,
        KeyX => 0x2d,
        KeyC => 0x2e,
        KeyV => 0x2f,
        KeyB => 0x30,
        KeyN => 0x31,
        KeyM => 0x32,
        Comma => 0x33,
        Period => 0x34,
        Slash => 0x35,
        ShiftRight => 0x36,
        NumpadMultiply => 0x37,
        AltLeft => 0x38,
        Space => 0x39,
        CapsLock => SC_CAPS,
        F1 => 0x3b,
        F2 => 0x3c,
        F3 => 0x3d,
        F4 => 0x3e,
        F5 => 0x3f,
        F6 => 0x40,
        F7 => 0x41,
        F8 => 0x42,
        F9 => 0x43,
        F10 => 0x44,
        NumLock => 0x45,
        ScrollLock => 0x46,
        Numpad7 => 0x47,
        Numpad8 => 0x48,
        Numpad9 => 0x49,
        NumpadSubtract => 0x4a,
        Numpad4 => 0x4b,
        Numpad5 => 0x4c,
        Numpad6 => 0x4d,
        NumpadAdd => 0x4e,
        Numpad1 => 0x4f,
        Numpad2 => 0x50,
        Numpad3 => 0x51,
        Numpad0 => 0x52,
        NumpadDecimal => 0x53,
        IntlBackslash => 0x56,
        F11 => 0x57,
        F12 => 0x58,
        NumpadEqual => 0x59,
        F13 => 0x64,
        F14 => 0x65,
        F15 => 0x66,
        F16 => 0x67,
        F17 => 0x68,
        F18 => 0x69,
        F19 => 0x6a,
        F20 => 0x6b,
        F21 => 0x6c,
        F22 => 0x6d,
        F23 => 0x6e,
        F24 => 0x76,
        IntlRo => 0x73,
        IntlYen => 0x7d,
        NumpadComma => 0x7e,

        MediaTrackPrevious => EXT | 0x10,
        MediaTrackNext => EXT | 0x19,
        NumpadEnter => EXT | 0x1c,
        ControlRight => SC_RCTRL,
        AudioVolumeMute => EXT | 0x20,
        MediaPlayPause => EXT | 0x22,
        MediaStop => EXT | 0x24,
        AudioVolumeDown => EXT | 0x2e,
        AudioVolumeUp => EXT | 0x30,
        NumpadDivide => EXT | 0x35,
        PrintScreen => EXT | 0x37,
        AltRight => EXT | 0x38,
        Home => EXT | 0x47,
        ArrowUp => EXT | 0x48,
        PageUp => EXT | 0x49,
        ArrowLeft => EXT | 0x4b,
        ArrowRight => EXT | 0x4d,
        End => EXT | 0x4f,
        ArrowDown => EXT | 0x50,
        PageDown => EXT | 0x51,
        Insert => EXT | 0x52,
        Delete => EXT | 0x53,
        // Command: the Windows key by default (same position), or Ctrl so that
        // Cmd+C / Cmd+V muscle memory keeps working.
        SuperLeft => {
            if cmd_as_ctrl {
                SC_LCTRL
            } else {
                EXT | 0x5b
            }
        }
        SuperRight => {
            if cmd_as_ctrl {
                SC_RCTRL
            } else {
                EXT | 0x5c
            }
        }
        ContextMenu => EXT | 0x5d,
        _ => return None,
    })
}
