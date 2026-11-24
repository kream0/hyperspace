//! Input events and the redundant-send queue that makes them reliable without
//! retransmit timers: every INPUT datagram carries all not-yet-acked events.

use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputEvent {
    /// Absolute pointer position, normalized to 0..=65535 over the captured display.
    MouseAbs { x: u16, y: u16 },
    /// Relative pointer motion in host pixels.
    MouseRel { dx: i16, dy: i16 },
    /// 0 = left, 1 = right, 2 = middle, 3 = back, 4 = forward.
    Button { button: u8, down: bool },
    /// Wheel motion in Windows units (120 = one detent). `dy > 0` scrolls up,
    /// `dx > 0` scrolls right.
    Wheel { dx: i16, dy: i16 },
    /// PC "set 1" scancode; extended keys have bit 0x100 set (0xE0 prefix).
    Key { scancode: u16, down: bool },
}

impl InputEvent {
    pub fn encode(&self) -> (u8, [u8; 4]) {
        fn two(a: [u8; 2], b: [u8; 2]) -> [u8; 4] {
            [a[0], a[1], b[0], b[1]]
        }
        match *self {
            InputEvent::MouseAbs { x, y } => (1, two(x.to_le_bytes(), y.to_le_bytes())),
            InputEvent::MouseRel { dx, dy } => (2, two(dx.to_le_bytes(), dy.to_le_bytes())),
            InputEvent::Button { button, down } => (3, [button, down as u8, 0, 0]),
            InputEvent::Wheel { dx, dy } => (4, two(dx.to_le_bytes(), dy.to_le_bytes())),
            InputEvent::Key { scancode, down } => {
                let s = scancode.to_le_bytes();
                (5, [s[0], s[1], down as u8, 0])
            }
        }
    }

    pub fn decode(kind: u8, p: [u8; 4]) -> Option<InputEvent> {
        let a = [p[0], p[1]];
        let b = [p[2], p[3]];
        Some(match kind {
            1 => InputEvent::MouseAbs { x: u16::from_le_bytes(a), y: u16::from_le_bytes(b) },
            2 => InputEvent::MouseRel { dx: i16::from_le_bytes(a), dy: i16::from_le_bytes(b) },
            3 => InputEvent::Button { button: p[0], down: p[1] != 0 },
            4 => InputEvent::Wheel { dx: i16::from_le_bytes(a), dy: i16::from_le_bytes(b) },
            5 => InputEvent::Key { scancode: u16::from_le_bytes(a), down: p[2] != 0 },
            _ => return None,
        })
    }
}

/// Sender side. Sequence numbers increase monotonically (gaps allowed).
#[derive(Debug)]
pub struct InputQueue {
    next_seq: u32,
    unacked: VecDeque<(u32, InputEvent)>,
}

/// Events beyond this many unacked are dropped oldest-first; the peer is
/// clearly unreachable at that point.
const MAX_UNACKED: usize = 128;

impl Default for InputQueue {
    fn default() -> Self {
        Self { next_seq: 1, unacked: VecDeque::new() }
    }
}

impl InputQueue {
    pub fn push(&mut self, ev: InputEvent) {
        // Absolute moves are idempotent: a newer one supersedes an unacked older one.
        if let (InputEvent::MouseAbs { .. }, Some((_, InputEvent::MouseAbs { .. }))) = (&ev, self.unacked.back()) {
            self.unacked.pop_back();
        }
        if self.unacked.len() >= MAX_UNACKED {
            self.unacked.pop_front();
        }
        self.unacked.push_back((self.next_seq, ev));
        self.next_seq = self.next_seq.wrapping_add(1);
    }

    pub fn ack(&mut self, seq: u32) {
        while let Some(&(s, _)) = self.unacked.front() {
            if seq_le(s, seq) {
                self.unacked.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn has_unacked(&self) -> bool {
        !self.unacked.is_empty()
    }

    /// Encode an INPUT datagram with every unacked event (oldest first).
    /// Returns false if there is nothing to send.
    pub fn encode(&self, out: &mut Vec<u8>) -> bool {
        if self.unacked.is_empty() {
            return false;
        }
        // Keep the datagram small: the newest 120 events at most.
        let skip = self.unacked.len().saturating_sub(120);
        crate::wire::input(out, self.unacked.iter().skip(skip));
        true
    }
}

#[inline]
fn seq_le(a: u32, b: u32) -> bool {
    (b.wrapping_sub(a) as i32) >= 0
}

/// Receiver side: filters duplicates/reordering.
#[derive(Debug, Default)]
pub struct InputReceiver {
    last: u32,
}

impl InputReceiver {
    /// True if the event is new and must be applied.
    pub fn accept(&mut self, seq: u32) -> bool {
        if (seq.wrapping_sub(self.last) as i32) > 0 {
            self.last = seq;
            true
        } else {
            false
        }
    }
    pub fn last(&self) -> u32 {
        self.last
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{parse, Packet};

    fn deliver(q: &InputQueue, rx: &mut InputReceiver, applied: &mut Vec<InputEvent>) {
        let mut buf = Vec::new();
        if !q.encode(&mut buf) {
            return;
        }
        match parse(&buf) {
            Some(Packet::Input(evs)) => {
                for (seq, ev) in evs.iter() {
                    if rx.accept(seq) {
                        applied.push(ev);
                    }
                }
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn event_roundtrip() {
        for ev in [
            InputEvent::MouseAbs { x: 65535, y: 1 },
            InputEvent::MouseRel { dx: -300, dy: 12 },
            InputEvent::Button { button: 4, down: true },
            InputEvent::Wheel { dx: -120, dy: 240 },
            InputEvent::Key { scancode: 0x11d, down: false },
        ] {
            let (k, p) = ev.encode();
            assert_eq!(InputEvent::decode(k, p), Some(ev));
        }
    }

    #[test]
    fn lost_datagrams_are_recovered_in_order_exactly_once() {
        let mut q = InputQueue::default();
        let mut rx = InputReceiver::default();
        let mut applied = Vec::new();
        let k = |s, d| InputEvent::Key { scancode: s, down: d };

        q.push(k(30, true)); // datagram lost
        q.push(k(30, false));
        deliver(&q, &mut rx, &mut applied); // carries both
        deliver(&q, &mut rx, &mut applied); // duplicate datagram
        assert_eq!(applied, vec![k(30, true), k(30, false)]);
        q.ack(rx.last());
        assert!(!q.has_unacked());

        q.push(InputEvent::MouseRel { dx: 1, dy: 1 });
        deliver(&q, &mut rx, &mut applied);
        q.push(InputEvent::MouseRel { dx: 2, dy: 2 });
        deliver(&q, &mut rx, &mut applied); // carries both, first must not re-apply
        assert_eq!(applied.len(), 4);
    }

    #[test]
    fn absolute_moves_coalesce() {
        let mut q = InputQueue::default();
        let mut rx = InputReceiver::default();
        let mut applied = Vec::new();
        q.push(InputEvent::MouseAbs { x: 1, y: 1 });
        deliver(&q, &mut rx, &mut applied);
        q.push(InputEvent::MouseAbs { x: 2, y: 2 });
        q.push(InputEvent::MouseAbs { x: 3, y: 3 });
        deliver(&q, &mut rx, &mut applied);
        assert_eq!(applied, vec![InputEvent::MouseAbs { x: 1, y: 1 }, InputEvent::MouseAbs { x: 3, y: 3 }]);
        // a click between moves prevents coalescing across it
        q.push(InputEvent::Button { button: 0, down: true });
        q.push(InputEvent::MouseAbs { x: 4, y: 4 });
        deliver(&q, &mut rx, &mut applied);
        assert_eq!(applied.len(), 4);
    }
}
