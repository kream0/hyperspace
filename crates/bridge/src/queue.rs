//! The outgoing queue of one relay link, bounded in bytes and in messages.
//!
//! Datagrams are dropped when it is full, as a congested UDP path would drop
//! them: the streaming protocol recovers from loss, not from a growing delay.
//! Control messages (a few bytes each) always get in.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::Notify;

/// About half a second of video at the rates the host streams at.
pub const MAX_BYTES: usize = 512 * 1024;
pub const MAX_COUNT: usize = 1024;
/// Room kept for control messages beyond [`MAX_COUNT`].
const CONTROL_SLACK: usize = 64;

struct State {
    items: VecDeque<Vec<u8>>,
    bytes: usize,
}

struct Inner {
    state: Mutex<State>,
    ready: Notify,
    max_bytes: usize,
    max_count: usize,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[derive(Clone)]
pub struct Tx(Arc<Inner>);

/// Single consumer: the link's writer.
pub struct Rx(Arc<Inner>);

pub fn queue(max_count: usize, max_bytes: usize) -> (Tx, Rx) {
    let inner = Arc::new(Inner {
        state: Mutex::new(State { items: VecDeque::new(), bytes: 0 }),
        ready: Notify::new(),
        max_bytes,
        max_count,
    });
    (Tx(inner.clone()), Rx(inner))
}

impl Tx {
    /// Queues an encoded datagram message; false if it was dropped because
    /// the queue is full.
    pub fn push(&self, msg: Vec<u8>) -> bool {
        let inner = &*self.0;
        {
            let mut s = inner.lock();
            if s.items.len() >= inner.max_count || s.bytes + msg.len() > inner.max_bytes {
                return false;
            }
            s.bytes += msg.len();
            s.items.push_back(msg);
        }
        inner.ready.notify_one();
        true
    }

    /// Queues a control message, past the datagram limits.
    pub fn push_control(&self, msg: Vec<u8>) -> bool {
        let inner = &*self.0;
        {
            let mut s = inner.lock();
            if s.items.len() >= inner.max_count + CONTROL_SLACK {
                return false;
            }
            s.bytes += msg.len();
            s.items.push_back(msg);
        }
        inner.ready.notify_one();
        true
    }
}

impl Rx {
    pub fn try_recv(&self) -> Option<Vec<u8>> {
        let mut s = self.0.lock();
        let msg = s.items.pop_front()?;
        s.bytes -= msg.len();
        Some(msg)
    }

    /// Waits for the next message. With a single consumer, a push that
    /// happens between the check and the wait leaves a permit in the Notify,
    /// so no wakeup is lost.
    pub async fn recv(&self) -> Vec<u8> {
        loop {
            if let Some(msg) = self.try_recv() {
                return msg;
            }
            self.0.ready.notified().await;
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> (usize, usize) {
        let s = self.0.lock();
        (s.items.len(), s.bytes)
    }
}
