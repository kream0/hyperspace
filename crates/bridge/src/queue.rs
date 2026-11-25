//! The outgoing queue of one relay link, bounded in bytes and in messages.
//!
//! Datagrams are dropped when it is full, as a congested UDP path would drop
//! them: the streaming protocol recovers from loss, not from a growing delay.
//! Control messages (a few bytes each) always get in.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// Datagrams [`Tx::push`] refused, the queue being full.
    dropped: AtomicU64,
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
        dropped: AtomicU64::new(0),
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
                inner.dropped.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            s.bytes += msg.len();
            s.items.push_back(msg);
        }
        inner.ready.notify_one();
        true
    }

    /// Datagrams [`push`](Tx::push) dropped so far because the queue was
    /// full. Control messages are not counted.
    pub fn dropped(&self) -> u64 {
        self.0.dropped.load(Ordering::Relaxed)
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

#[cfg(test)]
mod tests {
    use super::*;
    use hyperspace_proto::relay::{self, Msg};

    /// Pushes `n` copies of `msg`; how many got in.
    fn push_n(tx: &Tx, msg: &[u8], n: usize) -> usize {
        (0..n).filter(|_| tx.push(msg.to_vec())).count()
    }

    #[test]
    fn a_full_queue_counts_every_datagram_it_drops() {
        // The link's own bounds, with the host's datagrams: big ones fill
        // the bytes first, small ones the count.
        for len in [relay::MAX_PAYLOAD, 1200, 40] {
            let (tx, rx) = queue(MAX_COUNT, MAX_BYTES);
            let msg = Msg::HostData { peer: 1, payload: &vec![7; len] }.encode();
            let fit = (MAX_BYTES / msg.len()).min(MAX_COUNT);
            assert_eq!(push_n(&tx, &msg, fit + 300), fit, "{len}-byte payloads");
            assert_eq!(rx.len(), (fit, fit * msg.len()));
            assert_eq!(tx.dropped(), 300, "{len}-byte payloads");
        }
    }

    #[test]
    fn the_drop_count_follows_the_queue() {
        let (tx, rx) = queue(4, 1000);
        assert_eq!(tx.dropped(), 0);
        // Full by count.
        assert_eq!(push_n(&tx, &[0; 10], 7), 4);
        assert_eq!(tx.dropped(), 3);
        // Control messages get in past the bound, and are never counted.
        assert!(tx.push_control(vec![1; 10]));
        assert_eq!(tx.dropped(), 3);
        // Room again once the writer takes some: no new drop until full again.
        assert!(rx.try_recv().is_some() && rx.try_recv().is_some());
        assert!(tx.push(vec![0; 10]));
        assert_eq!(tx.dropped(), 3);
        assert!(!tx.push(vec![0; 10]));
        assert_eq!(tx.dropped(), 4);
        while rx.try_recv().is_some() {}
        // Full by bytes: 600 + 600 is over 1000, 600 + 400 is not.
        assert!(tx.push(vec![0; 600]));
        assert!(!tx.push(vec![0; 600]));
        assert!(tx.push(vec![0; 400]));
        assert!(!tx.push(vec![0; 1]));
        // Every sender shares the count.
        assert!(!tx.clone().push(vec![0; 1]));
        assert_eq!(tx.dropped(), 7);
    }
}
