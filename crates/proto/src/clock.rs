//! Monotonic microsecond clock shared by host and client code.

use std::sync::OnceLock;
use std::time::Instant;

static EPOCH: OnceLock<Instant> = OnceLock::new();

/// Microseconds since the first call in this process. Monotonic.
#[inline]
pub fn now_us() -> u64 {
    EPOCH.get_or_init(Instant::now).elapsed().as_micros() as u64
}

/// NTP-style clock offset estimator. Keeps the sample with the lowest RTT in a
/// sliding window, which is the one least distorted by queueing.
#[derive(Debug, Clone)]
pub struct ClockSync {
    samples: [(u64, i64); 16],
    n: usize,
    idx: usize,
}

impl Default for ClockSync {
    fn default() -> Self {
        Self { samples: [(u64::MAX, 0); 16], n: 0, idx: 0 }
    }
}

impl ClockSync {
    /// `t_send`/`t_recv` are local times, `t_peer` is the peer's clock when it
    /// answered.
    pub fn add_sample(&mut self, t_send: u64, t_peer: u64, t_recv: u64) {
        let rtt = t_recv.saturating_sub(t_send);
        let mid = t_send + rtt / 2;
        let offset = t_peer as i64 - mid as i64;
        self.samples[self.idx] = (rtt, offset);
        self.idx = (self.idx + 1) % self.samples.len();
        self.n = (self.n + 1).min(self.samples.len());
    }

    fn best(&self) -> Option<(u64, i64)> {
        self.samples[..self.n].iter().copied().min_by_key(|s| s.0)
    }

    /// Lowest RTT seen in the window, microseconds.
    pub fn rtt_us(&self) -> Option<u64> {
        self.best().map(|s| s.0)
    }

    /// peer_clock - local_clock, microseconds.
    pub fn offset_us(&self) -> Option<i64> {
        self.best().map(|s| s.1)
    }

    /// Convert a peer timestamp into the local clock domain.
    pub fn peer_to_local(&self, t_peer: u64) -> Option<u64> {
        self.offset_us().map(|o| (t_peer as i64 - o).max(0) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_from_best_rtt() {
        let mut c = ClockSync::default();
        // peer clock = local + 1_000_000; rtt 2000 symmetric
        c.add_sample(10_000, 1_011_000, 12_000);
        // a jittery sample (asymmetric delay) with larger rtt must not win
        c.add_sample(20_000, 1_029_000, 30_000);
        assert_eq!(c.rtt_us(), Some(2000));
        assert_eq!(c.offset_us(), Some(1_000_000));
        assert_eq!(c.peer_to_local(1_500_000), Some(500_000));
    }
}
