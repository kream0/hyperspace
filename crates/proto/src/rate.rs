//! Receiver-driven bitrate control.
//!
//! The stream has no jitter buffer to hide congestion behind, so the client
//! watches for its earliest signs - frames arriving later than they used to,
//! repairs, unrecoverable loss - and asks the host for a lower bitrate before
//! the delay becomes visible, then probes back up while the path keeps up.

/// What the receiver observed during one interval (about a second).
#[derive(Clone, Copy, Debug, Default)]
pub struct Sample {
    pub frames: u64,
    /// Mean and minimum of (arrival - capture) over the interval, same clock.
    pub delay_avg_us: Option<u64>,
    pub delay_min_us: Option<u64>,
    /// Frames lost for good (a keyframe was needed).
    pub dropped: u64,
    /// Retransmission requests sent.
    pub nacks: u64,
    pub rtt_us: u64,
}

#[derive(Debug)]
pub struct RateControl {
    current: u32,
    requested: u32,
    min: u32,
    max: u32,
    /// Delay of an uncongested path, tracked as a slowly rising minimum.
    base_delay_us: Option<u64>,
    clean_intervals: u32,
}

impl RateControl {
    /// `max == 0` disables control (the source has no adjustable bitrate).
    pub fn new(start_kbps: u32, max_kbps: u32) -> RateControl {
        let max = max_kbps.max(start_kbps);
        RateControl {
            current: start_kbps,
            requested: start_kbps,
            min: 1_000.min(start_kbps.max(1)),
            max: if max_kbps == 0 { 0 } else { max },
            base_delay_us: None,
            clean_intervals: 0,
        }
    }

    pub fn current_kbps(&self) -> u32 {
        self.current
    }

    /// Feed one interval; returns a bitrate to request from the host, if it
    /// should change.
    pub fn update(&mut self, s: &Sample) -> Option<u32> {
        if self.max == 0 || s.frames == 0 {
            return None;
        }
        if let Some(min) = s.delay_min_us {
            // Let the baseline creep up so a route change is eventually forgotten.
            let crept = self.base_delay_us.map(|b| b + 300);
            self.base_delay_us = Some(crept.map_or(min, |b| b.min(min)));
        }
        let queued = match (s.delay_avg_us, self.base_delay_us) {
            (Some(avg), Some(base)) => avg.saturating_sub(base),
            _ => 0,
        };
        let queue_limit = (2 * s.rtt_us).clamp(25_000, 150_000);

        if s.dropped > 0 || queued > queue_limit {
            self.current = ((self.current as u64 * 3 / 4) as u32).max(self.min);
            self.clean_intervals = 0;
        } else if s.nacks * 5 > s.frames {
            // Frequent repairs without delay build-up: ease off gently.
            self.current = ((self.current as u64 * 9 / 10) as u32).max(self.min);
            self.clean_intervals = 0;
        } else {
            self.clean_intervals += 1;
            if self.clean_intervals >= 3 && self.current < self.max {
                self.current = ((self.current as u64 * 11 / 10) as u32 + 100).min(self.max);
            }
        }
        // Skip changes too small to matter.
        let diff = self.current.abs_diff(self.requested);
        if diff * 25 >= self.requested || (self.current == self.max && diff != 0) {
            self.requested = self.current;
            Some(self.current)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean(delay: u64) -> Sample {
        Sample { frames: 60, delay_avg_us: Some(delay + 2_000), delay_min_us: Some(delay), dropped: 0, nacks: 0, rtt_us: 20_000 }
    }

    #[test]
    fn disabled_without_a_ceiling() {
        let mut rc = RateControl::new(0, 0);
        assert_eq!(rc.update(&Sample { frames: 60, dropped: 5, ..Default::default() }), None);
    }

    #[test]
    fn ramps_up_to_the_ceiling_on_a_clean_path() {
        let mut rc = RateControl::new(10_000, 30_000);
        let mut last = 10_000;
        for _ in 0..40 {
            if let Some(k) = rc.update(&clean(15_000)) {
                assert!(k > last && k <= 30_000);
                last = k;
            }
        }
        assert_eq!(last, 30_000);
        assert_eq!(rc.update(&clean(15_000)), None, "stays put at the ceiling");
    }

    #[test]
    fn backs_off_when_delay_builds_and_recovers() {
        let mut rc = RateControl::new(20_000, 20_000);
        for _ in 0..5 {
            assert_eq!(rc.update(&clean(15_000)), None);
        }
        // queue grows by 80 ms
        let congested =
            Sample { frames: 60, delay_avg_us: Some(95_000), delay_min_us: Some(60_000), dropped: 0, nacks: 2, rtt_us: 20_000 };
        assert_eq!(rc.update(&congested), Some(15_000));
        assert_eq!(rc.update(&congested), Some(11_250));
        // path clears: three quiet intervals, then climb
        assert_eq!(rc.update(&clean(15_000)), None);
        assert_eq!(rc.update(&clean(15_000)), None);
        let up = rc.update(&clean(15_000)).unwrap();
        assert!(up > 11_250);
        for _ in 0..30 {
            rc.update(&clean(15_000));
        }
        assert_eq!(rc.current_kbps(), 20_000);
    }

    #[test]
    fn loss_reduces_and_never_goes_below_the_floor() {
        let mut rc = RateControl::new(4_000, 4_000);
        for _ in 0..30 {
            rc.update(&Sample { frames: 60, dropped: 1, rtt_us: 5_000, ..Default::default() });
        }
        assert_eq!(rc.current_kbps(), 1_000);
        // occasional repairs on Wi-Fi are not congestion
        let mut rc = RateControl::new(30_000, 30_000);
        for _ in 0..10 {
            let s = Sample { nacks: 3, ..clean(3_000) };
            assert_eq!(rc.update(&s), None);
        }
        assert_eq!(rc.current_kbps(), 30_000);
    }
}
