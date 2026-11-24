//! Frame fragmentation and loss-repairing reassembly.
//!
//! Sender: a frame of `len` bytes becomes `ceil(len / chunk)` datagrams, each
//! carrying a [`FragHeader`]. Every fragment except the last holds exactly
//! `chunk` bytes, so a fragment's offset is `frag_idx * chunk`.
//!
//! Receiver: frames are released strictly in order (P-frames depend on their
//! predecessor). Holes are NACKed immediately; if the head-of-line frame cannot
//! be repaired within a deadline derived from the RTT, the reassembler asks for
//! a keyframe and discards everything until one arrives.

use crate::wire::{FragHeader, FLAG_KEYFRAME, FRAG_HEADER_LEN};
use std::collections::VecDeque;

pub const MAX_FRAME_LEN: usize = 32 << 20;
const MAX_PARTIALS: usize = 64;
/// No fragment for this long on an incomplete newest frame => its tail was lost.
const TAIL_TIMEOUT_US: u64 = 4_000;
const MAX_NACK_FRAGS: usize = 256;

#[inline]
pub fn frag_count(len: usize, chunk: usize) -> usize {
    len.div_ceil(chunk).max(1)
}

/// Splits frames into datagrams, reusing one scratch buffer.
#[derive(Default)]
pub struct Fragmenter {
    buf: Vec<u8>,
}

impl Fragmenter {
    /// Emit every fragment of `data`.
    #[allow(clippy::too_many_arguments)]
    pub fn send_all(
        &mut self,
        kind: u8,
        flags: u8,
        frame_id: u32,
        ts_us: u64,
        data: &[u8],
        chunk: usize,
        mut send: impl FnMut(&[u8]),
    ) {
        let n = frag_count(data.len(), chunk);
        for idx in 0..n {
            self.send_one(kind, flags, frame_id, ts_us, data, chunk, idx, &mut send);
        }
    }

    /// Emit a single fragment (used for retransmits). Out-of-range indices are ignored.
    #[allow(clippy::too_many_arguments)]
    pub fn send_one(
        &mut self,
        kind: u8,
        flags: u8,
        frame_id: u32,
        ts_us: u64,
        data: &[u8],
        chunk: usize,
        idx: usize,
        send: &mut impl FnMut(&[u8]),
    ) {
        let start = idx * chunk;
        if idx >= frag_count(data.len(), chunk) {
            return;
        }
        let end = (start + chunk).min(data.len());
        let payload = &data[start..end];
        self.buf.resize(FRAG_HEADER_LEN + payload.len(), 0);
        FragHeader { kind, flags, frag_idx: idx as u16, frame_id, frame_len: data.len() as u32, ts_us }
            .write(&mut self.buf[..FRAG_HEADER_LEN]);
        self.buf[FRAG_HEADER_LEN..].copy_from_slice(payload);
        send(&self.buf);
    }
}

#[derive(Debug)]
pub struct Frame {
    pub id: u32,
    pub flags: u8,
    /// Sender clock at capture.
    pub ts_us: u64,
    /// Local clock when the first fragment arrived.
    pub first_rx_us: u64,
    pub data: Vec<u8>,
}

impl Frame {
    pub fn is_keyframe(&self) -> bool {
        self.flags & FLAG_KEYFRAME != 0
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action<'a> {
    /// Ask the sender to retransmit fragments (empty slice = whole frame).
    Nack { frame_id: u32, frags: &'a [u16] },
    RequestKeyframe,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ReasmStats {
    pub frames_delivered: u64,
    /// Frames skipped because they could not be repaired in time.
    pub frames_dropped: u64,
    pub nacks_sent: u64,
    pub keyframe_requests: u64,
    pub duplicate_frags: u64,
}

struct Partial {
    id: u32,
    flags: u8,
    ts_us: u64,
    /// 0 while the frame is a placeholder (we know it exists, but no fragment arrived).
    frag_cnt: u32,
    got_count: u32,
    max_idx: u32,
    got: Vec<u64>,
    data: Vec<u8>,
    first_rx_us: u64,
    last_rx_us: u64,
    first_nack_us: u64,
    last_nack_us: u64,
}

impl Partial {
    fn placeholder(id: u32, now: u64) -> Partial {
        Partial {
            id,
            flags: 0,
            ts_us: 0,
            frag_cnt: 0,
            got_count: 0,
            max_idx: 0,
            got: Vec::new(),
            data: Vec::new(),
            first_rx_us: now,
            last_rx_us: now,
            first_nack_us: 0,
            last_nack_us: 0,
        }
    }
    fn complete(&self) -> bool {
        self.frag_cnt != 0 && self.got_count == self.frag_cnt
    }
    fn has(&self, idx: u32) -> bool {
        self.got[(idx / 64) as usize] & (1 << (idx % 64)) != 0
    }
    fn is_key(&self) -> bool {
        self.flags & FLAG_KEYFRAME != 0
    }
}

#[inline]
fn id_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

pub struct Reassembler {
    kind: u8,
    chunk: usize,
    /// Sorted by id, ascending.
    partials: VecDeque<Partial>,
    next_id: u32,
    highest_id: u32,
    seen_any: bool,
    need_key: bool,
    last_kf_req_us: u64,
    rtt_us: u64,
    pool: Vec<Vec<u8>>,
    scratch: Vec<u16>,
    pub stats: ReasmStats,
}

impl Reassembler {
    pub fn new(kind: u8, chunk: usize, now_us: u64) -> Reassembler {
        Reassembler {
            kind,
            chunk: chunk.max(1),
            partials: VecDeque::new(),
            next_id: 0,
            highest_id: 0,
            seen_any: false,
            need_key: true,
            last_kf_req_us: now_us,
            rtt_us: 5_000,
            pool: Vec::new(),
            scratch: Vec::new(),
            stats: ReasmStats::default(),
        }
    }

    pub fn kind(&self) -> u8 {
        self.kind
    }

    pub fn set_rtt_us(&mut self, rtt: u64) {
        self.rtt_us = rtt.clamp(200, 500_000);
    }

    fn renack_us(&self) -> u64 {
        (self.rtt_us + self.rtt_us / 2 + 2_000).clamp(4_000, 100_000)
    }

    fn give_up_us(&self) -> u64 {
        (3 * self.rtt_us + 15_000).clamp(25_000, 300_000)
    }

    fn kf_interval_us(&self) -> u64 {
        (4 * self.rtt_us).clamp(100_000, 500_000)
    }

    /// Return a frame buffer for reuse.
    pub fn recycle(&mut self, buf: Vec<u8>) {
        if self.pool.len() < 8 {
            self.pool.push(buf);
        }
    }

    /// Stop delivering until a keyframe arrives. Keeps any keyframe already
    /// in flight together with the frames that follow it.
    fn enter_need_key(&mut self) {
        self.need_key = true;
        let keep_from = self.partials.iter().position(|p| p.is_key()).unwrap_or(self.partials.len());
        for _ in 0..keep_from {
            let p = self.partials.pop_front().unwrap();
            self.recycle(p.data);
            self.stats.frames_dropped += 1;
        }
    }

    /// Feed one received fragment.
    pub fn push(&mut self, h: &FragHeader, payload: &[u8], now_us: u64) {
        if h.kind != self.kind {
            return;
        }
        let len = h.frame_len as usize;
        if len == 0 || len > MAX_FRAME_LEN {
            return;
        }
        let cnt = frag_count(len, self.chunk);
        let idx = h.frag_idx as usize;
        if idx >= cnt || cnt > u16::MAX as usize + 1 {
            return;
        }
        let expect = if idx == cnt - 1 { len - idx * self.chunk } else { self.chunk };
        if payload.len() != expect {
            return;
        }
        let id = h.frame_id;
        if id_lt(id, self.next_id) {
            self.stats.duplicate_frags += 1;
            return;
        }
        let is_key = h.flags & FLAG_KEYFRAME != 0;
        if !self.seen_any || id_lt(self.highest_id, id) {
            self.highest_id = id;
            self.seen_any = true;
        }
        // While waiting for a keyframe, P-frames are only useful if they
        // follow a keyframe that is already in flight.
        if self.need_key && !is_key && !self.partials.iter().any(|p| p.is_key() && id_lt(p.id, id)) {
            return;
        }

        // Locate or create the partial (list is tiny and sorted; search from the back).
        let mut pos = self.partials.len();
        let mut found = false;
        while pos > 0 {
            let pid = self.partials[pos - 1].id;
            if pid == id {
                found = true;
                pos -= 1;
                break;
            }
            if id_lt(pid, id) {
                break;
            }
            pos -= 1;
        }
        if !found {
            // Frames between the previous known frame and this one exist but
            // have not produced a single fragment yet: track them as
            // placeholders so they get NACKed.
            let first_missing = match pos.checked_sub(1).map(|i| self.partials[i].id) {
                Some(prev) => Some(prev.wrapping_add(1)),
                None if !self.need_key => Some(self.next_id),
                None => None,
            };
            let gap = first_missing.map_or(0, |m| id.wrapping_sub(m) as usize);
            if self.partials.len() + gap >= MAX_PARTIALS {
                // Hopelessly behind: start over from the next keyframe.
                self.stats.frames_dropped += self.partials.len() as u64;
                while let Some(p) = self.partials.pop_front() {
                    self.recycle(p.data);
                }
                self.need_key = true;
                if !is_key {
                    return;
                }
                pos = 0;
            } else if let Some(mut m) = first_missing {
                while m != id {
                    self.partials.insert(pos, Partial::placeholder(m, now_us));
                    pos += 1;
                    m = m.wrapping_add(1);
                }
            }
            self.partials.insert(pos, Partial::placeholder(id, now_us));
        }

        let chunk = self.chunk;
        let p = &mut self.partials[pos];
        if p.frag_cnt == 0 {
            p.flags = h.flags;
            p.ts_us = h.ts_us;
            p.frag_cnt = cnt as u32;
            p.got = vec![0u64; cnt.div_ceil(64)];
            let mut data = self.pool.pop().unwrap_or_default();
            data.clear();
            data.resize(len, 0);
            p.data = data;
            p.first_rx_us = now_us;
        } else if p.frag_cnt != cnt as u32 || p.data.len() != len {
            return; // inconsistent with earlier fragments
        }
        if p.has(idx as u32) {
            self.stats.duplicate_frags += 1;
            return;
        }
        p.got[idx / 64] |= 1 << (idx % 64);
        p.got_count += 1;
        p.max_idx = p.max_idx.max(idx as u32);
        p.last_rx_us = now_us;
        p.data[idx * chunk..idx * chunk + payload.len()].copy_from_slice(payload);
    }

    fn take(&mut self, pos: usize) -> Frame {
        let p = self.partials.remove(pos).unwrap();
        self.next_id = p.id.wrapping_add(1);
        self.need_key = false;
        self.stats.frames_delivered += 1;
        Frame { id: p.id, flags: p.flags, ts_us: p.ts_us, first_rx_us: p.first_rx_us, data: p.data }
    }

    /// Next decodable frame, if any. Call until it returns `None`.
    #[allow(clippy::manual_pop_if)]
    pub fn pop(&mut self) -> Option<Frame> {
        loop {
            // In-order head.
            if let Some(p) = self.partials.front() {
                if p.id == self.next_id && p.complete() {
                    if self.need_key && !p.is_key() {
                        let p = self.partials.pop_front().unwrap();
                        self.next_id = p.id.wrapping_add(1);
                        self.recycle(p.data);
                        self.stats.frames_dropped += 1;
                        continue;
                    }
                    return Some(self.take(0));
                }
            }
            // Head is stuck: jump to the newest complete keyframe if there is one.
            let k = (0..self.partials.len()).rev().find(|&i| self.partials[i].complete() && self.partials[i].is_key())?;
            for _ in 0..k {
                let p = self.partials.pop_front().unwrap();
                self.recycle(p.data);
                self.stats.frames_dropped += 1;
            }
            return Some(self.take(0));
        }
    }

    /// Drive timers. Call after each burst of `push` and at least every few ms
    /// while frames are outstanding.
    pub fn poll(&mut self, now_us: u64, mut act: impl FnMut(Action<'_>)) {
        if self.need_key && now_us.saturating_sub(self.last_kf_req_us) >= self.kf_interval_us() {
            self.last_kf_req_us = now_us;
            self.stats.keyframe_requests += 1;
            act(Action::RequestKeyframe);
        }

        let renack = self.renack_us();
        let give_up = self.give_up_us();
        let highest = self.highest_id;
        let mut give_up_now = false;

        for (i, p) in self.partials.iter_mut().enumerate() {
            if p.complete() {
                continue;
            }
            let later_exists = id_lt(p.id, highest);
            let stalled = now_us.saturating_sub(p.last_rx_us) > TAIL_TIMEOUT_US;
            let all = later_exists || stalled;
            if p.frag_cnt != 0 && !all && p.got_count == p.max_idx + 1 {
                continue; // contiguous so far, still arriving
            }
            if !self.need_key && i == 0 && p.first_nack_us != 0 && now_us.saturating_sub(p.first_nack_us) > give_up {
                give_up_now = true;
                break;
            }
            if p.last_nack_us != 0 && now_us.saturating_sub(p.last_nack_us) < renack {
                continue;
            }
            self.scratch.clear();
            if p.frag_cnt != 0 {
                let limit = if all { p.frag_cnt } else { p.max_idx };
                let missing = limit - p.got_count.min(limit);
                // Mostly gone: cheaper to ask for the whole frame.
                if !(all && missing as usize > MAX_NACK_FRAGS) {
                    for idx in 0..limit {
                        if !p.has(idx) {
                            self.scratch.push(idx as u16);
                            if self.scratch.len() >= MAX_NACK_FRAGS {
                                break;
                            }
                        }
                    }
                    if self.scratch.is_empty() {
                        continue;
                    }
                }
            } else if !all {
                continue;
            }
            if p.first_nack_us == 0 {
                p.first_nack_us = now_us;
            }
            p.last_nack_us = now_us;
            self.stats.nacks_sent += 1;
            act(Action::Nack { frame_id: p.id, frags: &self.scratch });
        }

        if give_up_now {
            self.enter_need_key();
            self.last_kf_req_us = now_us;
            self.stats.keyframe_requests += 1;
            act(Action::RequestKeyframe);
        }
    }

    /// The decoder lost its reference chain: discard until the next keyframe.
    /// The caller is expected to send the keyframe request itself right away.
    pub fn force_keyframe(&mut self, now_us: u64) {
        self.enter_need_key();
        self.last_kf_req_us = now_us;
        self.stats.keyframe_requests += 1;
    }

    /// True while frames are buffered (poll soon).
    pub fn busy(&self) -> bool {
        !self.partials.is_empty()
    }

    pub fn waiting_for_keyframe(&self) -> bool {
        self.need_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::pt;

    const CHUNK: usize = 100;

    fn frame_bytes(id: u32, len: usize) -> Vec<u8> {
        (0..len).map(|i| (i as u32).wrapping_mul(31).wrapping_add(id * 7) as u8).collect()
    }

    /// Fragment a frame into owned datagrams.
    fn dgrams(id: u32, key: bool, len: usize) -> Vec<Vec<u8>> {
        let data = frame_bytes(id, len);
        let mut out = Vec::new();
        Fragmenter::default().send_all(
            pt::VIDEO,
            if key { FLAG_KEYFRAME } else { 0 },
            id,
            id as u64 * 1000,
            &data,
            CHUNK,
            |d| out.push(d.to_vec()),
        );
        out
    }

    fn feed(r: &mut Reassembler, d: &[u8], now: u64) {
        let (h, p) = FragHeader::read(d).unwrap();
        r.push(&h, p, now);
    }

    fn pop_ids(r: &mut Reassembler) -> Vec<u32> {
        let mut v = Vec::new();
        while let Some(f) = r.pop() {
            assert_eq!(f.data, frame_bytes(f.id, f.data.len()), "frame {} corrupted", f.id);
            v.push(f.id);
            r.recycle(f.data);
        }
        v
    }

    fn collect_actions(r: &mut Reassembler, now: u64) -> (Vec<(u32, Vec<u16>)>, bool) {
        let mut nacks = Vec::new();
        let mut kf = false;
        r.poll(now, |a| match a {
            Action::Nack { frame_id, frags } => nacks.push((frame_id, frags.to_vec())),
            Action::RequestKeyframe => kf = true,
        });
        (nacks, kf)
    }

    #[test]
    fn fragment_sizes() {
        assert_eq!(dgrams(0, true, 1).len(), 1);
        assert_eq!(dgrams(0, true, 100).len(), 1);
        assert_eq!(dgrams(0, true, 101).len(), 2);
        let d = dgrams(0, true, 250);
        assert_eq!(d.iter().map(|x| x.len() - FRAG_HEADER_LEN).collect::<Vec<_>>(), vec![100, 100, 50]);
    }

    #[test]
    fn in_order_delivery() {
        let mut r = Reassembler::new(pt::VIDEO, CHUNK, 0);
        for (id, key) in [(0, true), (1, false), (2, false)] {
            for d in dgrams(id, key, 950) {
                feed(&mut r, &d, 10);
            }
        }
        assert_eq!(pop_ids(&mut r), vec![0, 1, 2]);
        assert!(!r.busy());
    }

    #[test]
    fn waits_for_keyframe_at_start() {
        let mut r = Reassembler::new(pt::VIDEO, CHUNK, 0);
        for d in dgrams(5, false, 300) {
            feed(&mut r, &d, 10);
        }
        assert!(pop_ids(&mut r).is_empty());
        let (_, kf) = collect_actions(&mut r, 200_000);
        assert!(kf, "should ask for a keyframe when none shows up");
        for d in dgrams(6, true, 300) {
            feed(&mut r, &d, 201_000);
        }
        for d in dgrams(7, false, 300) {
            feed(&mut r, &d, 201_000);
        }
        assert_eq!(pop_ids(&mut r), vec![6, 7]);
    }

    #[test]
    fn hole_is_nacked_and_repaired() {
        let mut r = Reassembler::new(pt::VIDEO, CHUNK, 0);
        for d in dgrams(0, true, 100) {
            feed(&mut r, &d, 0);
        }
        assert_eq!(pop_ids(&mut r), vec![0]);

        let f1 = dgrams(1, false, 1000);
        for (i, d) in f1.iter().enumerate() {
            if i != 3 && i != 7 {
                feed(&mut r, d, 1000);
            }
        }
        // idx 3 and 7 are below max_idx (9) -> NACK right away
        let (nacks, kf) = collect_actions(&mut r, 1000);
        assert_eq!(nacks, vec![(1, vec![3, 7])]);
        assert!(!kf);
        // rate limited
        assert!(collect_actions(&mut r, 1500).0.is_empty());
        // frame 2 arrives complete but must wait
        for d in dgrams(2, false, 150) {
            feed(&mut r, &d, 2000);
        }
        assert!(pop_ids(&mut r).is_empty());
        feed(&mut r, &f1[3], 3000);
        feed(&mut r, &f1[7], 3000);
        assert_eq!(pop_ids(&mut r), vec![1, 2]);
        assert_eq!(r.stats.frames_dropped, 0);
    }

    #[test]
    fn tail_loss_is_nacked_after_timeout() {
        let mut r = Reassembler::new(pt::VIDEO, CHUNK, 0);
        let f0 = dgrams(0, true, 500);
        for d in &f0[..3] {
            feed(&mut r, d, 1000);
        }
        // still arriving as far as we can tell
        assert!(collect_actions(&mut r, 1500).0.is_empty());
        let (nacks, _) = collect_actions(&mut r, 1000 + TAIL_TIMEOUT_US + 1);
        assert_eq!(nacks, vec![(0, vec![3, 4])]);
    }

    #[test]
    fn wholly_lost_frame_is_nacked() {
        let mut r = Reassembler::new(pt::VIDEO, CHUNK, 0);
        for d in dgrams(0, true, 100) {
            feed(&mut r, &d, 0);
        }
        assert_eq!(pop_ids(&mut r), vec![0]);
        // frame 1 vanishes entirely, frame 2 arrives
        for d in dgrams(2, false, 100) {
            feed(&mut r, &d, 1000);
        }
        let (nacks, _) = collect_actions(&mut r, 1000);
        assert_eq!(nacks, vec![(1, vec![])]);
        assert!(pop_ids(&mut r).is_empty());
        for d in dgrams(1, false, 220) {
            feed(&mut r, &d, 2000);
        }
        assert_eq!(pop_ids(&mut r), vec![1, 2]);
    }

    #[test]
    fn gives_up_and_recovers_on_keyframe() {
        let mut r = Reassembler::new(pt::VIDEO, CHUNK, 0);
        for d in dgrams(0, true, 100) {
            feed(&mut r, &d, 0);
        }
        assert_eq!(pop_ids(&mut r), vec![0]);
        for d in dgrams(2, false, 100) {
            feed(&mut r, &d, 1000);
        }
        let (n, kf) = collect_actions(&mut r, 1000);
        assert_eq!(n.len(), 1);
        assert!(!kf);
        // nothing comes back; past the deadline we must ask for a keyframe
        let mut got_kf = false;
        let mut t = 1000;
        while t < 400_000 && !got_kf {
            t += 2000;
            got_kf = collect_actions(&mut r, t).1;
        }
        assert!(got_kf);
        assert!(r.waiting_for_keyframe());
        // P-frames are useless now
        for d in dgrams(3, false, 100) {
            feed(&mut r, &d, t);
        }
        assert!(pop_ids(&mut r).is_empty());
        for d in dgrams(4, true, 300) {
            feed(&mut r, &d, t);
        }
        for d in dgrams(5, false, 100) {
            feed(&mut r, &d, t);
        }
        assert_eq!(pop_ids(&mut r), vec![4, 5]);
        assert!(r.stats.frames_dropped >= 1);
    }

    #[test]
    fn skips_to_newer_keyframe_without_waiting() {
        let mut r = Reassembler::new(pt::VIDEO, CHUNK, 0);
        for d in dgrams(0, true, 100) {
            feed(&mut r, &d, 0);
        }
        assert_eq!(pop_ids(&mut r), vec![0]);
        let f1 = dgrams(1, false, 300);
        feed(&mut r, &f1[0], 10);
        for d in dgrams(2, true, 300) {
            feed(&mut r, &d, 20);
        }
        assert_eq!(pop_ids(&mut r), vec![2]);
        // late fragments of frame 1 are ignored
        feed(&mut r, &f1[1], 30);
        feed(&mut r, &f1[2], 30);
        assert!(pop_ids(&mut r).is_empty());
        assert!(!r.busy());
    }

    #[test]
    fn duplicates_and_reordering_are_harmless() {
        let mut r = Reassembler::new(pt::VIDEO, CHUNK, 0);
        let mut all: Vec<Vec<u8>> = Vec::new();
        for (id, key) in [(0, true), (1, false), (2, false), (3, false)] {
            all.extend(dgrams(id, key, 777));
        }
        // deterministic shuffle + duplicates
        let mut order: Vec<usize> = (0..all.len()).collect();
        let mut s = 12345u32;
        for i in (1..order.len()).rev() {
            s = s.wrapping_mul(1664525).wrapping_add(1013904223);
            order.swap(i, (s >> 8) as usize % (i + 1));
        }
        let mut got = Vec::new();
        for &i in order.iter().chain(order.iter()) {
            feed(&mut r, &all[i], 5);
            got.extend(pop_ids(&mut r));
        }
        assert_eq!(got, vec![0, 1, 2, 3]);
    }

    #[test]
    fn random_loss_with_retransmit_always_converges() {
        // Simulated link: 10% loss on first transmission and on retransmits.
        let mut s = 99u32;
        let mut rnd = move || {
            s = s.wrapping_mul(1664525).wrapping_add(1013904223);
            (s >> 8) % 100
        };
        let mut r = Reassembler::new(pt::VIDEO, CHUNK, 0);
        r.set_rtt_us(1000);
        let total = 300u32;
        let mut sent: Vec<(bool, usize)> = Vec::new();
        let mut delivered = Vec::new();
        let mut now = 0u64;
        let mut force_key = true;
        let mut id = 0u32;
        while id < total || r.busy() {
            if id < total {
                let len = 150 + (id as usize * 37) % 900;
                sent.push((force_key, len));
                for d in dgrams(id, force_key, len) {
                    if rnd() >= 10 {
                        feed(&mut r, &d, now);
                    }
                }
                force_key = false;
                id += 1;
            }
            for _ in 0..8 {
                now += 2000;
                let (nacks, kf) = collect_actions(&mut r, now);
                if kf {
                    force_key = true;
                }
                for (fid, frags) in nacks {
                    let (key, len) = sent[fid as usize];
                    let ds = dgrams(fid, key, len);
                    let idxs: Vec<usize> =
                        if frags.is_empty() { (0..ds.len()).collect() } else { frags.iter().map(|&f| f as usize).collect() };
                    for i in idxs {
                        if rnd() >= 10 {
                            feed(&mut r, &ds[i], now);
                        }
                    }
                }
                delivered.extend(pop_ids(&mut r));
            }
            if now > 60_000_000 {
                panic!("did not converge");
            }
        }
        // strictly increasing, and (with repair) nearly everything arrives
        assert!(delivered.windows(2).all(|w| w[0] < w[1]));
        assert!(delivered.len() as u32 > total * 9 / 10, "only {} of {total}", delivered.len());
    }
}
