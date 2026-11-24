//! Windowless client: receives and validates the stream. Used for automated
//! tests and for measuring the transport on machines without the GUI backend.

use crate::session::{self, Exit, Handler, InputTx, Options, Stats};
use crate::Args;
use hyperspace_proto::cursor::CursorShape;
use hyperspace_proto::frag::Frame;
use hyperspace_proto::input::InputEvent;
use hyperspace_proto::{annexb, log, Codec};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

struct Headless {
    codec: Codec,
    frames: u64,
    bad: u64,
    cursors: u64,
    max_frames: Option<u64>,
    stop: Arc<AtomicBool>,
    scratch: Vec<u8>,
    have_params: bool,
    last_id: Option<u32>,
    print_stats: bool,
    last: Stats,
}

impl Handler for Headless {
    fn video_frame(&mut self, frame: &Frame) -> bool {
        let info = annexb::inspect(self.codec, &frame.data);
        if info.keyframe && info.has_param_sets {
            self.have_params = annexb::param_sets(self.codec, &frame.data).complete(self.codec);
        }
        annexb::to_length_prefixed(self.codec, &frame.data, &mut self.scratch);
        // What a real decoder needs: parameter sets first, slices in every
        // frame, keyframe flag matching the bitstream, ids strictly increasing.
        let ordered = self.last_id.is_none_or(|l| (frame.id.wrapping_sub(l) as i32) > 0);
        let ok = self.have_params && info.slices > 0 && info.keyframe == frame.is_keyframe() && !self.scratch.is_empty() && ordered;
        if !ok {
            self.bad += 1;
            log!("frame {}: invalid ({info:?}, flagged key {}, params {})", frame.id, frame.is_keyframe(), self.have_params);
        }
        self.last_id = Some(frame.id);
        self.frames += 1;
        if self.max_frames.is_some_and(|m| self.frames >= m) {
            self.stop.store(true, Ordering::Relaxed);
        }
        true
    }

    fn cursor_shape(&mut self, shape: CursorShape) {
        self.cursors += 1;
        log!("cursor shape {}x{} hotspot ({}, {})", shape.width, shape.height, shape.hot_x, shape.hot_y);
    }

    fn cursor_visible(&mut self, visible: bool) {
        log!("cursor visible: {visible}");
    }

    fn stats(&mut self, s: &Stats) {
        self.last = *s;
        if self.print_stats {
            log!("{}", s.summary());
        }
    }
}

pub fn run(args: &Args) -> i32 {
    let opts = Options {
        host: args.host,
        fps: if args.fps == 0 { 60 } else { args.fps },
        bitrate_kbps: args.bitrate_kbps,
        codecs: args.codecs,
        max_datagram: args.max_datagram,
    };
    let conn = match session::connect(&opts) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let w = conn.welcome;
    log!(
        "connected: {}x{} @ {} fps, {}, {:.1} Mbit/s (headless)",
        w.width,
        w.height,
        w.fps,
        w.codec.name(),
        w.bitrate_kbps as f64 / 1000.0
    );
    let input = InputTx::new(conn.sock.clone());
    if args.test_input {
        // Harmless on a real host: nudge the pointer, tap and release Shift.
        input.send_all(&[
            InputEvent::MouseAbs { x: 32768, y: 32768 },
            InputEvent::MouseRel { dx: 4, dy: 4 },
            InputEvent::Key { scancode: 0x2a, down: true },
            InputEvent::Key { scancode: 0x2a, down: false },
            InputEvent::Wheel { dx: 0, dy: 0 },
        ]);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let mut h = Headless {
        codec: w.codec,
        frames: 0,
        bad: 0,
        cursors: 0,
        max_frames: args.frames,
        stop: stop.clone(),
        scratch: Vec::new(),
        have_params: false,
        last_id: None,
        print_stats: args.stats,
        last: Stats::default(),
    };
    let exit = session::receive_loop(&conn, &input, &stop, &mut h);
    log!(
        "{}: {} frames ({} invalid), {} dropped, {} nacks, {} keyframe requests, {} cursor shapes, input acked: {}",
        exit.describe(),
        h.frames,
        h.bad,
        h.last.frames_dropped,
        h.last.nacks,
        h.last.keyframe_requests,
        h.cursors,
        !input.has_unacked()
    );
    let reached = args.frames.is_none_or(|m| h.frames >= m);
    let clean = matches!(exit, Exit::Local) || (args.frames.is_none() && matches!(exit, Exit::Host(_)));
    if clean && reached && h.bad == 0 && (!args.test_input || !input.has_unacked()) {
        println!("CLIENT OK");
        0
    } else {
        1
    }
}
