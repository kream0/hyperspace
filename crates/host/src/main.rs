//! hyperspace-host: streams this machine's desktop to a hyperspace client and
//! applies the client's keyboard/mouse input.

mod file_source;
mod inject;
mod pipeline;
mod server;
#[cfg(windows)]
mod win;
#[cfg_attr(not(windows), allow(dead_code))]
mod yuv;

use hyperspace_proto::{log, wire, Codec, DEFAULT_PORT};
use pipeline::{Config, EncoderPref, SourceKind};
use std::net::SocketAddr;

const HELP: &str = "\
hyperspace-host - low-latency remote desktop host

USAGE:
    hyperspace-host [OPTIONS]

OPTIONS:
    --port <N>            UDP port to listen on [default: 45800]
    --bind <ADDR:PORT>    Listen address [default: 0.0.0.0:45800]
    --display <N>         Display to capture, see --list [default: primary]
    --codec <h264|hevc>   Force a codec [default: hevc if both sides support it]
    --encoder <auto|hw|sw>  Encoder selection [default: auto = hardware, else software]
    --bitrate <MBIT>      Video bitrate; overrides the client's request
    --max-fps <N>         Cap the frame rate regardless of the client's request
    --packet-size <N>     Max UDP payload [default: 1400; use 1200 over VPNs]
    --view-only           Ignore remote keyboard/mouse
    --once                Exit when the first session ends
    --dump <FILE>         Also write the encoded stream to FILE (Annex B)
    --file <FILE>         Stream an Annex B .h264/.h265 file instead of the desktop
    --file-size <WxH>     Picture size announced for --file [default: 1280x720]
    --list                List displays and encoders, then exit
    --self-test [N]       Capture+encode N frames locally (no network), then exit
    -h, --help            Show this help
    -V, --version         Show version
";

enum Mode {
    Serve,
    List,
    SelfTest(u32),
}

fn parse_args() -> Result<(Config, Mode), String> {
    let mut cfg = Config {
        bind: SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT)),
        source: SourceKind::Desktop,
        display: usize::MAX,
        codec: None,
        encoder: EncoderPref::Auto,
        bitrate_kbps: 0,
        max_fps: 0,
        packet_size: wire::DEFAULT_DATAGRAM,
        dump: None,
        once: false,
        view_only: false,
        file_size: (1280, 720),
    };
    let mut mode = Mode::Serve;
    let mut args = std::env::args().skip(1).peekable();
    while let Some(a) = args.next() {
        let mut val = |name: &str| args.next().ok_or(format!("{name} needs a value"));
        match a.as_str() {
            "-h" | "--help" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("hyperspace-host {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--port" => {
                let p: u16 = val("--port")?.parse().map_err(|_| "invalid --port")?;
                cfg.bind.set_port(p);
            }
            "--bind" => cfg.bind = val("--bind")?.parse().map_err(|_| "invalid --bind (expected ADDR:PORT)")?,
            "--display" => cfg.display = val("--display")?.parse().map_err(|_| "invalid --display")?,
            "--codec" => {
                cfg.codec = Some(match val("--codec")?.as_str() {
                    "h264" | "avc" => Codec::H264,
                    "hevc" | "h265" => Codec::Hevc,
                    other => return Err(format!("unknown codec '{other}'")),
                })
            }
            "--encoder" => {
                cfg.encoder = match val("--encoder")?.as_str() {
                    "auto" => EncoderPref::Auto,
                    "hw" | "hardware" => EncoderPref::Hardware,
                    "sw" | "software" => EncoderPref::Software,
                    other => return Err(format!("unknown encoder '{other}'")),
                }
            }
            "--bitrate" => {
                let m: f64 = val("--bitrate")?.parse().map_err(|_| "invalid --bitrate")?;
                if !(0.1..=1000.0).contains(&m) {
                    return Err("--bitrate is in Mbit/s (0.1 - 1000)".into());
                }
                cfg.bitrate_kbps = (m * 1000.0) as u32;
            }
            "--max-fps" => cfg.max_fps = val("--max-fps")?.parse().map_err(|_| "invalid --max-fps")?,
            "--packet-size" => {
                let n: usize = val("--packet-size")?.parse().map_err(|_| "invalid --packet-size")?;
                if !(wire::MIN_DATAGRAM..=wire::MAX_DATAGRAM).contains(&n) {
                    return Err(format!("--packet-size must be {}..={}", wire::MIN_DATAGRAM, wire::MAX_DATAGRAM));
                }
                cfg.packet_size = n;
            }
            "--view-only" => cfg.view_only = true,
            "--once" => cfg.once = true,
            "--dump" => cfg.dump = Some(val("--dump")?.into()),
            "--file" => cfg.source = SourceKind::File(val("--file")?.into()),
            "--file-size" => {
                let v = val("--file-size")?;
                let (w, h) = v.split_once('x').ok_or("--file-size expects WxH")?;
                cfg.file_size = (w.parse().map_err(|_| "invalid width")?, h.parse().map_err(|_| "invalid height")?);
            }
            "--list" => mode = Mode::List,
            "--self-test" => {
                let n = match args.peek().and_then(|s| s.parse::<u32>().ok()) {
                    Some(n) => {
                        args.next();
                        n
                    }
                    None => 120,
                };
                mode = Mode::SelfTest(n);
            }
            other => return Err(format!("unknown option '{other}' (try --help)")),
        }
    }
    Ok((cfg, mode))
}

fn main() {
    let (cfg, mode) = match parse_args() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };
    let result = match mode {
        Mode::Serve => serve(cfg),
        Mode::List => list(),
        Mode::SelfTest(n) => self_test(cfg, n),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn serve(cfg: Config) -> Result<(), String> {
    #[cfg(windows)]
    win::process_setup();
    let mut server = server::Server::new(cfg.clone())?;
    log!("hyperspace-host {} listening on udp {}", env!("CARGO_PKG_VERSION"), server.local_addr().unwrap_or(cfg.bind));
    log!("no authentication: only expose this port on a network you trust");
    server.run()
}

fn list() -> Result<(), String> {
    #[cfg(windows)]
    {
        win::list()
    }
    #[cfg(not(windows))]
    {
        println!("desktop capture is only available on Windows; this build can serve --file streams");
        Ok(())
    }
}

/// Run the pipeline without a network: proves capture + encode work on this
/// machine and reports timing.
fn self_test(cfg: Config, frames: u32) -> Result<(), String> {
    use hyperspace_proto::annexb;
    use pipeline::{Control, Sink, StreamInfo, StreamRequest};
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct TestSink {
        info: Mutex<Option<StreamInfo>>,
        frames: AtomicU32,
        keyframes: AtomicU32,
        bad: AtomicU32,
        bytes: AtomicU64,
        lat_sum: AtomicU64,
        lat_max: AtomicU64,
        cursors: AtomicU32,
        dump: Mutex<Option<std::fs::File>>,
    }
    impl Sink for TestSink {
        fn started(&self, info: &StreamInfo) {
            log!("pipeline ready: {info:?}");
            *self.info.lock().unwrap() = Some(*info);
        }
        fn frame(&self, data: &[u8], keyframe: bool, ts_us: u64) {
            let codec = self.info.lock().unwrap().expect("frame before started").codec;
            let au = annexb::inspect(codec, data);
            let n = self.frames.fetch_add(1, Ordering::Relaxed);
            // Every frame needs slices; keyframes must be flagged and self-contained.
            let ok = au.slices > 0 && au.keyframe == keyframe && (!keyframe || au.has_param_sets) && (n > 0 || keyframe);
            if !ok {
                self.bad.fetch_add(1, Ordering::Relaxed);
                log!("frame {n}: unexpected structure {au:?} (flagged keyframe: {keyframe})");
            }
            self.keyframes.fetch_add(keyframe as u32, Ordering::Relaxed);
            self.bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
            let lat = hyperspace_proto::clock::now_us().saturating_sub(ts_us);
            self.lat_sum.fetch_add(lat, Ordering::Relaxed);
            self.lat_max.fetch_max(lat, Ordering::Relaxed);
            if let Some(f) = self.dump.lock().unwrap().as_mut() {
                server::write_dump(f, codec, data);
            }
        }
        fn cursor(&self, shape: Option<&hyperspace_proto::cursor::CursorShape>, visible: bool) {
            if let Some(s) = shape {
                log!("cursor shape {}x{} hot ({}, {}) visible {visible}", s.width, s.height, s.hot_x, s.hot_y);
                self.cursors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    #[cfg(windows)]
    win::process_setup();
    let sink = Arc::new(TestSink::default());
    if let Some(p) = &cfg.dump {
        *sink.dump.lock().unwrap() = Some(std::fs::File::create(p).map_err(|e| format!("{}: {e}", p.display()))?);
    }
    let ctl = Arc::new(Control::default());
    let req = StreamRequest { codecs: wire::CODEC_MASK_ALL, fps: 60, bitrate_kbps: 0 };
    let result = std::thread::scope(|scope| {
        let worker = scope.spawn(|| pipeline::run(&cfg, req, ctl.clone(), sink.clone()));
        let start = std::time::Instant::now();
        let mut last_kf = start;
        while !worker.is_finished() {
            std::thread::sleep(std::time::Duration::from_millis(10));
            // A static desktop produces no frames; forced keyframes keep the
            // encoder busy and exercise the IDR-on-demand path.
            if last_kf.elapsed().as_millis() >= 150 {
                last_kf = std::time::Instant::now();
                ctl.keyframe.store(true, Ordering::Relaxed);
            }
            if sink.frames.load(Ordering::Relaxed) >= frames || start.elapsed().as_secs() >= 30 {
                ctl.stop.store(true, Ordering::Relaxed);
            }
        }
        worker.join().unwrap_or(Err("pipeline panicked".into()))
    });
    let n = sink.frames.load(Ordering::Relaxed);
    let bad = sink.bad.load(Ordering::Relaxed);
    log!(
        "self-test: {n} frames ({} keyframes, {bad} malformed), {} bytes, capture->encoded avg {:.2} ms max {:.2} ms, {} cursor shapes",
        sink.keyframes.load(Ordering::Relaxed),
        sink.bytes.load(Ordering::Relaxed),
        sink.lat_sum.load(Ordering::Relaxed) as f64 / n.max(1) as f64 / 1000.0,
        sink.lat_max.load(Ordering::Relaxed) as f64 / 1000.0,
        sink.cursors.load(Ordering::Relaxed)
    );
    result?;
    if n == 0 {
        return Err("no frames were produced".into());
    }
    if bad != 0 {
        return Err(format!("{bad} frames had an unexpected bitstream structure"));
    }
    println!("SELF-TEST OK");
    Ok(())
}
