//! hyperspace-host: streams this machine's desktop to a hyperspace client and
//! applies the client's keyboard/mouse input.

mod file_source;
mod inject;
mod pipeline;
mod reach;
mod server;
#[cfg(windows)]
mod win;
#[cfg_attr(not(windows), allow(dead_code))]
mod yuv;

use hyperspace_proto::{log, wire, Codec, DEFAULT_PORT};
use pipeline::{Config, EncoderPref, SourceKind};
use hyperspace_proto::pairing::{config_dir, Pairing};
use hyperspace_bridge::{plain_error, HostBridge, RelayUrl};
use hyperspace_proto::relay::RoomKey;
use hyperspace_proto::secure::Key;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

const HELP: &str = "\
hyperspace-host - low-latency remote desktop host

USAGE:
    hyperspace-host [OPTIONS]

OPTIONS:
    --port <N>            UDP port to listen on [default: 45800]
    --bind <ADDR:PORT>    Listen on one address only [default: all, IPv4 and IPv6]
    --public-host <NAME>  DNS name that points at this PC (e.g. a dynamic-DNS name);
                          added to the pairing string
    --no-upnp             Do not ask the router to forward the port
    --no-dht              Do not publish this host's address for roaming clients
    --new-key             Replace the pairing key (every client must pair again)
    --config-dir <DIR>    Where the key and pairing string are kept
    --relay <URL|off>     Also take clients through the relay at URL (wss://...), for
                          clients that cannot reach this PC over UDP; remembered until
                          --relay off
    --relay-id            Print this host's relay id (the relay's operator adds it to the
                          relay's allow list), then exit
    --relay-check <URL>   Check that a relay answers at URL (DNS, TCP, TLS, WebSocket),
                          then exit
    --display <N>         Display to capture, see --list [default: primary]
    --codec <h264|hevc>   Force a codec [default: hevc if both sides support it]
    --encoder <auto|hw|sw>  Encoder selection [default: auto = hardware, else software]
    --bitrate <MBIT>      Video bitrate; overrides the client's request
    --max-fps <N>         Cap the frame rate regardless of the client's request
    --packet-size <N>     Max UDP payload on the LAN [default: 1400; 1232 is used across the internet]
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
    RelayId,
    RelayCheck(String),
}

/// What `--relay` asked for.
enum RelayArg {
    /// No flag: use the saved setting, if any.
    Unset,
    Off,
    Set(RelayUrl),
}

struct Extra {
    upnp: bool,
    dht: bool,
    public_host: Option<String>,
    new_key: bool,
    config_dir: PathBuf,
    relay: RelayArg,
}

fn parse_args() -> Result<(Config, Mode, Extra), String> {
    let mut extra = Extra {
        upnp: true,
        dht: true,
        public_host: None,
        new_key: false,
        config_dir: config_dir(),
        relay: RelayArg::Unset,
    };
    let mut cfg = Config {
        bind: None,
        port: DEFAULT_PORT,
        key: Key::from_bytes([0; 32]),
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
                cfg.port = val("--port")?.parse().map_err(|_| "invalid --port")?;
                if let Some(b) = cfg.bind.as_mut() {
                    b.set_port(cfg.port);
                }
            }
            "--bind" => {
                let addr: SocketAddr = val("--bind")?.parse().map_err(|_| "invalid --bind (expected ADDR:PORT)")?;
                cfg.port = addr.port();
                cfg.bind = Some(addr);
            }
            "--public-host" => extra.public_host = Some(val("--public-host")?),
            "--no-upnp" => extra.upnp = false,
            "--no-dht" => extra.dht = false,
            "--new-key" => extra.new_key = true,
            "--config-dir" => extra.config_dir = val("--config-dir")?.into(),
            "--relay" => {
                let v = val("--relay")?;
                extra.relay = if v.eq_ignore_ascii_case("off") {
                    RelayArg::Off
                } else {
                    RelayArg::Set(RelayUrl::parse(&v).map_err(|e| format!("invalid --relay: {e}"))?)
                };
            }
            "--relay-id" => mode = Mode::RelayId,
            "--relay-check" => mode = Mode::RelayCheck(val("--relay-check")?),
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
    Ok((cfg, mode, extra))
}

fn main() {
    let (cfg, mode, extra) = match parse_args() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };
    let result = match mode {
        Mode::Serve => serve(cfg, extra),
        Mode::List => list(),
        Mode::SelfTest(n) => self_test(cfg, n),
        Mode::RelayId => relay_id(&extra),
        Mode::RelayCheck(url) => relay_check(&url),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Load the pairing key, creating it on first run.
fn load_key(extra: &Extra) -> Result<Key, String> {
    let path = extra.config_dir.join("host.key");
    if !extra.new_key {
        if let Some(p) = Pairing::load(&path) {
            return Ok(p.key);
        }
    }
    let key = Key::generate();
    Pairing { key: key.clone(), addrs: Vec::new() }
        .save(&path)
        .map_err(|e| format!("cannot store the pairing key in {}: {}", path.display(), plain_error(&e)))?;
    log!("generated a new pairing key ({})", path.display());
    Ok(key)
}

/// `--relay-check`: needs no key and touches no file.
fn relay_check(url: &str) -> Result<(), String> {
    let line = hyperspace_bridge::check(url)?;
    println!("{line}");
    Ok(())
}

/// `--relay-id`: the id the relay's operator adds to its allow list. It is
/// derived from the pairing key but does not reveal it.
fn relay_id(extra: &Extra) -> Result<(), String> {
    if extra.new_key {
        return Err("--relay-id cannot be combined with --new-key".into());
    }
    let key = load_key(extra)?;
    println!("{}", RoomKey::derive(&key).id().hex());
    eprintln!("(give this relay id to the operator of the relay; it changes only with --new-key)");
    Ok(())
}

/// The relay to use: from `--relay` (and saved for the next runs), else the
/// saved setting. There is no default relay.
fn relay_setting(extra: &Extra) -> Option<RelayUrl> {
    let path = extra.config_dir.join("relay.txt");
    match &extra.relay {
        RelayArg::Set(url) => {
            let saved = std::fs::create_dir_all(&extra.config_dir).and_then(|_| std::fs::write(&path, format!("{url}\n")));
            match saved {
                Ok(()) => log!("relay setting saved to {} (--relay off removes it)", path.display()),
                Err(e) => log!(
                    "cannot save the relay setting to {}, using it for this run only: {}",
                    path.display(),
                    plain_error(&e)
                ),
            }
            Some(url.clone())
        }
        RelayArg::Off => {
            match std::fs::remove_file(&path) {
                Ok(()) => log!("relay setting removed: clients connect over UDP only"),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => log!("cannot remove {}, not using a relay for this run: {}", path.display(), plain_error(&e)),
            }
            None
        }
        RelayArg::Unset => match std::fs::read_to_string(&path) {
            Ok(text) if text.trim().is_empty() => None,
            Ok(text) => match RelayUrl::parse(text.trim()) {
                Ok(url) => Some(url),
                Err(e) => {
                    log!("ignoring the relay setting in {}: {e}", path.display());
                    None
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                log!("cannot read {}, not using a relay: {}", path.display(), plain_error(&e));
                None
            }
        },
    }
}

/// Where the relay bridge sends its clients' datagrams: the server's own
/// address, or loopback when the server listens on every address.
fn relay_target(local: SocketAddr) -> SocketAddr {
    let port = local.port();
    let can_bind = |ip: IpAddr| std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok();
    match local.ip() {
        ip if !ip.is_unspecified() => local,
        // A dual-stack socket takes both; ::1 also reaches a v6-only one.
        IpAddr::V6(_) if can_bind(Ipv6Addr::LOCALHOST.into()) => SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
        _ => SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
    }
}

/// Binds the server's socket, then takes the relay setting: a run that fails
/// to start saves nothing.
fn start_server(cfg: &Config, extra: &Extra) -> Result<(server::Server, Option<RelayUrl>), String> {
    let server = server::Server::new(cfg.clone())?;
    log!(
        "hyperspace-host {} listening on udp {}",
        env!("CARGO_PKG_VERSION"),
        server.local_addr().map(|a| a.to_string()).unwrap_or_else(|| cfg.port.to_string())
    );
    let relay = relay_setting(extra);
    Ok((server, relay))
}

/// True while serve() still has goodbyes to send: the BYE to a client, the
/// release of held keys, the close of the relay link and the withdrawal of
/// the router's mappings. When the console window is closed, Windows ends
/// the process as soon as the console handler returns, so the handler waits
/// for this to clear.
static SERVING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Holds SERVING up until it is dropped, which also covers serve()'s early
/// returns.
struct Serving(&'static std::sync::atomic::AtomicBool);

impl Serving {
    fn start() -> Serving {
        Serving::hold(&SERVING)
    }

    /// The same for any flag: a test holds one of its own.
    fn hold(flag: &'static std::sync::atomic::AtomicBool) -> Serving {
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        Serving(flag)
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// serve()'s last goodbyes, in this order: the relay link closes, the reach
/// thread withdraws the router's mappings, and only then does `serving`
/// clear its flag, so a console being closed ends the process after all of
/// them.
fn wind_down<B>(bridge: Option<B>, reach: std::thread::JoinHandle<()>, serving: Serving) {
    drop(bridge);
    let _ = reach.join();
    drop(serving);
}

/// Waits until `flag` is false, for at most `limit`. True if it cleared in
/// time.
#[cfg(any(windows, test))]
fn wait_while(flag: &std::sync::atomic::AtomicBool, limit: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + limit;
    loop {
        if !flag.load(std::sync::atomic::Ordering::SeqCst) {
            return true;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return false;
        }
        std::thread::sleep((deadline - now).min(std::time::Duration::from_millis(10)));
    }
}

fn serve(mut cfg: Config, extra: Extra) -> Result<(), String> {
    let serving = Serving::start();
    #[cfg(windows)]
    win::process_setup();
    cfg.key = load_key(&extra)?;
    let (mut server, relay) = start_server(&cfg, &extra)?;
    let local = server.local_addr();
    // Kept until the server stops: dropping it closes the relay link.
    let mut bridge = None;
    if let Some(url) = &relay {
        log!("relay: {url} (relay id {})", RoomKey::derive(&cfg.key).id().hex());
        let target = relay_target(local.unwrap_or_else(|| SocketAddr::from((Ipv4Addr::LOCALHOST, cfg.port))));
        match HostBridge::start(&url.to_string(), &cfg.key, target, server.relayed_peers()) {
            Ok(b) => bridge = Some(b),
            // The bridge's errors already say "cannot start the relay link".
            Err(e) => log!("relay: {e}"),
        }
    }
    let reach = {
        let opts = reach::Options {
            key: cfg.key.clone(),
            port: cfg.port,
            upnp: extra.upnp,
            dht: extra.dht,
            public_host: extra.public_host,
            config_dir: extra.config_dir,
            relay: relay.as_ref().map(|u| u.to_string()),
        };
        std::thread::Builder::new().name("reach".into()).spawn(move || reach::run(opts)).map_err(|e| plain_error(&e))?
    };
    let result = server.run();
    // Let the reach thread withdraw the router's port mapping.
    server::SHUTDOWN.store(true, std::sync::atomic::Ordering::Relaxed);
    // The client has its BYE: close the relay link and wait for the router's
    // mappings to be withdrawn before a closing console may end the process.
    wind_down(bridge, reach, serving);
    result
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
        *sink.dump.lock().unwrap() =
            Some(std::fs::File::create(p).map_err(|e| format!("{}: {}", p.display(), plain_error(&e)))?);
    }
    let ctl = Arc::new(Control::default());
    let req = StreamRequest { codecs: wire::CODEC_MASK_ALL, fps: 60, bitrate_kbps: 0, wan: false };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_closing_console_waits_for_the_goodbyes_and_no_longer() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        // Cleared while waiting: the wait ends then, well before its limit.
        let busy = Arc::new(AtomicBool::new(true));
        let clear = {
            let busy = busy.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                busy.store(false, Ordering::SeqCst);
            })
        };
        let start = Instant::now();
        assert!(wait_while(&busy, Duration::from_secs(3)));
        assert!(start.elapsed() < Duration::from_secs(2), "waited {:?}", start.elapsed());
        clear.join().unwrap();

        // Never cleared: the wait gives up at its limit.
        let stuck = AtomicBool::new(true);
        let start = Instant::now();
        assert!(!wait_while(&stuck, Duration::from_millis(100)));
        let took = start.elapsed();
        assert!(took >= Duration::from_millis(100) && took < Duration::from_secs(2), "waited {took:?}");

        // Already clear: no wait at all.
        assert!(wait_while(&AtomicBool::new(false), Duration::ZERO));
    }

    #[test]
    fn serving_holds_until_it_is_dropped() {
        use std::sync::atomic::Ordering;
        // No test runs serve(), so nothing else touches SERVING.
        let serving = Serving::start();
        assert!(SERVING.load(Ordering::SeqCst));
        drop(serving);
        assert!(!SERVING.load(Ordering::SeqCst));
    }

    #[test]
    fn serving_clears_only_once_the_router_mappings_are_withdrawn() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;
        // A flag of this test's own, so the test above keeps SERVING to itself.
        static FLAG: AtomicBool = AtomicBool::new(false);
        static HELD_WHILE_WITHDRAWING: AtomicBool = AtomicBool::new(false);
        let serving = Serving::hold(&FLAG);
        // Stands in for the reach thread, still busy with the router when
        // serve() winds down.
        let reach = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(200));
            HELD_WHILE_WITHDRAWING.store(FLAG.load(Ordering::SeqCst), Ordering::SeqCst);
        });
        wind_down(None::<()>, reach, serving);
        assert!(HELD_WHILE_WITHDRAWING.load(Ordering::SeqCst), "the flag cleared before the mappings were withdrawn");
        assert!(!FLAG.load(Ordering::SeqCst));
    }

    fn extra(dir: &std::path::Path, relay: RelayArg) -> Extra {
        Extra { upnp: false, dht: false, public_host: None, new_key: false, config_dir: dir.to_path_buf(), relay }
    }

    /// A directory of this test's own, not created yet.
    fn temp_dir(test: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!("hyperspace-host-{test}-{}-{nanos}", std::process::id()))
    }

    fn listening_on(bind: SocketAddr) -> Config {
        Config {
            bind: Some(bind),
            port: bind.port(),
            key: Key::generate(),
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
        }
    }

    #[test]
    fn a_host_that_cannot_bind_saves_no_relay_setting() {
        let dir = temp_dir("bind");
        let file = dir.join("relay.txt");
        let url = RelayUrl::parse("wss://relay.example").unwrap();
        let taken = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = taken.local_addr().unwrap();
        let e = start_server(&listening_on(addr), &extra(&dir, RelayArg::Set(url.clone()))).err().expect("the port is taken");
        assert!(e.starts_with(&format!("cannot bind UDP port {}: ", addr.port())), "{e}");
        assert!(!e.contains("os error"), "{e}");
        assert!(!file.exists(), "{e}");
        // The same run on a free port saves it.
        let (server, relay) = start_server(&listening_on("127.0.0.1:0".parse().unwrap()), &extra(&dir, RelayArg::Set(url))).unwrap();
        assert!(server.local_addr().is_some_and(|a| a.port() != 0));
        assert_eq!(relay.map(|u| u.to_string()).as_deref(), Some("wss://relay.example/v1"));
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "wss://relay.example/v1\n");
        drop((server, taken));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_relay_setting_is_kept_until_turned_off() {
        let dir = temp_dir("setting");
        let file = dir.join("relay.txt");
        let url = RelayUrl::parse("wss://relay.example").unwrap();
        let setting = |relay: RelayArg| relay_setting(&extra(&dir, relay)).map(|u| u.to_string());

        // No flag and nothing saved: no relay (there is no default one).
        assert_eq!(setting(RelayArg::Unset), None);
        // --relay saves it (creating the directory) and later runs use it.
        assert_eq!(setting(RelayArg::Set(url.clone())).as_deref(), Some("wss://relay.example/v1"));
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "wss://relay.example/v1\n");
        assert_eq!(setting(RelayArg::Unset).as_deref(), Some("wss://relay.example/v1"));
        // --relay off removes it, and saying it again is fine.
        assert_eq!(setting(RelayArg::Off), None);
        assert!(!file.exists());
        assert_eq!(setting(RelayArg::Off), None);
        assert_eq!(setting(RelayArg::Unset), None);
        // A file edited by hand: read leniently, ignored if invalid.
        std::fs::write(&file, "  WSS://Relay.Example:8443/hs \r\n").unwrap();
        assert_eq!(setting(RelayArg::Unset).as_deref(), Some("wss://relay.example:8443/hs"));
        std::fs::write(&file, "https://relay.example\n").unwrap();
        assert_eq!(setting(RelayArg::Unset), None);
        std::fs::write(&file, "\n").unwrap();
        assert_eq!(setting(RelayArg::Unset), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_relay_bridge_sends_to_the_server() {
        let any_v4: SocketAddr = "0.0.0.0:45800".parse().unwrap();
        assert_eq!(relay_target(any_v4), "127.0.0.1:45800".parse().unwrap());
        let any_v6 = relay_target("[::]:45800".parse().unwrap());
        assert!(any_v6.ip().is_loopback() && any_v6.port() == 45800, "{any_v6}");
        let one: SocketAddr = "192.0.2.10:45801".parse().unwrap();
        assert_eq!(relay_target(one), one);
    }
}
