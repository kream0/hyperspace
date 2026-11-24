//! hyperspace-client: shows a hyperspace host's desktop and forwards input.

mod headless;
#[cfg(target_os = "macos")]
mod keymap;
#[cfg(target_os = "macos")]
mod mac;
mod session;

use hyperspace_proto::pairing::{config_dir, resolve_addr, Pairing};
use hyperspace_proto::secure::Key;
use hyperspace_proto::{wire, Codec, DEFAULT_PORT};
use std::net::SocketAddr;
use std::path::PathBuf;

const HELP: &str = "\
hyperspace-client - low-latency remote desktop client

USAGE:
    hyperspace-client pair <PAIRING-STRING>   Remember a host (once; the host prints the string)
    hyperspace-client [OPTIONS]               Connect to the remembered host, wherever you are
    hyperspace-client <HOST[:PORT]> [OPTIONS] Connect to the remembered host at this address

OPTIONS:
    --fps <N>             Frame rate to request [default: this display's refresh rate]
    --bitrate <MBIT>      Video bitrate to request [default: host picks from resolution]
    --codec <h264|hevc>   Only accept this codec [default: either, host prefers hevc]
    --packet-size <N>     Largest UDP payload to receive [default: host decides]
    --no-lookup           Only try the addresses already known for the host
    --connect-timeout <S> Give up connecting after S seconds [default: 15]
    --config-dir <DIR>    Where the remembered host is kept
    --fullscreen          Start in fullscreen
    --cmd-as-ctrl         Send the Command key as Ctrl instead of the Windows key
    --stats               Print stream statistics every second
    --headless            No window: receive and validate the stream only
    --frames <N>          Exit after N frames (testing)
    --test-input          Headless: send a few synthetic input events
    --test-keyframes      Headless: request a keyframe every 150 ms
    -h, --help            Show this help
    -V, --version         Show version

SHORTCUTS (macOS window):
    Ctrl+Option+Cmd+Q     Disconnect and quit
    Ctrl+Option+Cmd+F     Toggle fullscreen
    Ctrl+Option+Cmd+S     Toggle the statistics overlay in the title bar
";

#[derive(Clone, Debug)]
pub struct Args {
    pub key: Key,
    /// Addresses to try for the host.
    pub candidates: Vec<SocketAddr>,
    /// Allow looking up the host's current address.
    pub lookup: bool,
    pub connect_timeout: std::time::Duration,
    pub host_name: String,
    /// Where the remembered host is stored.
    pub saved_path: PathBuf,
    /// 0 = auto.
    pub fps: u16,
    pub bitrate_kbps: u32,
    pub codecs: u8,
    pub max_datagram: u16,
    pub fullscreen: bool,
    pub cmd_as_ctrl: bool,
    pub stats: bool,
    pub headless: bool,
    pub frames: Option<u64>,
    pub test_input: bool,
    pub test_keyframes: bool,
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut positional: Vec<String> = Vec::new();
    let mut dir = config_dir();
    let mut a = Args {
        key: Key::from_bytes([0; 32]),
        candidates: Vec::new(),
        lookup: true,
        connect_timeout: std::time::Duration::from_secs(15),
        host_name: String::new(),
        saved_path: PathBuf::new(),
        fps: 0,
        bitrate_kbps: 0,
        codecs: wire::CODEC_MASK_ALL,
        max_datagram: 0,
        fullscreen: false,
        cmd_as_ctrl: false,
        stats: false,
        headless: !cfg!(target_os = "macos"),
        frames: None,
        test_input: false,
        test_keyframes: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut val = |name: &str| args.next().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("hyperspace-client {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--fps" => {
                a.fps = val("--fps")?.parse().map_err(|_| "invalid --fps")?;
                if !(1..=480).contains(&a.fps) {
                    return Err("--fps must be 1..=480".into());
                }
            }
            "--bitrate" => {
                let m: f64 = val("--bitrate")?.parse().map_err(|_| "invalid --bitrate")?;
                if !(0.1..=1000.0).contains(&m) {
                    return Err("--bitrate is in Mbit/s (0.1 - 1000)".into());
                }
                a.bitrate_kbps = (m * 1000.0) as u32;
            }
            "--codec" => {
                a.codecs = match val("--codec")?.as_str() {
                    "h264" | "avc" => Codec::H264.mask(),
                    "hevc" | "h265" => Codec::Hevc.mask(),
                    other => return Err(format!("unknown codec '{other}'")),
                }
            }
            "--packet-size" => {
                let n: usize = val("--packet-size")?.parse().map_err(|_| "invalid --packet-size")?;
                if !(wire::MIN_DATAGRAM..=wire::MAX_DATAGRAM).contains(&n) {
                    return Err(format!("--packet-size must be {}..={}", wire::MIN_DATAGRAM, wire::MAX_DATAGRAM));
                }
                a.max_datagram = n as u16;
            }
            "--no-lookup" => a.lookup = false,
            "--connect-timeout" => {
                let secs: f64 = val("--connect-timeout")?.parse().map_err(|_| "invalid --connect-timeout")?;
                a.connect_timeout = std::time::Duration::from_secs_f64(secs.clamp(0.5, 600.0));
            }
            "--config-dir" => dir = val("--config-dir")?.into(),
            "--fullscreen" => a.fullscreen = true,
            "--cmd-as-ctrl" => a.cmd_as_ctrl = true,
            "--stats" => a.stats = true,
            "--headless" => a.headless = true,
            "--frames" => a.frames = Some(val("--frames")?.parse().map_err(|_| "invalid --frames")?),
            "--test-input" => a.test_input = true,
            "--test-keyframes" => a.test_keyframes = true,
            s if s.starts_with('-') => return Err(format!("unknown option '{s}' (try --help)")),
            s => positional.push(s.to_string()),
        }
    }
    a.saved_path = dir.join("host.txt");
    let saved = Pairing::load(&a.saved_path);
    let save = |p: &Pairing| p.save(&a.saved_path).map_err(|e| format!("cannot save to {}: {e}", a.saved_path.display()));

    let pos: Vec<&str> = positional.iter().map(String::as_str).collect();
    let pairing = match pos.as_slice() {
        ["pair", s] => {
            let p = Pairing::parse(s).ok_or("that is not a pairing string (it starts with 'hs1.')")?;
            save(&p)?;
            println!("Paired. Run `hyperspace-client` to connect.");
            return Ok(None);
        }
        ["pair", ..] => return Err("usage: hyperspace-client pair <PAIRING-STRING>".into()),
        [] => saved.ok_or(
            "no host is paired yet.\nRun hyperspace-host on the PC, then: hyperspace-client pair <the string it prints>",
        )?,
        [s] if Pairing::looks_like(s) => {
            let p = Pairing::parse(s).ok_or("invalid pairing string")?;
            save(&p)?;
            p
        }
        [host] => {
            // An explicit address, authenticated with the remembered key.
            let key = saved.ok_or("no host is paired yet: run `hyperspace-client pair <PAIRING-STRING>` first")?.key;
            a.lookup = false;
            Pairing { key, addrs: vec![host.to_string()] }
        }
        _ => return Err("too many arguments (try --help)".into()),
    };
    a.key = pairing.key.clone();
    for entry in &pairing.addrs {
        for addr in resolve_addr(entry, DEFAULT_PORT) {
            if !a.candidates.contains(&addr) {
                a.candidates.push(addr);
            }
        }
    }
    if a.candidates.is_empty() && !a.lookup {
        return Err(format!("cannot resolve '{}'", pairing.addrs.join(", ")));
    }
    a.host_name = pairing.addrs.first().cloned().unwrap_or_else(|| "host".into()).replace('/', ":");
    Ok(Some(a))
}

impl Args {
    pub fn session_options(&self, fps: u16) -> session::Options {
        session::Options {
            key: self.key.clone(),
            candidates: self.candidates.clone(),
            lookup: self.lookup,
            timeout: self.connect_timeout,
            fps,
            bitrate_kbps: self.bitrate_kbps,
            codecs: self.codecs,
            max_datagram: self.max_datagram,
        }
    }

    /// Remember addresses the lookup service returned, so the next connect is direct.
    pub fn remember(&self, conn: &session::Connection) {
        if conn.learned.is_empty() {
            return;
        }
        let p = Pairing { key: self.key.clone(), addrs: conn.learned.clone() };
        if let Err(e) = p.save(&self.saved_path) {
            hyperspace_proto::log!("could not update {}: {e}", self.saved_path.display());
        }
    }
}

fn main() {
    let args = match parse_args() {
        Ok(Some(a)) => a,
        Ok(None) => return,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };
    let code = if args.headless {
        headless::run(&args)
    } else {
        #[cfg(target_os = "macos")]
        {
            mac::run(&args)
        }
        #[cfg(not(target_os = "macos"))]
        {
            unreachable!("headless is forced on this platform")
        }
    };
    std::process::exit(code);
}

