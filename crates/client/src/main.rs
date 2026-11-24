//! hyperspace-client: shows a hyperspace host's desktop and forwards input.

mod headless;
#[cfg(target_os = "macos")]
mod keymap;
#[cfg(target_os = "macos")]
mod mac;
mod session;

use hyperspace_proto::{wire, Codec, DEFAULT_PORT};
use std::net::{SocketAddr, ToSocketAddrs};

const HELP: &str = "\
hyperspace-client - low-latency remote desktop client

USAGE:
    hyperspace-client <HOST[:PORT]> [OPTIONS]

OPTIONS:
    --fps <N>             Frame rate to request [default: this display's refresh rate]
    --bitrate <MBIT>      Video bitrate to request [default: host picks from resolution]
    --codec <h264|hevc>   Only accept this codec [default: either, host prefers hevc]
    --packet-size <N>     Largest UDP payload to receive [default: host's, 1400]
    --fullscreen          Start in fullscreen
    --cmd-as-ctrl         Send the Command key as Ctrl instead of the Windows key
    --stats               Print stream statistics every second
    --headless            No window: receive and validate the stream only
    --frames <N>          Exit after N frames (testing)
    --test-input          Headless: send a few synthetic input events
    -h, --help            Show this help
    -V, --version         Show version

SHORTCUTS (macOS window):
    Ctrl+Option+Cmd+Q     Disconnect and quit
    Ctrl+Option+Cmd+F     Toggle fullscreen
    Ctrl+Option+Cmd+S     Toggle the statistics overlay in the title bar
";

#[derive(Clone, Debug)]
pub struct Args {
    pub host: SocketAddr,
    pub host_name: String,
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
}

fn parse_args() -> Result<Args, String> {
    let mut host_name: Option<String> = None;
    let mut a = Args {
        host: SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT)),
        host_name: String::new(),
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
            "--fullscreen" => a.fullscreen = true,
            "--cmd-as-ctrl" => a.cmd_as_ctrl = true,
            "--stats" => a.stats = true,
            "--headless" => a.headless = true,
            "--frames" => a.frames = Some(val("--frames")?.parse().map_err(|_| "invalid --frames")?),
            "--test-input" => a.test_input = true,
            s if s.starts_with('-') => return Err(format!("unknown option '{s}' (try --help)")),
            s => {
                if host_name.is_some() {
                    return Err("only one host may be given".into());
                }
                host_name = Some(s.to_string());
            }
        }
    }
    let name = host_name.ok_or("missing host address (try --help)")?;
    a.host = resolve(&name)?;
    a.host_name = name;
    Ok(a)
}

/// Accepts `host`, `host:port`, `1.2.3.4`, `[::1]:port`.
fn resolve(name: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = name.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = name.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, DEFAULT_PORT));
    }
    let with_port = if name.rsplit_once(':').is_some_and(|(_, p)| p.parse::<u16>().is_ok()) {
        name.to_string()
    } else {
        format!("{name}:{DEFAULT_PORT}")
    };
    let addrs: Vec<SocketAddr> =
        with_port.to_socket_addrs().map_err(|e| format!("cannot resolve '{name}': {e}"))?.collect();
    // Prefer IPv4: it is what a LAN host is most likely listening on.
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .copied()
        .ok_or(format!("cannot resolve '{name}'"))
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_literals() {
        assert_eq!(resolve("192.168.1.20").unwrap(), "192.168.1.20:45800".parse().unwrap());
        assert_eq!(resolve("192.168.1.20:5000").unwrap(), "192.168.1.20:5000".parse().unwrap());
        assert_eq!(resolve("[::1]:7").unwrap(), "[::1]:7".parse().unwrap());
        assert_eq!(resolve("::1").unwrap().port(), DEFAULT_PORT);
        assert_eq!(resolve("localhost").unwrap().port(), DEFAULT_PORT);
        assert_eq!(resolve("localhost:99").unwrap().port(), 99);
    }
}
