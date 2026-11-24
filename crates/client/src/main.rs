//! hyperspace-client: shows a hyperspace host's desktop and forwards input.

mod headless;
#[cfg(target_os = "macos")]
mod keymap;
#[cfg(target_os = "macos")]
mod mac;
mod relay;
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
    --relay <URL|off>     Also connect through this relay (wss://...) when the host's
                          addresses do not answer; remembered. `off`: never [default:
                          the remembered setting, else the relay in the pairing string]
    --relay-check <URL>   Check that this relay can be reached from here, then exit
    --config-dir <DIR>    Where the remembered host is kept
    --fullscreen          Start in fullscreen
    --cmd-as-ctrl         Send the Command key as Ctrl instead of the Windows key
    --stats               Print stream statistics every second
    --headless            No window: receive and validate the stream only
    --frames <N>          Exit after N frames (testing)
    --test-input          Headless: send a few synthetic input events
    --test-keyframes      Headless: request a keyframe every 150 ms
    --test-reconnect      End the first session 2 s in without a goodbye, then
                          connect again (with a relay set; testing)
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
    pub test_reconnect: bool,
    /// The relay to fall back on (canonical address), if any.
    pub relay: Option<String>,
    /// The relay entry of the saved pairing string, kept when it is updated.
    pub pairing_relay: Option<String>,
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
        test_reconnect: false,
        relay: None,
        pairing_relay: None,
    };
    let mut relay_arg = relay::RelayArg::Unset;
    let mut relay_check: Option<String> = None;
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
            "--test-reconnect" => a.test_reconnect = true,
            "--relay" => relay_arg = relay::RelayArg::parse(&val("--relay")?)?,
            "--relay-check" => relay_check = Some(val("--relay-check")?),
            s if s.starts_with('-') => return Err(format!("unknown option '{s}' (try --help)")),
            s => positional.push(s.to_string()),
        }
    }
    if let Some(url) = relay_check {
        // Needs no pairing: run it before looking for one.
        match hyperspace_bridge::check(&url) {
            Ok(line) => {
                println!("{line}");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }
    let relay_path = dir.join("relay.txt");
    a.saved_path = dir.join("host.txt");
    let saved = Pairing::load(&a.saved_path);
    let save = |p: &Pairing| p.save(&a.saved_path).map_err(|e| format!("cannot save to {}: {e}", a.saved_path.display()));

    let pos: Vec<&str> = positional.iter().map(String::as_str).collect();
    let pairing = match pos.as_slice() {
        ["pair", s] => {
            let p = Pairing::parse(s).ok_or("that is not a pairing string (it starts with 'hs1.')")?;
            save(&p)?;
            if relay_arg != relay::RelayArg::Unset {
                relay::setting(&relay_arg, &relay_path, None);
            }
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
            // An explicit address, authenticated with the remembered key
            // (and its relay, if the remembered pairing names one).
            let saved = saved.ok_or("no host is paired yet: run `hyperspace-client pair <PAIRING-STRING>` first")?;
            a.lookup = false;
            let mut p = Pairing { key: saved.key.clone(), addrs: vec![host.to_string()] };
            p.set_relay(saved.relay().as_deref())?;
            p
        }
        _ => return Err("too many arguments (try --help)".into()),
    };
    a.key = pairing.key.clone();
    for entry in pairing.addresses() {
        for addr in resolve_addr(entry, DEFAULT_PORT) {
            if !a.candidates.contains(&addr) {
                a.candidates.push(addr);
            }
        }
    }
    a.pairing_relay = relay::from_pairing(&pairing);
    a.relay = relay::setting(&relay_arg, &relay_path, a.pairing_relay.as_deref());
    if a.candidates.is_empty() && !a.lookup && a.relay.is_none() {
        return Err(format!("cannot resolve '{}'", pairing.addresses().collect::<Vec<_>>().join(", ")));
    }
    a.host_name = pairing.addresses().next().unwrap_or("host").replace('/', ":");
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
            cut_first_session: self.test_reconnect.then_some(std::time::Duration::from_secs(2)),
        }
    }

    /// The relay link for the sessions, if a relay is set.
    pub fn relay_link(&self) -> Option<relay::Relay> {
        self.relay.clone().map(|url| relay::Relay::new(url, self.key.clone()))
    }

    /// Remember addresses the lookup service returned, so the next connect is direct.
    pub fn remember(&self, conn: &session::Connection) {
        if conn.learned.is_empty() {
            return;
        }
        // The pairing's relay entry stays (the --relay setting has its own file).
        let p = remembered(&self.key, &conn.learned, self.pairing_relay.as_deref());
        if let Err(e) = p.save(&self.saved_path) {
            hyperspace_proto::log!("could not update {}: {e}", self.saved_path.display());
        }
    }
}

/// The pairing to save after a lookup: the addresses it found, and the relay
/// the pairing named, if any.
fn remembered(key: &Key, learned: &[String], relay: Option<&str>) -> Pairing {
    let mut p = Pairing { key: key.clone(), addrs: learned.to_vec() };
    if relay.is_some() {
        if let Err(e) = p.set_relay(relay) {
            hyperspace_proto::log!("not keeping the pairing's relay: {e}");
        }
    }
    p
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembered_addresses_keep_the_relay() {
        let key = Key::from_bytes([3; 32]);
        let learned = vec!["192.0.2.7/45800".to_string(), "2001:db8::7/45800".to_string()];
        let p = remembered(&key, &learned, Some("wss://relay.example/v1"));
        assert_eq!(p.relay().as_deref(), Some("wss://relay.example/v1"));
        assert_eq!(p.addresses().collect::<Vec<_>>(), ["192.0.2.7/45800", "2001:db8::7/45800"]);
        assert_eq!(p.key, key);
        // Through the pairing string and back, as it is saved.
        let back = Pairing::parse(&p.encode()).unwrap();
        assert_eq!(back.relay().as_deref(), Some("wss://relay.example/v1"));
        assert_eq!(back.addresses().count(), 2);

        // No relay in the pairing: none appears.
        let p = remembered(&key, &learned, None);
        assert_eq!(p.relay(), None);
        assert_eq!(p.addrs, learned);

        // A relay entry among the learned addresses is not doubled.
        let mut with_relay = learned.clone();
        with_relay.push("relay=wss://relay.example/v1".into());
        let p = remembered(&key, &with_relay, Some("wss://relay.example/v1"));
        assert_eq!(p.addrs.iter().filter(|a| a.starts_with("relay=")).count(), 1);
        assert_eq!(p.addresses().count(), 2);
    }
}

