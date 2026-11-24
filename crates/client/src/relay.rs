//! The relay fallback, client side: which relay to use (the `--relay` flag,
//! the saved setting, or the pairing string's), and the link to it, which
//! joins the race of the host's direct addresses.

use hyperspace_bridge::{ClientBridge, LinkStats, RelayUrl, Status};
use hyperspace_proto::log;
use hyperspace_proto::pairing::{check_relay_url, Pairing, RELAY_PREFIX};
use hyperspace_proto::relay::refused;
use hyperspace_proto::secure::Key;
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

/// How often a session through the relay logs the link's counters.
const REPORT_EVERY: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayArg {
    /// No `--relay`: the saved setting, else the pairing string's relay.
    Unset,
    /// `--relay off`: no relay, even one the pairing string names; saved.
    Off,
    /// `--relay URL`: this relay; saved for the runs that follow.
    Set(RelayUrl),
}

impl RelayArg {
    pub fn parse(value: &str) -> Result<RelayArg, String> {
        if value.trim().eq_ignore_ascii_case("off") {
            Ok(RelayArg::Off)
        } else {
            RelayUrl::parse(value).map(RelayArg::Set).map_err(|e| format!("invalid --relay: {e}"))
        }
    }
}

/// The pairing string's relay. `Pairing::relay` skips an entry that the
/// pairing format rejects: say why in one line rather than drop it unseen.
pub fn from_pairing(p: &Pairing) -> Option<String> {
    let found = p.relay();
    if found.is_none() {
        if let Some(Err(why)) = p.addrs.iter().find_map(|a| a.strip_prefix(RELAY_PREFIX)).map(check_relay_url) {
            log!("ignoring the relay in the pairing string: {why}");
        }
    }
    found
}

/// The relay to use, in its canonical form: `--relay` (saved to `path`),
/// else what `path` holds ("off" or an address), else the pairing string's.
/// There is no built-in relay.
pub fn setting(arg: &RelayArg, path: &Path, pairing: Option<&str>) -> Option<String> {
    let save = |text: &str| -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, text)
    };
    match arg {
        RelayArg::Set(url) => {
            match save(&format!("{url}\n")) {
                Ok(()) => log!("relay setting saved to {} (--relay off turns the relay off)", path.display()),
                Err(e) => log!("cannot save the relay setting to {}: {e}; using it for this run only", path.display()),
            }
            return Some(url.to_string());
        }
        RelayArg::Off => {
            match save("off\n") {
                Ok(()) => log!("relay off (saved in {}; --relay URL turns it back on)", path.display()),
                Err(e) => log!("relay off for this run (cannot save it to {}: {e})", path.display()),
            }
            return None;
        }
        RelayArg::Unset => {}
    }
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let text = text.trim_start_matches('\u{feff}').trim();
            if text.eq_ignore_ascii_case("off") {
                log!("relay off (set in {}; --relay URL turns it back on)", path.display());
                return None;
            }
            if !text.is_empty() {
                match RelayUrl::parse(text) {
                    Ok(url) => return Some(url.to_string()),
                    Err(e) => log!("ignoring the relay setting in {}: {e}", path.display()),
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => log!("cannot read {}: {e}", path.display()),
    }
    match RelayUrl::parse(pairing?) {
        Ok(url) => Some(url.to_string()),
        Err(e) => {
            log!("ignoring the relay in the pairing string: {e}");
            None
        }
    }
}

/// The link's counters in one line.
pub fn stats_line(s: &LinkStats) -> String {
    let mb = |bytes: u64| bytes as f64 / 1e6;
    let up = match s.connected_since {
        Some(t) => format!("up {} s", t.elapsed().as_secs()),
        None => "down".to_string(),
    };
    let mut line = format!(
        "relay link: {up}, {} reconnects, last close: {}, in {:.1} MB / out {:.1} MB, dropped {}",
        s.reconnects,
        s.last_close.as_deref().unwrap_or("none"),
        mb(s.bytes_in),
        mb(s.bytes_out),
        s.dropped
    );
    if s.discarded_while_down > 0 {
        line += &format!(" (and {} while the link was down)", s.discarded_while_down);
    }
    line
}

/// What a status of the relay link means for the user, as one sentence;
/// `host` is the relay's host name, for the IT department.
pub fn status_line(status: Status, host: &str) -> String {
    match status {
        Status::Connecting => "no answer from the relay yet (still connecting).".to_string(),
        Status::CannotReach(why) => format!(
            "the relay is not reachable: {}. On a company network, ask IT to allow {host}.",
            why.trim_end_matches('.')
        ),
        Status::RelayBusy => "the relay is busy; retrying.".to_string(),
        Status::Refused(refused::NOT_ALLOWED) => "this relay does not serve this PC yet: its operator must add the \
             PC's relay id (hyperspace-host --relay-id prints it)."
            .to_string(),
        Status::Refused(r) => format!("the relay refused the connection: {}.", refused::describe(r)),
        Status::HostOffline => "the PC is not connected to the relay (host not running, older than 0.3.0, or \
             started without --relay)."
            .to_string(),
        Status::HostOnline => "the PC is connected to the relay but did not answer.".to_string(),
        Status::ClosedByHost => "the host closed this connection through the relay.".to_string(),
        Status::Closed(why) => format!("the relay link stopped: {}.", why.trim_end_matches('.')),
    }
}

/// The link to the relay. Owned by the thread that runs the sessions; every
/// call returns at once (the link runs on a thread of its own).
pub struct Relay {
    url: String,
    host: String,
    key: Key,
    bridge: Option<ClientBridge>,
    /// The one socket that talks to the link, for the link's whole life: the
    /// link serves only the first local socket that sends to it.
    sock: Option<UdpSocket>,
    start_error: Option<String>,
    /// The relay carried the last session: the next race starts with it.
    won_last: bool,
    reconnects_seen: u64,
    last_report: Instant,
}

impl Relay {
    pub fn new(url: String, key: Key) -> Relay {
        let host = RelayUrl::parse(&url).map(|u| u.host().to_string()).unwrap_or_else(|_| url.clone());
        Relay {
            url,
            host,
            key,
            bridge: None,
            sock: None,
            start_error: None,
            won_last: false,
            reconnects_seen: 0,
            last_report: Instant::now(),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Starts the link unless it runs (it comes up in the background), and
    /// asks for a new one if the host closed the last. Returns a handle on
    /// the link's one socket, with the loopback address that stands for the
    /// host, or None if the link cannot start.
    pub fn start(&mut self) -> Option<(UdpSocket, SocketAddr)> {
        match self.bridge.as_ref().map(ClientBridge::status) {
            None => {}
            // The link stopped for good: a new one (and a new socket), below.
            Some(Status::Closed(why)) => {
                log!("relay: starting a new relay link (the last one stopped: {why})");
                self.report();
                self.bridge = None;
                self.sock = None;
            }
            Some(status) => {
                if status == Status::ClosedByHost {
                    // Called once per connect attempt, and attempts back off.
                    if let Some(b) = &self.bridge {
                        b.reconnect();
                    }
                }
                return self.socket();
            }
        }
        let (bridge, addr) = match ClientBridge::start(&self.url, &self.key) {
            Ok(started) => started,
            Err(e) => {
                log!("relay: cannot start the relay link: {e}");
                self.start_error = Some(e);
                return None;
            }
        };
        match crate::session::relay_socket(addr) {
            Ok(sock) => {
                self.bridge = Some(bridge);
                self.sock = Some(sock);
                self.start_error = None;
                self.reconnects_seen = 0;
                self.last_report = Instant::now();
                self.socket()
            }
            Err(e) => {
                // The link is of no use without it: it closes here.
                log!("relay: cannot use the relay: no local socket for it ({e})");
                self.start_error = Some(format!("no local socket for it ({e})"));
                None
            }
        }
    }

    /// A handle on the link's one socket for one connect, with what the last
    /// session left in it dropped.
    fn socket(&self) -> Option<(UdpSocket, SocketAddr)> {
        let (bridge, sock) = (self.bridge.as_ref()?, self.sock.as_ref()?);
        let handle = sock.try_clone().and_then(|s| s.set_nonblocking(true).map(|()| s));
        match handle {
            Ok(s) => {
                let mut buf = [0u8; 2048];
                for _ in 0..100_000 {
                    if s.recv(&mut buf).is_err() {
                        break;
                    }
                }
                Some((s, bridge.local_addr()))
            }
            Err(e) => {
                log!("relay: cannot use the relay link's socket: {e}");
                None
            }
        }
    }

    /// The host answered directly: the link is not needed.
    pub fn stop(&mut self) {
        if self.bridge.is_some() {
            self.report();
            self.bridge = None;
            self.sock = None;
            log!("relay link closed: the host answered directly");
        }
        self.won_last = false;
    }

    /// The relay carried this session.
    pub fn won(&mut self) {
        self.won_last = true;
    }

    pub fn won_last(&self) -> bool {
        self.won_last
    }

    pub fn status(&self) -> Option<Status> {
        self.bridge.as_ref().map(ClientBridge::status)
    }

    /// See [`ClientBridge::hosts_seen`]: a rise means a new handshake.
    pub fn hosts_seen(&self) -> u64 {
        self.bridge.as_ref().map_or(0, ClientBridge::hosts_seen)
    }

    /// Waiting longer for the relay cannot help.
    pub fn failed(&self) -> bool {
        match self.status() {
            None => true,
            Some(Status::Refused(r)) => !matches!(r, refused::TIMEOUT | refused::ROOM_FULL | refused::RELAY_FULL),
            Some(Status::Closed(_)) => true,
            Some(_) => false,
        }
    }

    /// Why the host did not answer through the relay, in words a user can
    /// act on.
    pub fn diagnose(&self) -> String {
        let Some(status) = self.status() else {
            return match &self.start_error {
                Some(e) => format!("the relay link could not start: {e}."),
                None => "not tried.".to_string(),
            };
        };
        status_line(status, &self.host)
    }

    /// Once a second during a session: a line when the link came back after
    /// a cut, and the counters every minute.
    pub fn tick(&mut self) {
        let Some(b) = &self.bridge else { return };
        let s = b.stats();
        if s.reconnects > self.reconnects_seen {
            self.reconnects_seen = s.reconnects;
            log!(
                "relay link reconnected ({} reconnects so far); it had closed: {}",
                s.reconnects,
                s.last_close.as_deref().unwrap_or("unknown")
            );
        }
        if self.last_report.elapsed() >= REPORT_EVERY {
            self.report();
        }
    }

    /// Logs the link's counters.
    pub fn report(&mut self) {
        let Some(b) = &self.bridge else { return };
        let line = stats_line(&b.stats());
        self.last_report = Instant::now();
        log!("{line}");
    }
}

impl Drop for Relay {
    /// The counters once more at exit, then the link closes.
    fn drop(&mut self) {
        self.report();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        std::env::temp_dir().join(format!("hyperspace-client-test-{name}-{}-{nanos}", std::process::id()))
    }

    fn set(url: &str) -> RelayArg {
        RelayArg::parse(url).unwrap()
    }

    #[test]
    fn relay_flag_beats_saved_setting_beats_pairing() {
        let dir = temp_dir("precedence");
        let path = dir.join("relay.txt");
        let pairing = Some("wss://pairing.example/v1");

        // Nothing saved: the pairing's relay, or none at all (no default).
        assert_eq!(setting(&RelayArg::Unset, &path, None), None);
        assert_eq!(setting(&RelayArg::Unset, &path, pairing).as_deref(), pairing);

        // The flag wins over the pairing and is saved (creating the directory).
        assert_eq!(setting(&set("wss://flag.example"), &path, pairing).as_deref(), Some("wss://flag.example/v1"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "wss://flag.example/v1\n");

        // A later run without the flag uses the saved one, over the pairing's:
        // an old pairing string (no relay) plus one --relay is enough.
        assert_eq!(setting(&RelayArg::Unset, &path, pairing).as_deref(), Some("wss://flag.example/v1"));
        assert_eq!(setting(&RelayArg::Unset, &path, None).as_deref(), Some("wss://flag.example/v1"));

        // A new flag replaces the saved one.
        assert_eq!(setting(&set("ws://127.0.0.1:47811"), &path, pairing).as_deref(), Some("ws://127.0.0.1:47811/v1"));
        assert_eq!(setting(&RelayArg::Unset, &path, None).as_deref(), Some("ws://127.0.0.1:47811/v1"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn relay_off_disables_even_the_pairings_relay() {
        let dir = temp_dir("off");
        let path = dir.join("relay.txt");
        let pairing = Some("wss://pairing.example/v1");

        assert_eq!(setting(&RelayArg::Off, &path, pairing), None);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "off\n");
        assert_eq!(setting(&RelayArg::Unset, &path, pairing), None);
        // Written by hand, any case, with Windows line ends.
        std::fs::write(&path, "\u{feff} OFF\r\n").unwrap();
        assert_eq!(setting(&RelayArg::Unset, &path, pairing), None);
        // --relay URL turns it back on.
        assert_eq!(setting(&set("wss://relay.example"), &path, pairing).as_deref(), Some("wss://relay.example/v1"));
        assert_eq!(setting(&RelayArg::Unset, &path, pairing).as_deref(), Some("wss://relay.example/v1"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn saved_setting_is_read_leniently() {
        let dir = temp_dir("lenient");
        let path = dir.join("relay.txt");
        std::fs::create_dir_all(&dir).unwrap();

        std::fs::write(&path, "  WSS://Relay.Example:8443/hs \r\n").unwrap();
        assert_eq!(setting(&RelayArg::Unset, &path, None).as_deref(), Some("wss://relay.example:8443/hs"));
        // Not a relay address, or empty: ignored, the pairing's relay is used.
        std::fs::write(&path, "https://relay.example\n").unwrap();
        assert_eq!(setting(&RelayArg::Unset, &path, Some("wss://pairing.example/v1")).as_deref(), Some("wss://pairing.example/v1"));
        assert_eq!(setting(&RelayArg::Unset, &path, None), None);
        std::fs::write(&path, "\n").unwrap();
        assert_eq!(setting(&RelayArg::Unset, &path, Some("wss://pairing.example/v1")).as_deref(), Some("wss://pairing.example/v1"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn relay_flag_values() {
        assert_eq!(RelayArg::parse("off").unwrap(), RelayArg::Off);
        assert_eq!(RelayArg::parse(" Off ").unwrap(), RelayArg::Off);
        assert!(matches!(RelayArg::parse("wss://relay.example"), Ok(RelayArg::Set(u)) if u.to_string() == "wss://relay.example/v1"));
        assert!(RelayArg::parse("relay.example").unwrap_err().starts_with("invalid --relay: "));
        assert!(RelayArg::parse("").is_err());
    }

    #[test]
    fn link_stats_line() {
        let mut s = LinkStats::default();
        assert_eq!(stats_line(&s), "relay link: down, 0 reconnects, last close: none, in 0.0 MB / out 0.0 MB, dropped 0");
        s.connected_since = Some(Instant::now());
        s.reconnects = 2;
        s.last_close = Some("no traffic for 35 s".into());
        s.bytes_in = 12_345_678;
        s.bytes_out = 260_000;
        s.dropped = 3;
        s.discarded_while_down = 7;
        assert_eq!(
            stats_line(&s),
            "relay link: up 0 s, 2 reconnects, last close: no traffic for 35 s, in 12.3 MB / out 0.3 MB, dropped 3 \
             (and 7 while the link was down)"
        );
    }

    #[test]
    fn every_status_has_its_line() {
        let host = "relay.example";
        let cases = [
            (
                Status::CannotReach("cannot connect to relay.example port 443: timed out.".into()),
                "the relay is not reachable: cannot connect to relay.example port 443: timed out. On a company \
                 network, ask IT to allow relay.example.",
            ),
            (
                Status::Refused(refused::NOT_ALLOWED),
                "this relay does not serve this PC yet: its operator must add the PC's relay id \
                 (hyperspace-host --relay-id prints it).",
            ),
            (
                Status::HostOffline,
                "the PC is not connected to the relay (host not running, older than 0.3.0, or started without \
                 --relay).",
            ),
            (Status::RelayBusy, "the relay is busy; retrying."),
            (Status::Connecting, "no answer from the relay yet (still connecting)."),
            (Status::HostOnline, "the PC is connected to the relay but did not answer."),
            (Status::ClosedByHost, "the host closed this connection through the relay."),
            (Status::Closed("the local socket failed".into()), "the relay link stopped: the local socket failed."),
        ];
        for (status, line) in cases {
            assert_eq!(status_line(status, host), line);
        }
        let other = status_line(Status::Refused(refused::RELAY_FULL), host);
        assert!(other.starts_with("the relay refused the connection: ") && other.ends_with('.'), "{other}");
        // No internal names in what the user reads.
        for status in [Status::RelayBusy, Status::HostOffline, Status::Refused(refused::NOT_ALLOWED)] {
            let line = status_line(status, host);
            assert!(!line.contains("Status") && !line.contains("bridge") && !line.contains("room"), "{line}");
        }
    }

    #[test]
    fn the_sessions_socket_hears_only_the_link() {
        for lo in ["127.0.0.1:0", "[::1]:0"] {
            // A machine without IPv6 skips that half.
            let Ok(link) = UdpSocket::bind(lo) else { continue };
            let link_addr = link.local_addr().unwrap();
            let s = crate::session::relay_socket(link_addr).unwrap();
            let mine = s.local_addr().unwrap();
            assert!(mine.ip().is_loopback(), "{mine}");
            assert_eq!(s.peer_addr().unwrap(), link_addr);
            // Another program on this machine sends first: its datagram never arrives.
            let stray = UdpSocket::bind(lo).unwrap();
            stray.send_to(b"stray", mine).unwrap();
            link.send_to(b"link", mine).unwrap();
            s.set_nonblocking(false).unwrap();
            s.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
            let mut buf = [0u8; 16];
            let n = s.recv(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"link");
            assert!(s.recv(&mut buf).is_err(), "a stray datagram got in");
            // What the session sends reaches the link and nobody else.
            s.send(b"out").unwrap();
            link.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
            let (n, from) = link.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"out");
            assert_eq!(from, mine);
            stray.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
            assert!(stray.recv(&mut buf).is_err());
        }
        assert!(crate::session::relay_socket("192.0.2.1:9".parse().unwrap()).is_err());
    }

    #[test]
    fn one_socket_for_the_links_whole_life() {
        // Nothing listens there: the link keeps trying in the background.
        let mut r = Relay::new("ws://127.0.0.1:9/v1".into(), Key::from_bytes([7; 32]));
        let (a, link) = r.start().expect("the link starts");
        let (b, again) = r.start().expect("the same link");
        assert_eq!(link, again);
        assert!(link.ip().is_loopback());
        assert_eq!(a.local_addr().unwrap(), b.local_addr().unwrap());
        assert_eq!(a.peer_addr().unwrap(), link);
        assert!(a.local_addr().unwrap().ip().is_loopback());
        r.stop();
        assert!(r.status().is_none());
        assert!(r.sock.is_none());
    }

    #[test]
    fn a_pairings_bad_relay_entry_is_skipped() {
        let key = Key::from_bytes([7; 32]);
        let p = |addrs: &[&str]| Pairing { key: key.clone(), addrs: addrs.iter().map(|a| a.to_string()).collect() };
        assert_eq!(from_pairing(&p(&["192.0.2.1/45800", "relay=ftp://relay.example"])), None);
        assert_eq!(from_pairing(&p(&["relay="])), None);
        assert_eq!(from_pairing(&p(&["192.0.2.1/45800"])), None);
        let first_good = from_pairing(&p(&["relay=ftp://relay.example", "relay=wss://relay.example/v1"]));
        assert_eq!(first_good.as_deref(), Some("wss://relay.example/v1"));
    }

    #[test]
    fn diagnosis_without_a_link() {
        let mut r = Relay::new("wss://relay.example/v1".into(), Key::from_bytes([7; 32]));
        assert_eq!(r.diagnose(), "not tried.");
        assert!(r.failed());
        assert_eq!(r.hosts_seen(), 0);
        r.start_error = Some("no thread".into());
        assert_eq!(r.diagnose(), "the relay link could not start: no thread.");
        assert_eq!(r.host, "relay.example");
    }
}
