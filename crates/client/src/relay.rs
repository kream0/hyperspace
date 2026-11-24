//! The relay fallback, client side: which relay to use (the `--relay` flag,
//! the saved setting, or the pairing string's), and the link to it, which
//! joins the race of the host's direct addresses.

use hyperspace_bridge::{ClientBridge, LinkStats, RelayUrl, Status};
use hyperspace_proto::log;
use hyperspace_proto::relay::refused;
use hyperspace_proto::secure::Key;
use std::net::SocketAddr;
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

/// The link to the relay. Owned by the thread that runs the sessions; every
/// call returns at once (the link runs on a thread of its own).
pub struct Relay {
    url: String,
    host: String,
    key: Key,
    bridge: Option<ClientBridge>,
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
    /// asks for a new one if the host closed the last. Returns the loopback
    /// address that stands for the host, or None if the link cannot start.
    pub fn start(&mut self) -> Option<SocketAddr> {
        if let Some(b) = &self.bridge {
            if b.status() == Status::ClosedByHost {
                b.reconnect();
            }
            return Some(b.local_addr());
        }
        match ClientBridge::start(&self.url, &self.key) {
            Ok((bridge, addr)) => {
                self.bridge = Some(bridge);
                self.start_error = None;
                self.reconnects_seen = 0;
                self.last_report = Instant::now();
                Some(addr)
            }
            Err(e) => {
                log!("relay: cannot start the relay link: {e}");
                self.start_error = Some(e);
                None
            }
        }
    }

    /// The host answered directly: the link is not needed.
    pub fn stop(&mut self) {
        if self.bridge.is_some() {
            self.report();
            self.bridge = None;
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
        match status {
            Status::Connecting => "no answer from the relay yet (still connecting).".to_string(),
            Status::CannotReach(why) => {
                format!("the relay is not reachable: {why}. On a company network, ask IT to allow {}.", self.host)
            }
            Status::RelayBusy => "the relay is busy; retrying.".to_string(),
            Status::Refused(refused::NOT_ALLOWED) => "this relay does not serve this PC yet: its operator must add the \
                 PC's relay id (shown by hyperspace-host --relay-id)."
                .to_string(),
            Status::Refused(r) => format!("the relay refused the connection: {}.", refused::describe(r)),
            Status::HostOffline => "the PC is not connected to the relay (host not running, older than 0.3.0, or \
                 started without --relay)."
                .to_string(),
            Status::HostOnline => "the PC is connected to the relay but did not answer.".to_string(),
            Status::ClosedByHost => "the host closed this connection through the relay.".to_string(),
            Status::Closed(why) => format!("the relay link stopped: {why}."),
        }
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
