//! Relay addresses: `wss://host[:port][/path]`, or `ws://` for a relay
//! without TLS (tests, or a relay reached on a private network).

use std::fmt;

use hyperspace_proto::{pairing, relay};

/// A checked relay address. Its text form (Display) is what gets saved and
/// put in the pairing string, so it only contains characters a shell leaves
/// alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayUrl {
    tls: bool,
    host: String,
    port: u16,
    path: String,
}

impl RelayUrl {
    pub fn parse(text: &str) -> Result<RelayUrl, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("the relay address is empty".into());
        }
        if let Some(c) = text.chars().find(|c| !c.is_ascii_graphic() || *c == ',') {
            return Err(format!("the relay address cannot contain {c:?}"));
        }
        let lower = text.to_ascii_lowercase();
        // The prefixes are ASCII, so slicing after them stays on a char boundary.
        let (tls, rest) = if lower.starts_with("wss://") {
            (true, &text[6..])
        } else if lower.starts_with("ws://") {
            (false, &text[5..])
        } else {
            return Err(format!("the relay address must start with wss:// (or ws:// without TLS), not {text:?}"));
        };
        if rest.contains(&['?', '#'][..]) {
            return Err("the relay address cannot have a query or fragment ('?', '#')".into());
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        if authority.contains('@') {
            return Err("the relay address cannot carry a user name or password".into());
        }
        if authority.contains(&['[', ']'][..]) || authority.matches(':').count() > 1 {
            return Err("use the relay's host name, not an IPv6 address".into());
        }
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => {
                let port: u16 = port.parse().map_err(|_| format!("bad port {port:?} in the relay address"))?;
                if port == 0 {
                    return Err("bad port 0 in the relay address".into());
                }
                (host, port)
            }
            None => (authority, if tls { 443 } else { 80 }),
        };
        if host.is_empty() {
            return Err("the relay address has no host name".into());
        }
        if host.len() > 253 || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b)) {
            return Err(format!("bad host name {host:?} in the relay address"));
        }
        if !path.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._/".contains(&b)) {
            return Err(format!("the relay address path {path:?} can only use letters, digits and - . _ /"));
        }
        let path = if path.is_empty() || path == "/" { relay::PATH.to_string() } else { path.to_string() };
        let url = RelayUrl { tls, host: host.to_ascii_lowercase(), port, path };
        pairing::check_relay_url(&url.to_string())?;
        Ok(url)
    }

    pub fn tls(&self) -> bool {
        self.tls
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

impl fmt::Display for RelayUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (scheme, default) = if self.tls { ("wss", 443) } else { ("ws", 80) };
        write!(f, "{scheme}://{}", self.host)?;
        if self.port != default {
            write!(f, ":{}", self.port)?;
        }
        f.write_str(&self.path)
    }
}

impl std::str::FromStr for RelayUrl {
    type Err = String;

    fn from_str(s: &str) -> Result<RelayUrl, String> {
        RelayUrl::parse(s)
    }
}
