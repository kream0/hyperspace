//! The pairing string: everything a client needs to reach and authenticate a
//! host. Printed by the host, pasted once into the client.
//!
//! Format: `hs1.<key>.<addr>/<port>,<addr>/<port>,...` where each address is
//! an IPv4/IPv6 literal or a DNS name. It contains only characters that
//! shells leave alone.

use crate::secure::Key;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pairing {
    pub key: Key,
    /// `host/port` entries, most local first.
    pub addrs: Vec<String>,
}

pub fn format_addr(addr: &SocketAddr) -> String {
    format!("{}/{}", addr.ip().to_canonical(), addr.port())
}

/// Parse `host/port`, `host:port`, `[v6]:port` or a bare host into (host, port).
pub fn split_host_port(s: &str, default_port: u16) -> Option<(String, u16)> {
    if s.is_empty() {
        return None;
    }
    if let Some((h, p)) = s.rsplit_once('/') {
        return Some((h.to_string(), p.parse().ok()?));
    }
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Some((a.ip().to_string(), a.port()));
    }
    if s.parse::<IpAddr>().is_ok() {
        return Some((s.to_string(), default_port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Some((h.to_string(), p.parse().ok()?)),
        _ => Some((s.to_string(), default_port)),
    }
}

/// Resolve one entry to socket addresses (DNS names may yield several).
pub fn resolve_addr(entry: &str, default_port: u16) -> Vec<SocketAddr> {
    let Some((host, port)) = split_host_port(entry, default_port) else { return Vec::new() };
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![SocketAddr::new(ip, port)];
    }
    (host.as_str(), port).to_socket_addrs().map(|a| a.collect()).unwrap_or_default()
}

impl Pairing {
    pub fn encode(&self) -> String {
        format!("hs1.{}.{}", self.key.encode(), self.addrs.join(","))
    }

    pub fn parse(s: &str) -> Option<Pairing> {
        let mut parts = s.trim().splitn(3, '.');
        if parts.next()? != "hs1" {
            return None;
        }
        let key = Key::decode(parts.next()?)?;
        let addrs = parts.next().unwrap_or("").split(',').filter(|a| !a.is_empty()).map(str::to_string).collect();
        Some(Pairing { key, addrs })
    }

    pub fn looks_like(s: &str) -> bool {
        s.trim().starts_with("hs1.")
    }

    pub fn load(path: &Path) -> Option<Pairing> {
        Pairing::parse(&std::fs::read_to_string(path).ok()?)
    }

    /// Write atomically, readable by the owner only where the OS supports it.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("tmp");
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            use std::io::Write;
            let mut f = opts.open(&tmp)?;
            writeln!(f, "{}", self.encode())?;
        }
        std::fs::rename(&tmp, path)
    }
}

/// Where keys and saved hosts live: `%APPDATA%\hyperspace` on Windows,
/// `~/.config/hyperspace` elsewhere.
pub fn config_dir() -> PathBuf {
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    };
    base.unwrap_or_else(|| PathBuf::from(".")).join("hyperspace")
}

/// True for addresses that can only be reached from the same site: private,
/// loopback, link-local and unique-local ranges.
pub fn is_local(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// True for IPv4 addresses that are not routable on the internet although
/// they sit on a router's WAN side: carrier-grade NAT or a second NAT layer.
pub fn is_behind_nat(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let p = Pairing {
            key: Key::generate(),
            addrs: vec!["192.168.1.50/45800".into(), "2a01:e0a:1::5/45800".into(), "home.example.org/4000".into()],
        };
        let s = p.encode();
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric() || "._-/:,".contains(c)), "{s}");
        assert_eq!(Pairing::parse(&s), Some(p.clone()));
        assert_eq!(Pairing::parse(&format!("  {s}\n")), Some(p));
        assert!(Pairing::parse("hs2.x.y").is_none());
        assert!(Pairing::parse("192.168.1.1").is_none());
        let bare = Pairing { key: Key::generate(), addrs: vec![] };
        assert_eq!(Pairing::parse(&bare.encode()), Some(bare));
    }

    #[test]
    fn host_port_forms() {
        let d = 45800;
        assert_eq!(split_host_port("10.0.0.1/7", d), Some(("10.0.0.1".into(), 7)));
        assert_eq!(split_host_port("10.0.0.1:7", d), Some(("10.0.0.1".into(), 7)));
        assert_eq!(split_host_port("10.0.0.1", d), Some(("10.0.0.1".into(), d)));
        assert_eq!(split_host_port("2a01::5/7", d), Some(("2a01::5".into(), 7)));
        assert_eq!(split_host_port("2a01::5", d), Some(("2a01::5".into(), d)));
        assert_eq!(split_host_port("[2a01::5]:7", d), Some(("2a01::5".into(), 7)));
        assert_eq!(split_host_port("pc.local", d), Some(("pc.local".into(), d)));
        assert_eq!(split_host_port("pc.local:7", d), Some(("pc.local".into(), 7)));
        assert_eq!(split_host_port("", d), None);
        assert_eq!(resolve_addr("2a01::5/7", d), vec!["[2a01::5]:7".parse().unwrap()]);
        assert_eq!(format_addr(&"[::ffff:10.0.0.1]:9".parse().unwrap()), "10.0.0.1/9");
    }

    #[test]
    fn address_classes() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(is_local(ip("192.168.1.2")) && is_local(ip("10.1.2.3")) && is_local(ip("127.0.0.1")));
        assert!(is_local(ip("::ffff:192.168.1.2")) && is_local(ip("fe80::1")) && is_local(ip("fd00::1")));
        assert!(!is_local(ip("82.64.1.2")) && !is_local(ip("2a01:e0a::1")) && !is_local(ip("100.64.0.1")));
        assert!(is_behind_nat(ip("100.64.0.1")) && is_behind_nat(ip("100.127.255.1")) && is_behind_nat(ip("192.168.0.1")));
        assert!(!is_behind_nat(ip("100.128.0.1")) && !is_behind_nat(ip("82.64.1.2")));
    }
}
