//! Making the host reachable from outside its LAN, without a VPN or relay.
//!
//! * asks the router (UPnP IGD) to forward the UDP port, and to open an IPv6
//!   firewall pinhole where the router supports that;
//! * works out which addresses a client could use (LAN, public IPv4, global
//!   IPv6, an optional DNS name) and prints them as the pairing string;
//! * keeps those addresses published (encrypted) in the BitTorrent DHT so a
//!   paired client still finds the host after its home IP address changes.

use crate::server::{PROBE_SEEN, PROBE_TOKEN, PT_PROBE, SHUTDOWN};
use hyperspace_bridge::plain_error;
use hyperspace_proto::pairing::{format_addr, is_behind_nat, is_relay_entry, Pairing};
use hyperspace_proto::secure::Key;
use hyperspace_proto::{log, rendezvous};
use igd_next::{PortMappingProtocol, SearchOptions};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

pub struct Options {
    pub key: Key,
    pub port: u16,
    pub upnp: bool,
    pub dht: bool,
    /// DNS name (optionally `name:port`) that always points at this host.
    pub public_host: Option<String>,
    pub config_dir: PathBuf,
    /// Relay URL this host also takes clients through: added last to the
    /// pairing string, never published to the DHT.
    pub relay: Option<String>,
}

const LEASE_SECS: u32 = 3600;
const RENEW_EVERY: Duration = Duration::from_secs(20 * 60);
const PUBLISH_EVERY: Duration = Duration::from_secs(30 * 60);

/// Addresses of this machine: (private IPv4s, global IPv6s).
fn local_addresses() -> (Vec<Ipv4Addr>, Vec<std::net::Ipv6Addr>) {
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        match iface.ip() {
            IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_link_local() => v4.push(ip),
            // Global unicast only (2000::/3): link-local and unique-local are useless off-site.
            IpAddr::V6(ip) if (ip.segments()[0] & 0xe000) == 0x2000 => v6.push(ip),
            _ => {}
        }
    }
    v4.sort();
    v4.dedup();
    v6.sort();
    v6.dedup();
    v6.truncate(4);
    (v4, v6)
}

struct PortMapping {
    gateway: igd_next::Gateway,
    local: SocketAddr,
    external_port: u16,
    external_ip: Option<IpAddr>,
    pinholes: Vec<u16>,
}

impl PortMapping {
    /// Find the router and ask it to forward `port` (UDP) to us.
    fn establish(port: u16, v6: &[std::net::Ipv6Addr]) -> Result<PortMapping, String> {
        let mut opts = SearchOptions::default();
        opts.timeout = Some(Duration::from_secs(3));
        // Tests point discovery at a stand-in router instead of the multicast group.
        if let Some(addr) = std::env::var("HYPERSPACE_UPNP_SEARCH").ok().and_then(|v| v.parse::<SocketAddr>().ok()) {
            opts.broadcast_address = addr;
            opts.allowed_gateway_ips = vec![addr.ip()];
        }
        let gateway = igd_next::search_gateway(opts).map_err(|e| format!("no UPnP router found ({e})"))?;
        // Our address on the interface that faces the router.
        let local_ip = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .and_then(|s| s.connect(gateway.addr).and_then(|_| s.local_addr()))
            .map(|a| a.ip())
            .map_err(|e| format!("cannot determine the LAN address: {e}"))?;
        let local = SocketAddr::new(local_ip, port);
        let external_port = match gateway.add_port(PortMappingProtocol::UDP, port, local, LEASE_SECS, "hyperspace") {
            Ok(()) => port,
            // The same port may be taken by another machine: take any free one.
            Err(first) => gateway
                .add_any_port(PortMappingProtocol::UDP, local, LEASE_SECS, "hyperspace")
                .map_err(|e| format!("the router refused to forward a port ({first}; {e})"))?,
        };
        let external_ip = gateway.get_external_ip().ok();
        let mut m = PortMapping { gateway, local, external_port, external_ip, pinholes: Vec::new() };
        m.open_pinholes(v6);
        Ok(m)
    }

    /// IPv6 is not translated, only filtered: ask for an opening per address.
    fn open_pinholes(&mut self, v6: &[std::net::Ipv6Addr]) {
        for id in self.pinholes.drain(..) {
            let _ = self.gateway.remove_pinhole(id);
        }
        for ip in v6 {
            let target = SocketAddrV6::new(*ip, self.local.port(), 0, 0);
            if let Ok(id) = self.gateway.add_pinhole(PortMappingProtocol::UDP, target, LEASE_SECS) {
                self.pinholes.push(id);
            }
        }
    }

    fn renew(&mut self, v6: &[std::net::Ipv6Addr]) {
        if let Err(e) =
            self.gateway.add_port(PortMappingProtocol::UDP, self.external_port, self.local, LEASE_SECS, "hyperspace")
        {
            log!("could not renew the router's port mapping: {e}");
        }
        if let Ok(ip) = self.gateway.get_external_ip() {
            self.external_ip = Some(ip);
        }
        self.open_pinholes(v6);
    }

    fn remove(&mut self) {
        let _ = self.gateway.remove_port(PortMappingProtocol::UDP, self.external_port);
        for id in self.pinholes.drain(..) {
            let _ = self.gateway.remove_pinhole(id);
        }
    }

    /// Public IPv4 endpoint, if the router really is on the internet.
    fn public_endpoint(&self) -> Option<SocketAddr> {
        self.external_ip.filter(|ip| !is_behind_nat(*ip)).map(|ip| SocketAddr::new(ip, self.external_port))
    }
}

/// Send a packet to our own public address and see whether it comes back in.
/// Most routers loop such traffic back ("NAT hairpinning"); when it arrives it
/// has passed the router's port forward and this PC's firewall, exactly like
/// a client's packet would. `false` only means "could not be confirmed".
fn probe(endpoint: SocketAddr) -> bool {
    let token = u64::from_le_bytes(Key::generate().bytes()[..8].try_into().unwrap()) | 1;
    PROBE_SEEN.store(false, Ordering::Relaxed);
    PROBE_TOKEN.store(token, Ordering::Relaxed);
    // Tests stand in for a router that loops traffic back.
    let endpoint = match std::env::var("HYPERSPACE_PROBE_VIA").ok().and_then(|v| v.parse().ok()) {
        Some(ip) => SocketAddr::new(ip, endpoint.port()),
        None => endpoint,
    };
    let mut packet = vec![PT_PROBE];
    packet.extend_from_slice(&token.to_le_bytes());
    let mut seen = false;
    if let Ok(sock) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
        'outer: for _ in 0..4 {
            let _ = sock.send_to(&packet, endpoint);
            for _ in 0..20 {
                std::thread::sleep(Duration::from_millis(20));
                if PROBE_SEEN.load(Ordering::Relaxed) {
                    seen = true;
                    break 'outer;
                }
            }
        }
    }
    PROBE_TOKEN.store(0, Ordering::Relaxed);
    seen
}

/// Everything the background thread knows about how to reach this host.
struct Reach {
    opts: Options,
    mapping: Option<PortMapping>,
    dht: Option<rendezvous::Dht>,
    last_addrs: Vec<String>,
}

impl Reach {
    fn addresses(&self) -> Vec<String> {
        let port = self.opts.port;
        let (v4, v6) = local_addresses();
        let mut out: Vec<String> = Vec::new();
        let mut push = |s: String| {
            if !out.contains(&s) {
                out.push(s);
            }
        };
        for ip in &v4 {
            push(format_addr(&SocketAddr::new((*ip).into(), port)));
        }
        if let Some(name) = &self.opts.public_host {
            if let Some((h, p)) = hyperspace_proto::pairing::split_host_port(name, port) {
                push(format!("{h}/{p}"));
            }
        }
        // Offered even when the router did not confirm it: the port may be forwarded by hand.
        if let Some((ep, _)) = self.public_endpoint() {
            push(format_addr(&ep));
        }
        for ip in &v6 {
            push(format_addr(&SocketAddr::new((*ip).into(), port)));
        }
        out
    }

    fn pairing(&self, addrs: &[String]) -> Pairing {
        pairing_for(&self.opts.key, addrs, self.opts.relay.as_deref())
    }

    fn announce(&mut self, first: bool) {
        let addrs = self.addresses();
        if !first && addrs == self.last_addrs {
            return;
        }
        let pairing = self.pairing(&addrs);
        let path = self.opts.config_dir.join("pairing.txt");
        if first {
            self.explain();
            if let Some(url) = &self.opts.relay {
                log!("clients that cannot reach these addresses connect through the relay at {url}");
            }
        }
        if let Err(e) = pairing.save(&path) {
            log!("cannot write {}: {}", path.display(), plain_error(&e));
        }
        if first {
            log!("pair a client once with:");
            eprintln!("\n    hyperspace-client pair {}\n", pairing.encode());
            log!("(also saved to {})", path.display());
        } else {
            log!("addresses changed: {}", addrs.join(", "));
        }
        self.last_addrs = addrs;
    }

    /// The public IPv4 endpoint clients would use, and whether the router
    /// confirmed forwarding it to us.
    fn public_endpoint(&self) -> Option<(SocketAddr, bool)> {
        if let Some(ep) = self.mapping.as_ref().and_then(|m| m.public_endpoint()) {
            return Some((ep, true));
        }
        let ip = self.dht.as_ref().and_then(rendezvous::public_ipv4).filter(|ip| !is_behind_nat((*ip).into()))?;
        Some((SocketAddr::new(ip.into(), self.opts.port), false))
    }

    /// Tell the user, in plain words, whether outside access will work.
    fn explain(&self) {
        let (_, v6) = local_addresses();
        let port = self.opts.port;
        let firewall_hint = format!(
            "if clients get no answer, allow the port in Windows Firewall (administrator prompt): \
             netsh advfirewall firewall add rule name=hyperspace dir=in action=allow protocol=UDP localport={port}"
        );
        if let Some(m) = self.mapping.as_ref().filter(|m| m.public_endpoint().is_none()) {
            log!(
                "the router forwarded a port, but its own address ({}) is not public: your provider uses \
                 carrier-grade NAT (or there is a second router), so IPv4 connections from outside cannot get in",
                m.external_ip.map(|i| i.to_string()).unwrap_or_else(|| "unknown".into())
            );
        }
        match self.public_endpoint() {
            Some((ep, mapped)) => {
                let verified = probe(ep);
                match (mapped, verified) {
                    (true, true) => log!(
                        "reachable from the internet at {ep}: the router forwards the port and a test packet sent to \
                         that address came back in (router and firewall both let clients through)"
                    ),
                    (false, true) => {
                        log!("reachable from the internet at {ep}: a test packet sent to that address came back in")
                    }
                    (true, false) => {
                        log!(
                            "the router forwards {ep} to this PC, but a test packet sent to that address did not come \
                             back in. Either the router cannot loop traffic back (common, harmless) or this PC's \
                             firewall is dropping it"
                        );
                        log!("{firewall_hint}");
                    }
                    (false, false) => {
                        if self.opts.upnp {
                            log!(
                                "automatic port forwarding is unavailable and UDP port {port} does not appear to be \
                                 forwarded: to connect from outside, forward it to this PC in your router (or enable UPnP there)"
                            );
                        }
                        log!("{firewall_hint}");
                    }
                }
            }
            None if self.opts.upnp && self.mapping.is_none() => log!(
                "automatic port forwarding is unavailable: to connect from outside, forward UDP port {port} to this PC \
                 in your router (or enable UPnP there)"
            ),
            None => {}
        }
        if !v6.is_empty() {
            let opened = self.mapping.as_ref().is_some_and(|m| !m.pinholes.is_empty());
            log!(
                "IPv6 address available{}",
                if opened {
                    " and opened in the router's firewall"
                } else {
                    " (reachable from IPv6 networks if the router's firewall allows inbound UDP to this PC)"
                }
            );
        }
    }

    fn publish(&mut self) -> bool {
        let Some(dht) = &self.dht else { return false };
        if self.last_addrs.is_empty() {
            return false;
        }
        match rendezvous::publish(dht, &self.opts.key, &dht_addrs(&self.last_addrs), rendezvous::unix_time()) {
            Ok(()) => true,
            Err(e) => {
                log!("could not publish this host's address for roaming clients: {e}");
                false
            }
        }
    }
}

/// The pairing string for `addrs`, with the relay entry (if any) last so
/// that clients try every direct address first.
fn pairing_for(key: &Key, addrs: &[String], relay: Option<&str>) -> Pairing {
    let mut pairing = Pairing { key: key.clone(), addrs: dht_addrs(addrs) };
    if let Err(e) = pairing.set_relay(relay) {
        log!("the relay is left out of the pairing string: {e}");
    }
    pairing
}

/// What may go into the DHT: addresses only, never the relay entry.
fn dht_addrs(addrs: &[String]) -> Vec<String> {
    addrs.iter().filter(|a| !is_relay_entry(a)).cloned().collect()
}

/// Run until shutdown. Never fails: every step is best-effort.
pub fn run(opts: Options) {
    let (_, v6) = local_addresses();
    let mapping = if opts.upnp {
        match PortMapping::establish(opts.port, &v6) {
            Ok(m) => Some(m),
            Err(e) => {
                log!("{e}");
                None
            }
        }
    } else {
        None
    };
    let dht = if opts.dht {
        match rendezvous::connect() {
            Ok(d) => {
                // Joining the network also teaches the node its public address.
                if !rendezvous::wait_ready(&d) {
                    log!("could not join the address lookup network (no internet access?)");
                }
                Some(d)
            }
            Err(e) => {
                log!("address lookup service unavailable: {e}");
                None
            }
        }
    } else {
        None
    };
    let mut reach = Reach { opts, mapping, dht, last_addrs: Vec::new() };
    reach.announce(true);
    let mut published = reach.publish();
    if published {
        log!("address published: paired clients will find this host even after its IP address changes");
    }
    let mut last_renew = Instant::now();
    let mut last_publish = Instant::now();
    let mut last_check = Instant::now();
    while !SHUTDOWN.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(200));
        if last_renew.elapsed() >= RENEW_EVERY {
            last_renew = Instant::now();
            let (_, v6) = local_addresses();
            if let Some(m) = reach.mapping.as_mut() {
                m.renew(&v6);
            }
        }
        // Notice address changes (new DHCP lease, new ISP prefix) within a minute.
        if last_check.elapsed() >= Duration::from_secs(60) {
            last_check = Instant::now();
            if let Some(m) = reach.mapping.as_mut() {
                if let Ok(ip) = m.gateway.get_external_ip() {
                    m.external_ip = Some(ip);
                }
            }
            let before = reach.last_addrs.clone();
            reach.announce(false);
            if reach.last_addrs != before {
                published = false;
            }
        }
        let retry = if published { PUBLISH_EVERY } else { Duration::from_secs(120) };
        if last_publish.elapsed() >= retry {
            last_publish = Instant::now();
            published = reach.publish();
        }
    }
    if let Some(m) = reach.mapping.as_mut() {
        m.remove();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_entry_goes_last_and_never_to_the_dht() {
        let key = Key::generate();
        let addrs = vec!["192.0.2.10/45800".to_string(), "2001:db8::5/45800".to_string()];
        let p = pairing_for(&key, &addrs, Some("wss://relay.example/v1"));
        assert_eq!(p.addrs.last().map(String::as_str), Some("relay=wss://relay.example/v1"));
        assert_eq!(p.relay().as_deref(), Some("wss://relay.example/v1"));
        assert_eq!(p.addresses().collect::<Vec<_>>(), ["192.0.2.10/45800", "2001:db8::5/45800"]);
        assert_eq!(Pairing::parse(&p.encode()), Some(p.clone()));
        assert_eq!(dht_addrs(&p.addrs), addrs);
        assert_eq!(pairing_for(&key, &addrs, None).addrs, addrs);
        // a relay alone still makes a usable pairing string
        assert_eq!(pairing_for(&key, &[], Some("wss://relay.example/v1")).addrs, ["relay=wss://relay.example/v1"]);
    }
}
