//! Carries hyperspace's UDP datagrams through a relay, for a host and a
//! client that cannot reach each other directly.
//!
//! Both ends connect out to the relay over a WebSocket (TLS on port 443 for
//! `wss://`) and the relay pairs them by room id; see
//! [`hyperspace_proto::relay`] for the protocol. The datagrams stay encrypted
//! end to end: the relay never holds the pairing key.
//!
//! Each end runs its link on a thread of its own and talks to the rest of the
//! program through loopback UDP sockets, so the host's server and the client
//! use the relay exactly as they use a direct path:
//!
//! - [`HostBridge`] opens, for each client the relay announces, a UDP socket
//!   on loopback that sends that client's datagrams to the host's server and
//!   carries the answers back. The server tells these apart through
//!   [`RelayedPeers`].
//! - [`ClientBridge`] gives the client a loopback address to send to as if it
//!   were the host's.

mod client;
mod host;
mod link;
mod queue;
mod url;

#[cfg(test)]
mod tests;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use hyperspace_proto::relay;

pub use client::{ClientBridge, Status};
pub use host::HostBridge;
pub use url::RelayUrl;

/// The loopback addresses [`HostBridge`] sends from, one per client connected
/// through the relay. Shared with the host's server, which treats datagrams
/// from them as coming from the internet.
#[derive(Clone, Debug, Default)]
pub struct RelayedPeers(Arc<RwLock<HashSet<SocketAddr>>>);

/// IPv4 addresses seen through a dual-stack socket arrive as `::ffff:a.b.c.d`.
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

impl RelayedPeers {
    pub fn new() -> RelayedPeers {
        RelayedPeers::default()
    }

    /// True if datagrams from `addr` come from a client through the relay.
    pub fn contains(&self, addr: SocketAddr) -> bool {
        self.0.read().unwrap_or_else(|e| e.into_inner()).contains(&canonical(addr))
    }

    pub fn len(&self) -> usize {
        self.0.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn insert(&self, addr: SocketAddr) {
        self.0.write().unwrap_or_else(|e| e.into_inner()).insert(canonical(addr));
    }

    pub(crate) fn remove(&self, addr: SocketAddr) {
        self.0.write().unwrap_or_else(|e| e.into_inner()).remove(&canonical(addr));
    }
}

/// Checks that a relay answers at `url`: DNS, TCP, TLS (for `wss://`), the
/// WebSocket upgrade and the relay's challenge. It closes without
/// authenticating, so it needs no key. Returns one line saying what worked,
/// or one line saying what failed.
pub fn check(url: &str) -> Result<String, String> {
    let url = RelayUrl::parse(url)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start the network runtime: {e}"))?;
    let result = rt.block_on(async {
        let mut ws = link::open(&url).await?;
        let answer = match tokio::time::timeout(link::AUTH_TIMEOUT, link::challenge(&mut ws)).await {
            Ok(Ok(_nonce)) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(format!(
                "connected, but the relay sent no challenge within {} s (is this a hyperspace relay?)",
                link::AUTH_TIMEOUT.as_secs()
            )),
        };
        let _ = tokio::time::timeout(Duration::from_secs(2), ws.close(None)).await;
        answer
    });
    rt.shutdown_background();
    result?;
    Ok(if url.tls() {
        format!("relay reachable: TLS ok, WebSocket ok, relay protocol v{}", relay::VERSION)
    } else {
        format!("relay reachable (no TLS): WebSocket ok, relay protocol v{}", relay::VERSION)
    })
}
