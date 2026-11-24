//! Finding the host when its address has changed, without running a server.
//!
//! The host periodically stores its current addresses in the BitTorrent
//! Mainline DHT as a BEP 44 mutable item. The item is signed with an Ed25519
//! key derived from the pairing key (so nobody else can overwrite it) and its
//! content is encrypted with another derived key (so nobody else can read the
//! addresses). A client that cannot reach the host at the addresses it knows
//! looks the item up. The DHT is only ever used to find addresses: it carries
//! no session traffic, and a wrong or missing answer just means "not found".

use crate::secure::Key;
use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
pub use mainline::Dht;
use mainline::{MutableItem, SigningKey};

/// BEP 44 values are limited to 1000 bytes.
const MAX_PLAIN: usize = 900;

fn derive(key: &Key, label: &[u8]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(label);
    h.update(key.bytes());
    h.finalize().into()
}

fn signing_key(key: &Key) -> SigningKey {
    SigningKey::from_bytes(&derive(key, b"hyperspace rendezvous signing v1"))
}

fn seal(key: &Key, plain: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new((&derive(key, b"hyperspace rendezvous sealing v1")).into());
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).expect("system randomness");
    let mut out = nonce.to_vec();
    out.extend(cipher.encrypt(Nonce::from_slice(&nonce), plain).expect("encryption cannot fail"));
    out
}

fn open(key: &Key, sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < 12 + 16 {
        return None;
    }
    let cipher = ChaCha20Poly1305::new((&derive(key, b"hyperspace rendezvous sealing v1")).into());
    cipher.decrypt(Nonce::from_slice(&sealed[..12]), &sealed[12..]).ok()
}

/// Encode the address list (newline separated, truncated to fit).
fn encode_addrs(addrs: &[String]) -> Vec<u8> {
    let mut out = String::new();
    for a in addrs {
        if out.len() + a.len() + 1 > MAX_PLAIN {
            break;
        }
        out.push_str(a);
        out.push('\n');
    }
    out.into_bytes()
}

fn decode_addrs(plain: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(plain)
        .lines()
        .filter(|l| !l.is_empty() && l.len() < 256 && l.is_ascii())
        .map(str::to_string)
        .collect()
}

/// Store the host's current addresses. `seq` must increase with every
/// publication (the Unix time works).
#[allow(deprecated)] // the blocking API is exactly what these one-shot calls need
pub fn publish(dht: &Dht, key: &Key, addrs: &[String], seq: i64) -> Result<(), String> {
    let value = seal(key, &encode_addrs(addrs));
    let item = MutableItem::new(signing_key(key), &value, seq, None);
    dht.put_mutable(item, None).map(|_| ()).map_err(|e| e.to_string())
}

/// Look up the host's most recently published addresses.
#[allow(deprecated)]
pub fn resolve(dht: &Dht, key: &Key) -> Option<Vec<String>> {
    let public = signing_key(key).verifying_key().to_bytes();
    let item = dht.get_mutable_most_recent(&public, None)?;
    let addrs = decode_addrs(&open(key, item.value())?);
    (!addrs.is_empty()).then_some(addrs)
}

/// A DHT node for publishing or resolving.
pub fn connect() -> std::io::Result<Dht> {
    Dht::client()
}

/// Block until the node has joined the network; false if it could not.
#[allow(deprecated)]
pub fn wait_ready(dht: &Dht) -> bool {
    dht.bootstrapped()
}

/// The public IPv4 address other DHT nodes see this machine at.
#[allow(deprecated)]
pub fn public_ipv4(dht: &Dht) -> Option<std::net::Ipv4Addr> {
    dht.info().public_address().map(|a| *a.ip())
}

pub fn unix_time() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealing_is_keyed() {
        let (a, b) = (Key::generate(), Key::generate());
        let sealed = seal(&a, b"82.64.1.2/45800\n");
        assert_eq!(open(&a, &sealed).as_deref(), Some(&b"82.64.1.2/45800\n"[..]));
        assert_eq!(open(&b, &sealed), None);
        assert_eq!(open(&a, &sealed[..20]), None);
        assert_ne!(signing_key(&a).to_bytes(), signing_key(&b).to_bytes());
    }

    #[test]
    fn address_list_encoding() {
        let addrs: Vec<String> = vec!["192.168.1.5/45800".into(), "2a01::1/45800".into()];
        assert_eq!(decode_addrs(&encode_addrs(&addrs)), addrs);
        let many: Vec<String> = (0..500).map(|i| format!("10.0.{}.{}/45800", i / 250, i % 250)).collect();
        assert!(encode_addrs(&many).len() <= MAX_PLAIN);
    }

    /// Publish and resolve through a private DHT running on localhost.
    #[test]
    fn publish_and_resolve_over_a_local_dht() {
        // Bound to localhost explicitly: only Linux lets you send to 0.0.0.0.
        let testnet = mainline::Testnet::builder(8).build().expect("local dht");
        let host = Dht::builder().bootstrap(&testnet.bootstrap).build().unwrap();
        let client = Dht::builder().bootstrap(&testnet.bootstrap).build().unwrap();
        let key = Key::generate();
        assert_eq!(resolve(&client, &key), None);

        let first = vec!["192.168.1.5/45800".to_string(), "82.64.1.2/45800".to_string()];
        publish(&host, &key, &first, 100).unwrap();
        assert_eq!(resolve(&client, &key), Some(first));

        // the address changed: the newer record wins
        let second = vec!["192.168.1.5/45800".to_string(), "90.1.2.3/45800".to_string()];
        publish(&host, &key, &second, 200).unwrap();
        assert_eq!(resolve(&client, &key), Some(second));

        // someone with a different key finds nothing
        assert_eq!(resolve(&client, &Key::generate()), None);
    }
}
