//! EIP-1459 node discovery: walks a network's DNS tree (e.g.
//! `all.mainnet.ethdisco.net`) and returns the peers it lists. Ported from Puddle.
//!
//! The tree signature is not checked: peers still go through the handshake and
//! the STATUS checks, and every block is verified.

use std::collections::HashSet;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::task::JoinSet;

use crate::configs::Peer;

const DNS_SERVER: &str = "8.8.8.8:53";
const DNS_TIMEOUT: Duration = Duration::from_secs(3);

/// Walks the DNS tree at `domain` and returns every node record (ENR) with an
/// IPv4 address and a TCP port.
pub async fn discover_peers(domain: &str) -> Vec<Peer> {
    let root = dns_txt_query(domain).await;
    let Some(entries_hash) = root
        .iter()
        .find(|s| s.starts_with("enrtree-root:"))
        .and_then(|s| s.split_whitespace().find_map(|f| f.strip_prefix("e=")))
        .map(str::to_string)
    else {
        warn!("No enrtree-root found at {}", domain);
        return vec![];
    };

    // Breadth-first walk, querying each level in parallel.
    let mut to_visit = vec![entries_hash];
    let mut visited: HashSet<String> = HashSet::new();
    let mut peers = vec![];

    while !to_visit.is_empty() {
        let mut queries = JoinSet::new();
        for hash in to_visit.drain(..) {
            if visited.insert(hash.clone()) {
                let subdomain = format!("{}.{}", hash, domain);
                queries.spawn(async move { dns_txt_query(&subdomain).await });
            }
        }

        while let Some(result) = queries.join_next().await {
            for txt in result.unwrap_or_default() {
                if let Some(branches) = txt.strip_prefix("enrtree-branch:") {
                    to_visit.extend(
                        branches
                            .split(',')
                            .map(str::trim)
                            .filter(|h| !h.is_empty())
                            .map(str::to_string),
                    );
                } else if let Some(enr) = txt.strip_prefix("enr:") {
                    if let Some(peer) = parse_enr(enr) {
                        peers.push(peer);
                    }
                }
                // enrtree-link entries (links to other trees) are skipped.
            }
        }
    }

    info!("DNS discovery at {} found {} peers", domain, peers.len());
    peers
}

async fn dns_txt_query(domain: &str) -> Vec<String> {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
        return vec![];
    };
    if sock.connect(DNS_SERVER).await.is_err() || sock.send(&build_query(domain)).await.is_err() {
        return vec![];
    }
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(DNS_TIMEOUT, sock.recv(&mut buf)).await {
        Ok(Ok(n)) => parse_txt_response(&buf[..n]),
        _ => {
            debug!("DNS query for {} failed", domain);
            vec![]
        }
    }
}

fn build_query(domain: &str) -> Vec<u8> {
    let mut pkt: Vec<u8> = vec![
        0x12, 0x34, // ID (one query per socket, so a fixed one is fine)
        0x01, 0x00, // flags: recursion desired
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    ];
    for label in domain.split('.').filter(|l| !l.is_empty()) {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0x00);
    pkt.extend_from_slice(&[0x00, 0x10]); // QTYPE = TXT
    pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    pkt
}

/// Skips a (possibly compressed) DNS name starting at `pos`.
fn skip_name(data: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let b = *data.get(pos)?;
        if b == 0 {
            return Some(pos + 1);
        }
        if b & 0xC0 == 0xC0 {
            return Some(pos + 2);
        }
        pos += 1 + b as usize;
    }
}

fn parse_txt_response(data: &[u8]) -> Vec<String> {
    let mut results = vec![];
    if data.len() < 12 {
        return results;
    }
    let ancount = u16::from_be_bytes([data[6], data[7]]);

    let Some(mut pos) = skip_name(data, 12) else {
        return results;
    };
    pos += 4; // QTYPE + QCLASS

    for _ in 0..ancount {
        let Some(p) = skip_name(data, pos) else {
            break;
        };
        pos = p;
        if pos + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;
        let end = pos + rdlen;
        if end > data.len() {
            break;
        }

        if rtype == 16 {
            // TXT data is a list of length-prefixed strings. Concatenate them with
            // no separator: EIP-1459 entries can be split at the 255-byte boundary.
            let mut txt = String::new();
            let mut p = pos;
            while p < end {
                let len = data[p] as usize;
                p += 1;
                if p + len > end {
                    break;
                }
                txt.push_str(&String::from_utf8_lossy(&data[p..p + len]));
                p += len;
            }
            if !txt.is_empty() {
                results.push(txt);
            }
        }
        pos = end;
    }
    results
}

/// Parses a base64 ENR (without the `enr:` prefix) into a peer. Records without
/// an IPv4 address, a TCP port or a secp256k1 key are skipped.
fn parse_enr(b64: &str) -> Option<Peer> {
    let data = base64url_decode(b64)?;
    let r = rlp::Rlp::new(&data);

    // [signature, seq, key, value, key, value, ...]
    let count = r.item_count().ok()?;
    let mut ip: Option<[u8; 4]> = None;
    let mut tcp: Option<u16> = None;
    let mut pubkey: Option<Vec<u8>> = None;
    let mut i = 2;
    while i + 1 < count {
        let key = r.at(i).ok()?;
        let value = r.at(i + 1).ok()?;
        match key.data().ok()? {
            b"ip" => ip = value.data().ok()?.try_into().ok(),
            b"tcp" => tcp = value.as_val().ok(),
            b"secp256k1" => pubkey = Some(value.data().ok()?.to_vec()),
            _ => {}
        }
        i += 2;
    }

    // The record holds the compressed key; the handshake needs the 64-byte form.
    let pk = secp256k1::PublicKey::from_slice(&pubkey?).ok()?;
    let ip = std::net::Ipv4Addr::from(ip?);
    Some(Peer {
        ip: ip.to_string(),
        port: tcp? as u32,
        remote_id: pk.serialize_uncompressed()[1..].to_vec(),
    })
}

/// Decodes unpadded base64url, as used by ENR text records.
fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::with_capacity(s.len() * 3 / 4 + 1);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        buf = (buf << 6) | TABLE.iter().position(|&x| x == c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Example record from EIP-778: 127.0.0.1, UDP 30303, no TCP port.
    const EIP778_ENR: &str = "-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8";

    #[test]
    fn enr_without_tcp_is_skipped() {
        assert!(parse_enr(EIP778_ENR).is_none());
    }

    #[test]
    fn enr_with_tcp_is_parsed() {
        // Same record with a "tcp" entry added (signature not checked).
        let data = base64url_decode(EIP778_ENR).unwrap();
        let r = rlp::Rlp::new(&data);
        let mut s = rlp::RlpStream::new_list(r.item_count().unwrap() + 2);
        for i in 0..r.item_count().unwrap() {
            if i == 6 {
                s.append(&"tcp".as_bytes());
                s.append(&30303u16);
            }
            s.append_raw(r.at(i).unwrap().as_raw(), 1);
        }
        let mut b64 = String::new();
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for chunk in s.out().chunks(3) {
            let n = chunk.iter().fold(0u32, |a, &b| a << 8 | b as u32) << (8 * (3 - chunk.len()));
            for k in 0..=chunk.len() {
                b64.push(TABLE[(n >> (18 - 6 * k) & 63) as usize] as char);
            }
        }

        let peer = parse_enr(&b64).unwrap();
        assert_eq!(peer.ip, "127.0.0.1");
        assert_eq!(peer.port, 30303);
        assert_eq!(peer.remote_id.len(), 64);
        assert_eq!(
            hex::encode(&peer.remote_id[..32]),
            "ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138"
        );
    }

    #[test]
    fn txt_response_parsing() {
        let mut pkt = build_query("example.org");
        pkt[7] = 1; // ANCOUNT = 1
        pkt.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x10, 0x00, 0x01, 0, 0, 0, 60]);
        pkt.extend_from_slice(&[0x00, 0x07, 3, b'a', b'b', b'c', 2, b'd', b'e']);
        assert_eq!(parse_txt_response(&pkt), vec!["abcde".to_string()]);
    }
}

#[cfg(test)]
mod live_tests {
    /// Needs network access: `cargo test --lib -- --ignored discover_mainnet`
    #[tokio::test]
    #[ignore]
    async fn discover_mainnet() {
        let peers = super::discover_peers("all.mainnet.ethdisco.net").await;
        println!("found {} peers", peers.len());
        assert!(!peers.is_empty());
    }
}
