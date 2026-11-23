//! Keeps the sync supplied with peers. Candidates come from the config, the
//! network's DNS tree (EIP-1459) and continuous discv4 lookups; they are
//! connected in the background and handed over on a channel, up to MAX_PEERS.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, mpsc};

use crate::configs::Peer;
use crate::connection::{Connection, Disconnected, TOO_MANY_PEERS};
use crate::dns_discovery;
use crate::networks::Network;

/// Most connections open at once. A slot is held from the handshake until the
/// connection is dropped by the sync, so in-flight handshakes count too.
pub const MAX_PEERS: usize = 50;

/// A peer is not tried again before this. Peers that refused us with "too many
/// peers" are queued again after it, since their slots free up over time;
/// others are only retried if discovery finds them again.
const RETRY_AFTER: Duration = Duration::from_secs(600);

/// The DNS tree changes slowly.
const DNS_REFRESH: Duration = Duration::from_secs(3600);

/// UDP port for discv4.
const DISCOVERY_PORT: u16 = 30303;

/// Starts finding and connecting peers in the background. New connections
/// arrive on the returned channel.
pub fn spawn(network: Network, config_peers: Vec<Peer>) -> mpsc::Receiver<Connection> {
    let (candidate_tx, candidate_rx) = mpsc::channel::<Peer>(1000);
    let (conn_tx, conn_rx) = mpsc::channel::<Connection>(MAX_PEERS);

    // Peers from the config are tried first.
    let tx = candidate_tx.clone();
    tokio::spawn(async move {
        for peer in config_peers {
            if tx.send(peer).await.is_err() {
                return;
            }
        }
    });

    if let Some(tree) = network.dns_tree {
        let tx = candidate_tx.clone();
        tokio::spawn(async move {
            loop {
                let mut found = dns_discovery::discover_peers(tree).await;
                secp256k1::rand::seq::SliceRandom::shuffle(
                    found.as_mut_slice(),
                    &mut secp256k1::rand::thread_rng(),
                );
                for peer in found {
                    if tx.send(peer).await.is_err() {
                        return;
                    }
                }
                tokio::time::sleep(DNS_REFRESH).await;
            }
        });
    }

    if !network.bootnodes.is_empty() {
        tokio::spawn(run_discv4(network, candidate_tx.clone()));
    }

    tokio::spawn(connect_candidates(
        network,
        candidate_rx,
        candidate_tx,
        conn_tx,
    ));

    conn_rx
}

/// Runs random discv4 lookups forever and sends the nodes found as candidates.
/// Blocks on the channel while every slot is taken, so lookups pause too.
async fn run_discv4(network: Network, candidates: mpsc::Sender<Peer>) {
    let bootnodes = network
        .bootnodes
        .iter()
        .filter_map(|b| b.parse().ok())
        .collect();
    let secret_key = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());
    let node = match discv4::Node::new(
        std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, DISCOVERY_PORT),
        secret_key,
        bootnodes,
        None,
        false,
        0,
    )
    .await
    {
        Ok(node) => node,
        Err(e) => {
            warn!("Failed to start discv4: {}", e);
            return;
        }
    };
    info!("discv4 started on UDP port {}", DISCOVERY_PORT);

    loop {
        let mut target = [0u8; 64];
        secp256k1::rand::RngCore::fill_bytes(&mut secp256k1::rand::thread_rng(), &mut target);
        let found = node.lookup(discv4::NodeId::from(target)).await;
        debug!(
            "discv4 lookup found {} nodes ({} in table)",
            found.len(),
            node.num_nodes()
        );
        let empty = found.is_empty();
        for record in found {
            // Only IPv4, like DNS discovery.
            let std::net::IpAddr::V4(ip) = record.address else {
                continue;
            };
            let peer = Peer {
                ip: ip.to_string(),
                port: record.tcp_port as u32,
                remote_id: record.id.as_bytes().to_vec(),
            };
            if candidates.send(peer).await.is_err() {
                return;
            }
        }
        if empty {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

/// Connects candidates while there are free slots. Each peer is tried at most
/// once every RETRY_AFTER.
async fn connect_candidates(
    network: Network,
    mut candidates: mpsc::Receiver<Peer>,
    retry: mpsc::Sender<Peer>,
    connections: mpsc::Sender<Connection>,
) {
    let slots = Arc::new(Semaphore::new(MAX_PEERS));
    let mut tried: HashMap<Vec<u8>, Instant> = HashMap::new();

    while let Some(peer) = candidates.recv().await {
        if tried
            .get(&peer.remote_id)
            .is_some_and(|t| t.elapsed() < RETRY_AFTER)
        {
            continue;
        }
        let Ok(slot) = slots.clone().acquire_owned().await else {
            return;
        };
        if tried.len() > 100_000 {
            tried.retain(|_, t| t.elapsed() < RETRY_AFTER);
        }
        tried.insert(peer.remote_id.clone(), Instant::now());

        let tx = connections.clone();
        let retry = retry.clone();
        tokio::spawn(async move {
            let addr = format!("{}:{}", peer.ip, peer.port);
            match Connection::connect(peer.clone(), network).await {
                Ok(mut conn) => {
                    info!(
                        "Connected to peer {} (eth/{})",
                        addr, conn.eth_protocol_version
                    );
                    conn.slot = Some(slot);
                    let _ = tx.send(conn).await;
                }
                Err(e) => {
                    debug!("Failed to connect to peer {}: {}", addr, e);
                    if let Some(Disconnected(TOO_MANY_PEERS)) = e.downcast_ref() {
                        drop(slot);
                        tokio::time::sleep(RETRY_AFTER).await;
                        let _ = retry.send(peer).await;
                    }
                }
            }
        });

        if connections.is_closed() {
            return;
        }
    }
}
