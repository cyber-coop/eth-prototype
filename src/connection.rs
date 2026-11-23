use rand_core::RngCore;
use secp256k1::SecretKey;
use secp256k1::rand;
use std::error;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinHandle;

use crate::configs::Peer;
use crate::eth;
use crate::message;
use crate::networks;
use crate::types;
use crate::utils;

/// How long to wait for the response to a single eth request before giving up
/// on the peer.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// eth response message codes (without the base protocol offset).
pub const BLOCK_HEADERS_CODE: u8 = 0x04;
pub const BLOCK_BODIES_CODE: u8 = 0x06;
pub const RECEIPTS_CODE: u8 = 0x10;

/// Checks a peer's STATUS is for our network and at the chain tip: same network
/// id and genesis, and a fork hash in `network.accepted_fork_hashes`.
///
/// The fork hash a node announces follows its own head, so peers still syncing
/// (or crawlers announcing genesis) are rejected, as are other chains sharing
/// our genesis. Without this, their low heads can be taken for the chain tip.
fn check_same_network(
    network: &networks::Network,
    network_id: u64,
    genesis: &[u8],
    fork_id: &(Vec<u8>, u64),
) -> Result<(), Box<dyn error::Error + Send + Sync>> {
    if network_id != network.network_id || genesis != network.genesis_hash {
        warn!(
            "Wrong network: network id {} genesis {} (expected {} and {})",
            network_id,
            hex::encode(genesis),
            network.network_id,
            hex::encode(network.genesis_hash)
        );
        return Err("Wrong network".into());
    }
    let accepted = network.accepted_fork_hashes;
    if !accepted.is_empty()
        && !accepted
            .iter()
            .any(|h| h.to_be_bytes().as_slice() == fork_id.0.as_slice())
    {
        warn!(
            "Wrong fork id {} (next {}), expected one of {:x?}",
            hex::encode(&fork_id.0),
            fork_id.1,
            accepted
        );
        return Err("Wrong fork id".into());
    }
    Ok(())
}

pub struct Connection {
    pub handle: JoinHandle<()>,
    pub rx_tcp: Receiver<Vec<u8>>,
    pub tx_write: tokio::sync::mpsc::Sender<Vec<u8>>,
    pub eth_protocol_version: u32,
    latest_blockhash: Vec<u8>,
}

impl Connection {
    // latest_blockhash getter
    pub fn latest_blockhash(&self) -> &Vec<u8> {
        &self.latest_blockhash
    }

    /// Sends `msg` and waits for the response carrying `req_id` with eth message
    /// code `response_code` (without the base protocol offset). Unrelated messages,
    /// including stale responses to earlier requests, are skipped.
    ///
    /// Returns the response payload (after the code byte), or `None` if the
    /// connection closed or no matching response arrived within REQUEST_TIMEOUT.
    /// Callers should drop the connection on `None`.
    pub async fn request(
        &mut self,
        msg: Vec<u8>,
        response_code: u8,
        req_id: u64,
    ) -> Option<Vec<u8>> {
        if self.tx_write.send(msg).await.is_err() {
            warn!("Connection lost, could not send request {}", req_id);
            return None;
        }

        let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
        loop {
            match tokio::time::timeout_at(deadline, self.rx_tcp.recv()).await {
                Err(_) => {
                    warn!("Request {} timed out after {:?}", req_id, REQUEST_TIMEOUT);
                    return None;
                }
                Ok(None) => {
                    warn!("Connection closed while waiting for request {}", req_id);
                    return None;
                }
                Ok(Some(mut body)) => {
                    if body[0].saturating_sub(16) != response_code {
                        continue;
                    }
                    match eth::parse_request_id(&body[1..]) {
                        Some(id) if id == req_id => {
                            body.remove(0);
                            return Some(body);
                        }
                        other => debug!(
                            "Ignoring response with request id {:?} (expected {})",
                            other, req_id
                        ),
                    }
                }
            }
        }
    }

    pub async fn connect(
        peer: Peer,
        network: networks::Network,
    ) -> Result<Self, Box<dyn error::Error + Send + Sync>> {
        let addr = SocketAddr::from_str(&format!("{}:{}", peer.ip, peer.port))?;

        let mut stream =
            tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr)).await??;
        stream.set_nodelay(true)?;

        let private_key = SecretKey::new(&mut rand::thread_rng())
            .secret_bytes()
            .to_vec();
        let mut nonce = vec![0; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ephemeral_privkey = SecretKey::new(&mut rand::thread_rng())
            .secret_bytes()
            .to_vec();
        let pad = vec![0; 100]; // should be generated randomly but we don't really care

        info!("Creating EIP8 Auth message");
        let init_msg = utils::create_auth_eip8(
            &peer.remote_id,
            &private_key,
            &nonce,
            &ephemeral_privkey,
            &pad,
        );

        // send the message
        info!("Sending EIP8 Auth message");
        utils::send_eip8_auth_message(&init_msg, &mut stream).await?;

        info!("waiting for answer... (ACK message)");
        let (payload, shared_mac_data) = utils::read_ack_message(&mut stream).await?;

        info!("ACK message received");
        info!("Received Ack");
        if payload[0] != 0x04 {
            return Err("Didn't received ACK when expecting it".into());
        }

        let (_remote_public_key, remote_nonce, ephemeral_shared_secret) =
            utils::handle_ack_message(&payload, &shared_mac_data, &private_key, &ephemeral_privkey);

        let remote_data = [shared_mac_data, payload].concat();
        let (mut ingress_aes, mut ingress_mac, mut egress_aes, mut egress_mac) = utils::setup_frame(
            remote_nonce,
            nonce,
            ephemeral_shared_secret,
            remote_data,
            init_msg,
        );

        info!("Frame setup done !");

        // Split the stream so reads and writes can later run in separate tasks.
        // Reading inside a `select!` is not cancel-safe: a partially read frame
        // would be dropped whenever a write won the race, desynchronising the stream.
        let (mut reader, mut writer) = stream.into_split();

        info!("Received Ack, waiting for Header");

        let uncrypted_body =
            utils::read_message(&mut reader, &mut ingress_mac, &mut ingress_aes).await?;

        if uncrypted_body[0] == 0x01 {
            warn!("Disconnect message : {}", hex::encode(&uncrypted_body));

            return Err("Disconnected peer".into());
        }

        // Should be HELLO
        assert_eq!(0x80, uncrypted_body[0]);
        let hello_message = message::parse_hello_message(uncrypted_body[1..].to_vec());

        info!(
            "HelloMessage {}",
            serde_json::to_string(&hello_message).unwrap()
        );

        // We need to find the highest eth version it supports
        let mut version = 0;
        for capability in &hello_message.capabilities {
            if capability.0.to_string() == "eth" {
                if capability.1 > version {
                    version = capability.1;
                }
            }
        }

        info!("Sending HELLO message");
        let secp = secp256k1::Secp256k1::new();
        let private_key = secp256k1::SecretKey::from_slice(&private_key).unwrap();
        let hello_message = types::HelloMessage {
            protocol_version: message::BASE_PROTOCOL_VERSION,
            client: String::from("deadbrain corp."),
            capabilities: vec![("eth".into(), 67), ("eth".into(), 68), ("eth".into(), 69)],
            port: 0,
            id: secp256k1::PublicKey::from_secret_key(&secp, &private_key).serialize_uncompressed()
                [1..]
                .to_vec(),
        };
        let hello = message::create_hello_message(hello_message);
        utils::send_message(hello, &mut writer, &mut egress_mac, &mut egress_aes).await?;

        info!("Sending STATUS message");

        let payload: Vec<u8>;
        if version == 69 {
            let status = eth::Status69 {
                version,
                network_id: network.network_id,
                genesis: network.genesis_hash.to_vec(),
                fork_id: (
                    network.fork_id[0].to_be_bytes().to_vec(),
                    network.fork_id[1] as u64,
                ),
                earliest: 0,
                latest: 0,
                latest_hash: network.genesis_hash.to_vec(),
            };
            if network == networks::Network::POLYGON_MAINNET {
                payload = eth::create_eth69_status_message_polygon(status);
            } else {
                payload = eth::create_eth69_status_message(status);
            }
        } else {
            let status = eth::Status {
                version,
                network_id: network.network_id,
                td: network
                    .head_td
                    .to_be_bytes()
                    .iter()
                    .skip_while(|x| **x == 0)
                    .map(|x| *x)
                    .collect(), // Maybe I should just have change the status type. But this is needed for now to remove the zeroes at the begining
                blockhash: network.genesis_hash.to_vec(),
                genesis: network.genesis_hash.to_vec(),
                fork_id: (
                    network.fork_id[0].to_be_bytes().to_vec(),
                    network.fork_id[1] as u64,
                ),
            };
            payload = eth::create_status_message(status);
        }
        utils::send_message(payload, &mut writer, &mut egress_mac, &mut egress_aes).await?;

        info!("Handling STATUS message");
        let uncrypted_body =
            utils::read_message(&mut reader, &mut ingress_mac, &mut ingress_aes).await?;
        if uncrypted_body[0] == 0x01 {
            warn!("Disconnect message : {}", hex::encode(&uncrypted_body));

            return Err("Disconnected peer".into());
        }

        let their_blockhash: Vec<u8>;
        if version == 69 {
            let their_status = if network == networks::Network::POLYGON_MAINNET {
                eth::parse_eth69_status_message_polygon(uncrypted_body[1..].to_vec())
                    .ok_or("Invalid STATUS message")?
            } else {
                eth::parse_eth69_status_message(uncrypted_body[1..].to_vec())
                    .ok_or("Invalid STATUS message")?
            };

            check_same_network(
                &network,
                their_status.network_id,
                &their_status.genesis,
                &their_status.fork_id,
            )?;

            their_blockhash = their_status.latest_hash;
        } else {
            let their_status = eth::parse_status_message(uncrypted_body[1..].to_vec())
                .ok_or("Invalid STATUS message")?;

            check_same_network(
                &network,
                their_status.network_id,
                &their_status.genesis,
                &their_status.fork_id,
            )?;

            their_blockhash = their_status.blockhash;
        }

        /******************
         *
         *  Send UPGRADE STATUS message (binance only)
         *
         ******************/
        if network == networks::Network::BINANCE_MAINNET {
            let upgrade_status = eth::create_upgrade_status_message();
            utils::send_message(
                upgrade_status,
                &mut writer,
                &mut egress_mac,
                &mut egress_aes,
            )
            .await?;
        }

        // Should do the loop here

        let (tx_tcp, rx_tcp) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        let (tx_write, mut rx_write) = tokio::sync::mpsc::channel::<Vec<u8>>(32);

        let tx_reply = tx_write.clone();

        let handle =
            tokio::spawn(async move {
                // Writer: sole owner of the egress state.
                let writer_handle = tokio::spawn(async move {
                    while let Some(msg) = rx_write.recv().await {
                        if let Err(e) =
                            utils::send_message(msg, &mut writer, &mut egress_mac, &mut egress_aes)
                                .await
                        {
                            warn!("Failed to send message: {}", e);
                            return;
                        }
                    }
                });

                // Reader: sole owner of the ingress state. Replies (pong, empty
                // headers) go through the writer's channel.
                loop {
                    let uncrypted_body =
                        match utils::read_message(&mut reader, &mut ingress_mac, &mut ingress_aes)
                            .await
                        {
                            Ok(b) => b,
                            Err(e) => {
                                warn!("Read error: {}", e);
                                break;
                            }
                        };

                    // handle RLPx message
                    if uncrypted_body[0] < 16 {
                        let code = uncrypted_body[0];

                        if code == 2 {
                            // send pong
                            if tx_reply.send(message::create_pong_message()).await.is_err() {
                                warn!("Failed to send pong: writer closed");
                                break;
                            }
                            continue;
                        }

                        if code == 1 {
                            let mut dec = snap::raw::Decoder::new();
                            match dec.decompress_vec(&uncrypted_body[1..]) {
                                Ok(message) => warn!("Disconnected ! {}", hex::encode(&message)),
                                Err(_) => warn!("Disconnected ! (failed to decompress message)"),
                            }
                            break;
                        }

                        info!("Unknown code {}", uncrypted_body[0]);
                        info!("{}", hex::encode(&uncrypted_body));
                        continue;
                    }

                    // drop mempool gossip — we never consume these
                    match uncrypted_body[0] - 16 {
                        1 => trace!("NewBlockHashes received"),
                        2 | 7 | 8 | 9 | 10 => continue,
                        _ => {}
                    }

                    if uncrypted_body[0] - 16 == 11 {
                        let mut dec = snap::raw::Decoder::new();
                        match dec.decompress_vec(&uncrypted_body[1..]) {
                            Ok(message) => info!(
                                "upgrade status message received (only binance) : {}",
                                hex::encode(&message)
                            ),
                            Err(_) => warn!("Failed to decompress upgrade status message"),
                        }
                    }

                    if uncrypted_body[0] - 16 == 3 {
                        let req_id = eth::parse_get_block_bodies(uncrypted_body[1..].to_vec());
                        let empty_block_headers_message =
                            eth::create_empty_block_headers_message(&req_id);
                        if tx_reply.send(empty_block_headers_message).await.is_err() {
                            warn!("Failed to send empty headers: writer closed");
                            break;
                        }
                    }

                    match tx_tcp.try_send(uncrypted_body) {
                        Ok(_) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            warn!("rx_tcp channel full, dropping message");
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            break;
                        }
                    }
                }

                writer_handle.abort();
            });

        Ok(Self {
            handle,
            latest_blockhash: their_blockhash,
            rx_tcp,
            tx_write,
            eth_protocol_version: version,
        })
    }
}
