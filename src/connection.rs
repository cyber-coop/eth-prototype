use rand_core::RngCore;
use secp256k1::rand;
use secp256k1::SecretKey;
use std::error;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinHandle;

use crate::configs::Peer;
use crate::eth;
use crate::mac;
use crate::message;
use crate::networks;
use crate::types;
use crate::utils;
use crate::utils::Aes256Ctr64BE;

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

        info!("Received Ack, waiting for Header");

        let uncrypted_body =
            utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes).await?;

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
        utils::send_message(hello, &mut stream, &mut egress_mac, &mut egress_aes).await?;

        info!("Sending STATUS message");

        let payload: Vec<u8>;
        if version == 69 {
            let status = eth::Status69 {
                version,
                network_id: network.network_id,
                genesis: network.genesis_hash.to_vec(),
                fork_id: (network.fork_id[0].to_be_bytes().to_vec(), 0),
                earliest: 0,
                latest: 0,
                latest_hash: network.genesis_hash.to_vec(),
            };
            payload = eth::create_eth69_status_message(status);
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
                fork_id: (network.fork_id[0].to_be_bytes().to_vec(), 0),
            };
            payload = eth::create_status_message(status);
        }
        utils::send_message(payload, &mut stream, &mut egress_mac, &mut egress_aes).await?;

        info!("Handling STATUS message");
        let uncrypted_body =
            utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes).await?;
        if uncrypted_body[0] == 0x01 {
            warn!("Disconnect message : {}", hex::encode(&uncrypted_body));

            return Err("Disconnected peer".into());
        }

        let their_blockhash: Vec<u8>;
        if version == 69 {
            let their_status =
                eth::parse_eth69_status_message(uncrypted_body[1..].to_vec()).unwrap();

            if their_status.fork_id.0 != network.fork_id[0].to_be_bytes().to_vec() {
                warn!(
                    "Wrong Fork ID. Expected {} but got {}",
                    hex::encode(network.fork_id[0].to_be_bytes().to_vec()),
                    hex::encode(their_status.fork_id.0)
                );
                return Err("Incompatible fork".into());
            }

            their_blockhash = their_status.latest_hash;
        } else {
            let their_status = eth::parse_status_message(uncrypted_body[1..].to_vec()).unwrap();

            if their_status.fork_id.0 != network.fork_id[0].to_be_bytes().to_vec() {
                warn!(
                    "Wrong Fork ID. Expected {} but got {}",
                    hex::encode(network.fork_id[0].to_be_bytes().to_vec()),
                    hex::encode(their_status.fork_id.0)
                );
                return Err("Incompatible fork".into());
            }

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
                &mut stream,
                &mut egress_mac,
                &mut egress_aes,
            )
            .await?;
        }

        // Should do the loop here

        let (tx_tcp, rx_tcp) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        let (tx_write, mut rx_write) = tokio::sync::mpsc::channel::<Vec<u8>>(32);

        let handle = tokio::spawn(async move {
            let mut code;
            loop {
                tokio::select! {
                    result = utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes) => {
                        let uncrypted_body = match result {
                            Ok(b) => b,
                            Err(e) => { warn!("Read error: {}", e); return; }
                        };

                        // handle RLPx message
                        if uncrypted_body[0] < 16 {
                            code = uncrypted_body[0];

                            if code == 2 {
                                // send pong
                                let pong = message::create_pong_message();
                                if let Err(e) = utils::send_message(pong, &mut stream, &mut egress_mac, &mut egress_aes).await {
                                    warn!("Failed to send pong: {}", e);
                                    return;
                                }
                                continue;
                            }

                            if code == 1 {
                                let mut dec = snap::raw::Decoder::new();
                                match dec.decompress_vec(&uncrypted_body[1..]) {
                                    Ok(message) => warn!("Disconnected ! {}", hex::encode(&message)),
                                    Err(_) => warn!("Disconnected ! (failed to decompress message)"),
                                }
                                return;
                            }

                            info!("Unknown code {}", uncrypted_body[0]);
                            info!("{}", hex::encode(&uncrypted_body));
                            continue;
                        }

                        if uncrypted_body[0] - 16 == 11 {
                            let mut dec = snap::raw::Decoder::new();
                            let message = dec.decompress_vec(&uncrypted_body[1..].to_vec()).unwrap();
                            info!("upgrade status message received (only binance) : {}", hex::encode(&message));
                        }

                        if uncrypted_body[0] - 16 == 3 {
                            let req_id = eth::parse_get_block_bodies(uncrypted_body[1..].to_vec());
                            let empty_block_bodies_message = eth::create_empty_block_headers_message(&req_id);
                            if let Err(e) = utils::send_message(empty_block_bodies_message, &mut stream, &mut egress_mac, &mut egress_aes).await {
                                warn!("Failed to send empty headers: {}", e);
                                return;
                            }
                        }

                        if tx_tcp.send(uncrypted_body).await.is_err() {
                            break;
                        }
                    }
                    Some(msg) = rx_write.recv() => {
                        if let Err(e) = utils::send_message(msg, &mut stream, &mut egress_mac, &mut egress_aes).await {
                            warn!("Failed to send message: {}", e);
                            return;
                        }
                    }
                }
            }
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
