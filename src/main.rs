use eth_prototype::configs::Peer;
use eth_prototype::networks::Network;
use secp256k1::rand::RngCore;
use secp256k1::{rand, SecretKey};
use std::env;
use std::error;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::process;
use std::str::FromStr;
use std::sync::mpsc::SyncSender;
use std::sync::mpsc::{channel, sync_channel};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use eth_prototype::eth;
use eth_prototype::types::{Block, Transaction, Withdrawal};
use eth_prototype::{configs, database, message, networks, types, utils};

#[macro_use]
extern crate log;

// max value seems to be 1024 (https://github.com/ethereum/go-ethereum/blob/master/eth/protocols/eth/handler.go#L40)
const BLOCK_NUM: usize = 1024;

fn main() {
    // Init log
    env_logger::init();

    info!("Ethereum mini node in rust");

    // Read cli args for network value
    let network_arg: String = env::args()
        .nth(1)
        .expect("expecting a network (ethereum_ropsten, ethereum_rinkeby, ethereum_goerli, ethereum_sepolia, ethereum_holesky, ethereum_hoodi, ethereum_mainnet or binance_mainnet).");
    let network = networks::Network::find(network_arg.as_str()).unwrap();

    // Load config values from the config file
    let config = configs::read_config();
    let mut current_hash: Vec<u8> = vec![];
    let mut reverse = true; // when we init syncing we go from the tip to the genesis block

    /******************
     *
     *  Connect to postgres
     *
     ******************/
    let mut postgres_client: postgres::Client;
    let database_params = format!(
        "host={} user={} password={} dbname={}",
        config.database.host,
        config.database.user,
        config.database.password,
        config.database.dbname
    );
    loop {
        let result = postgres::Client::connect(&database_params, postgres::NoTls);

        match result {
            Ok(client) => {
                postgres_client = client;
                break;
            }
            Err(_) => {
                warn!("Fail to connect to database. Retrying in 20 seconds...");
                thread::sleep(Duration::from_secs(20));
            }
        }
    }
    info!("Connected to database");

    // create the tables if they don't exist
    database::create_tables(&network_arg, &mut postgres_client);

    // get the hash of the next block in the chain going reverse
    // we should check if we are at the genesis block and that the parenthash is 0x0000......
    let result = postgres_client.query(format!("SELECT parent_hash FROM {0}.blocks WHERE number = (SELECT MIN(number) FROM {0}.blocks);", network_arg).as_str(), &[]).unwrap();

    if result.len() > 0 {
        let row = &result[0];
        let hash = row.try_get(0);
        match hash {
            Ok(h) => {
                current_hash = h;
            }
            Err(_) => {
                error!("Fail to get hash of the minimum block");
            }
        }

        if current_hash
            == hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
        {
            info!("We are already synced completly!");

            // We get the highest block to keep indexing the new ones
            let result = postgres_client.query(format!("SELECT hash, number FROM {0}.blocks WHERE number = (SELECT MAX(number) FROM {0}.blocks);", network_arg).as_str(), &[]).unwrap();

            let row = &result[0];
            let hash = row.try_get(0);

            let number: i32 = row.try_get(1).unwrap();
            dbg!(number);

            match hash {
                Ok(h) => {
                    current_hash = h;
                    reverse = false; // The initial sync has been done. We keep indexing the new incoming blocks now.
                }
                Err(_) => {
                    error!("Fail to get hash of the max block");
                }
            }

            info!("We now save the new incoming blocks");
        }

        info!("We are starting at hash {}", hex::encode(&current_hash));
    }

    /********************
     *
     *  Start database thread
     *
     ********************/

    // Create a queue with a maximum of 102400 blocks (100 * 1024 = 102400 blocks). We query blocks by batch of 1024 blocks.
    let (tx, rx) = sync_channel(100);

    let database_handle = thread::spawn(move || {
        info!("Starting database thread");

        // Connect to database
        let mut postgres_client =
            postgres::Client::connect(&database_params, postgres::NoTls).unwrap();

        // while recv save blocks in database
        loop {
            let blocks: Vec<(Block, Vec<Transaction>, Vec<Block>, Vec<Withdrawal>)> =
                rx.recv().unwrap();
            database::save_blocks(&blocks, &network_arg, &mut postgres_client);

            // We are synced
            if network.genesis_hash.to_vec() == blocks.last().unwrap().0.hash.to_vec() {
                info!("We are synced !");
                // Open, read and execute SQL scripts at the end of sync
                utils::open_exec_sql_file(&network_arg, &mut postgres_client);
                break;
            }
        }

        info!("Closing thread!");
    });

    for peer in config.peers {
        match run(peer, network, &mut current_hash, reverse, &tx) {
            Ok(()) => {
                // We are done
                break;
            }
            Err(_) => {
                // next peer
                continue;
            }
        };
    }

    info!("Tried all peers");
    // need to wait for database thread to finish
    database_handle.join().unwrap();
}

fn run(
    peer: Peer,
    network: Network,
    current_hash: &mut Vec<u8>,
    reverse: bool,
    tx: &SyncSender<Vec<(Block, Vec<Transaction>, Vec<Block>, Vec<Withdrawal>)>>,
) -> Result<(), Box<dyn error::Error>> {
    /******************
     *
     *  Connect to peer
     *
     ******************/
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from_str(&format!("{}:{}", peer.ip, peer.port)).unwrap(),
        Duration::from_secs(3),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;

    let private_key = SecretKey::new(&mut rand::thread_rng())
        .secret_bytes()
        .to_vec();
    let mut nonce = vec![0; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ephemeral_privkey = SecretKey::new(&mut rand::thread_rng())
        .secret_bytes()
        .to_vec();
    let pad = vec![0; 100]; // should be generated randomly but we don't really care

    /******************
     *
     *  Create Auth message (EIP8 supported)
     *
     ******************/
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
    utils::send_eip8_auth_message(&init_msg, &mut stream)?;

    info!("waiting for answer... (ACK message)");
    let (payload, shared_mac_data) = utils::read_ack_message(&mut stream)?;

    /******************
     *
     *  Handle Ack
     *
     ******************/

    info!("ACK message received");
    info!("Received Ack");
    if payload[0] != 0x04 {
        return Err("Didn't received ACK when expecting it".into());
    }

    let (_remote_public_key, remote_nonce, ephemeral_shared_secret) =
        utils::handle_ack_message(&payload, &shared_mac_data, &private_key, &ephemeral_privkey);

    /******************
     *
     *  Setup Frame
     *
     ******************/

    let remote_data = [shared_mac_data, payload].concat();
    let (mut ingress_aes, mut ingress_mac, egress_aes, egress_mac) = utils::setup_frame(
        remote_nonce,
        nonce,
        ephemeral_shared_secret,
        remote_data,
        init_msg,
    );
    let mut egress_aes = Arc::new(Mutex::new(egress_aes));
    let mut egress_mac = Arc::new(Mutex::new(egress_mac));

    info!("Frame setup done !");

    info!("Received Ack, waiting for Header");

    /******************
     *
     *  Handle HELLO
     *
     ******************/

    let uncrypted_body = utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes)?;

    if uncrypted_body[0] == 0x01 {
        warn!("Disconnect message : {}", hex::encode(&uncrypted_body));

        return Err("Disconnected peer".into());
    }

    // Should be HELLO
    assert_eq!(0x80, uncrypted_body[0]);
    let hello_message = message::parse_hello_message(uncrypted_body[1..].to_vec());

    info!("{:#?}", &hello_message);

    // We need to find the highest eth version it supports
    let _capabilities = serde_json::to_string(&hello_message.capabilities).unwrap();

    // We need to find the highest eth version it supports
    let mut version = 0;
    for capability in &hello_message.capabilities {
        if capability.0.to_string() == "eth" {
            if capability.1 > version && capability.1 < 69 {
                version = capability.1;
            }
        }
    }

    /******************
     *
     *  Create Hello
     *
     ******************/

    info!("Sending HELLO message");
    let secp = secp256k1::Secp256k1::new();
    let private_key = secp256k1::SecretKey::from_slice(&private_key).unwrap();
    let hello_message = types::HelloMessage {
        protocol_version: message::BASE_PROTOCOL_VERSION,
        client: String::from("deadbrain corp."),
        capabilities: vec![("eth".into(), 67), ("eth".into(), 68)],
        port: 0,
        id: secp256k1::PublicKey::from_secret_key(&secp, &private_key).serialize_uncompressed()
            [1..]
            .to_vec(),
    };
    let hello = message::create_hello_message(hello_message);
    utils::send_message(hello, &mut stream, &mut egress_mac, &mut egress_aes)?;

    /******************
     *
     *  Send STATUS message
     *
     ******************/

    info!("Sending STATUS message");

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

    let payload = eth::create_status_message(status);
    utils::send_message(payload, &mut stream, &mut egress_mac, &mut egress_aes)?;

    /******************
     *
     *  Handle STATUS message
     *
     ******************/

    info!("Handling STATUS message");
    let uncrypted_body = utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes)?;
    if uncrypted_body[0] == 0x01 {
        warn!("Disconnect message : {}", hex::encode(&uncrypted_body));

        return Err("Disconnected peer".into());
    }
    let their_status = eth::parse_status_message(uncrypted_body[1..].to_vec()).unwrap();

    if their_status.fork_id.0 != network.fork_id[0].to_be_bytes().to_vec() {
        warn!(
            "Wrong Fork ID. Expected {} but got {}",
            hex::encode(network.fork_id[0].to_be_bytes().to_vec()),
            hex::encode(their_status.fork_id.0)
        );
        return Err("Incompatible fork".into());
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
        )?;
    }

    // If we don't have blocks in the database we use the best one
    if current_hash.len() == 0 {
        *current_hash = their_status.blockhash;
    }

    /****************************
     *
     *  START FETCHING BLOCKS
     *
     ****************************/

    let mut thread_stream = stream.try_clone().unwrap();
    let thread_egress_mac = Arc::clone(&egress_mac);
    let thread_egress_aes = Arc::clone(&egress_aes);

    let (tx_tcp, rx_tcp) = channel();

    let _tcp_handle = thread::spawn(move || {
        let mut uncrypted_body: Vec<u8>;
        let mut code;
        loop {
            uncrypted_body =
                utils::read_message(&mut thread_stream, &mut ingress_mac, &mut ingress_aes)
                    .unwrap();

            // handle RLPx message
            if uncrypted_body[0] < 16 {
                code = uncrypted_body[0];

                if code == 2 {
                    // send pong
                    let pong = message::create_pong_message();

                    utils::send_message(
                        pong,
                        &mut thread_stream,
                        &thread_egress_mac,
                        &thread_egress_aes,
                    )
                    .unwrap();
                }

                if code == 1 {
                    // Received a disconnect message
                    let mut dec = snap::raw::Decoder::new();
                    let message = dec.decompress_vec(&uncrypted_body[1..].to_vec()).unwrap();

                    warn!("Disconnected ! {}", hex::encode(&message));

                    return;
                }

                info!("Unknown code {}", uncrypted_body[0]);
                info!("{}", hex::encode(&uncrypted_body));

                continue;
            }

            if uncrypted_body[0] - 16 == 11 {
                let mut dec = snap::raw::Decoder::new();
                let message = dec.decompress_vec(&uncrypted_body[1..].to_vec()).unwrap();
                info!(
                    "upgrade status message received (only binance) : {}",
                    hex::encode(&message)
                );
            }

            if uncrypted_body[0] - 16 == 3 {
                // Rospten node keep asking us for new block headers that we don't have
                // Working with Geth/v1.10.23-stable-d901d853 but not v1.10.21
                let req_id = eth::parse_get_block_bodies(uncrypted_body[1..].to_vec());
                let empty_block_bodies_message = eth::create_empty_block_headers_message(&req_id);

                utils::send_message(
                    empty_block_bodies_message,
                    &mut thread_stream,
                    &thread_egress_mac,
                    &thread_egress_aes,
                )
                .unwrap();
            }

            tx_tcp.send(uncrypted_body).unwrap();
        }
    });

    loop {
        /******************
         *
         *  Send GetBlockHeaders message
         *
         ******************/

        info!("Sending GetBlockHeaders message");

        let get_blocks_headers =
            eth::create_get_block_headers_message(&current_hash, BLOCK_NUM, 0, reverse);
        utils::send_message(
            get_blocks_headers,
            &mut stream,
            &mut egress_mac,
            &mut egress_aes,
        )?;

        /******************
         *
         *  Handle BlockHeader message
         *
         ******************/

        info!("Handling BlockHeaders message");
        let mut uncrypted_body: Vec<u8>;
        let mut code;
        loop {
            uncrypted_body = rx_tcp.recv()?;

            code = uncrypted_body[0] - 16;
            if code == 4 {
                break;
            }
        }

        assert_eq!(code, 4);

        let block_headers = eth::parse_block_headers(uncrypted_body[1..].to_vec());

        // update block hash
        if reverse {
            *current_hash = block_headers.last().unwrap().parent_hash.to_vec();
        } else {
            *current_hash = block_headers.last().unwrap().hash.to_vec();
        }

        /******************
         *
         *  Send GetBlockBodies message
         *
         ******************/
        info!("Sending GetBlockBodies message");
        let hashes = block_headers
            .iter()
            .map(|b| b.hash.clone())
            .collect::<Vec<Vec<u8>>>();

        let mut transactions: Vec<(Vec<Transaction>, Vec<Block>, Vec<Withdrawal>)> = vec![];

        while transactions.len() < hashes.len() {
            let get_blocks_bodies =
                eth::create_get_block_bodies_message(&hashes[transactions.len()..].to_vec());
            utils::send_message(
                get_blocks_bodies,
                &mut stream,
                &mut egress_mac,
                &mut egress_aes,
            )?;

            /******************
             *
             *  Handle BlockHeader message
             *
             ******************/

            let mut uncrypted_body: Vec<u8>;
            let mut code;
            loop {
                uncrypted_body = rx_tcp.recv()?;

                code = uncrypted_body[0] - 16;
                if code == 6 {
                    break;
                }
            }
            assert_eq!(code, 6);

            let tmp_txs = eth::parse_block_bodies(uncrypted_body[1..].to_vec());
            transactions.extend(tmp_txs);

            info!(
                "Handling BlockBodies message ({}/{} block bodies received)",
                transactions.len(),
                hashes.len()
            );
        }

        let mut blocks: Vec<(Block, Vec<Transaction>, Vec<Block>, Vec<Withdrawal>)> = vec![];
        let t_iter = transactions.iter();
        t_iter
            .enumerate()
            .for_each(|(i, (txs, ommers, withdrawals))| {
                blocks.push((
                    block_headers[i].clone(),
                    txs.to_vec(),
                    ommers.to_vec(),
                    withdrawals.to_vec(),
                ));
            });

        let current_height = blocks.last().unwrap().0.number;
        info!("Blocks n° {}", current_height);

        // We already have the first block of the current batch when toward the tip of the chain
        if (!reverse) {
            blocks.remove(0);
        }

        // send blocks to the other thread to save in database
        if blocks.len() > 0 {
            tx.send(blocks)?;
        }

        if current_height == 0 {
            info!("Data fully synced");

            break;
        }
    }
    Ok(())
}
