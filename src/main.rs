use byteorder::{BigEndian, ReadBytesExt};
use secp256k1::rand::RngCore;
use secp256k1::{rand, SecretKey};
use std::env;
use std::io::prelude::*;
use std::net::TcpStream;
use std::sync::mpsc::sync_channel;
use std::thread;
use std::time::Duration;

use eth_prototype::protocols::eth;
use eth_prototype::types::{Block, Transaction};
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
        .expect("expecting a network (ethereum_rinkeby, ethereum_goerli, ethereum_sepolia, ethereum_mainnet or binance_mainnet).");
    let network = networks::Network::find(network_arg.as_str()).unwrap();

    // Load config values from the config file
    let config = configs::read_config();
    let mut current_hash: Vec<u8> = vec![];

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
    let result = postgres_client.query(format!("SELECT parenthash FROM {0}.blocks WHERE height = (SELECT MIN(height) FROM {0}.blocks);", network_arg).as_str(), &[]).unwrap();

    if result.len() > 0 {
        let row = &result[0];
        let hash = row.try_get(0);
        match hash {
            Ok(h) => {
                current_hash = h;
            }
            Err(_) => {}
        }

        info!("We are starting at hash {}", hex::encode(&current_hash));
    }

    /******************
     *
     *  Connect to peer
     *
     ******************/
    let mut stream =
        TcpStream::connect(format!("{}:{}", config.peer.ip, config.peer.port)).unwrap();
    let remote_id = config.peer.remote_id;

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
    let init_msg =
        utils::create_auth_eip8(&remote_id, &private_key, &nonce, &ephemeral_privkey, &pad);

    // send the message
    info!("Sending EIP8 Auth message");
    stream.write(&init_msg).unwrap();
    stream.flush().unwrap();

    info!("waiting for answer...");
    let mut buf = [0u8; 2];
    let _size = stream.read(&mut buf);

    let size_expected = buf.as_slice().read_u16::<BigEndian>().unwrap() as usize;
    let shared_mac_data = &buf[0..2];

    let mut payload = vec![0u8; size_expected.into()];
    let size = stream.read(&mut payload).unwrap();

    assert_eq!(size, size_expected);

    /******************
     *
     *  Handle Ack
     *
     ******************/

    info!("ACK message received");
    let decrypted =
        utils::decrypt_message(&payload.to_vec(), &shared_mac_data.to_vec(), &private_key);

    // decode RPL data
    let rlp = rlp::Rlp::new(&decrypted);
    let mut rlp = rlp.into_iter();

    // id to pubkey
    let remote_public_key: Vec<u8> = [vec![0x04], rlp.next().unwrap().as_val().unwrap()].concat();
    let remote_nonce: Vec<u8> = rlp.next().unwrap().as_val().unwrap();

    let ephemeral_shared_secret = utils::ecdh_x(&remote_public_key, &ephemeral_privkey);

    /******************
     *
     *  Setup Frame
     *
     ******************/

    let remote_data = [shared_mac_data, &payload].concat();
    let (mut ingress_aes, mut ingress_mac, mut egress_aes, mut egress_mac) = utils::setup_frame(
        remote_nonce,
        nonce,
        ephemeral_shared_secret,
        remote_data,
        init_msg,
    );

    info!("Frame setup done !");

    info!("Received Ack, waiting for Header");

    /******************
     *
     *  Handle HELLO
     *
     ******************/

    let uncrypted_body = utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes);

    // Should be HELLO
    assert_eq!(0x80, uncrypted_body[0]);
    let payload = rlp::decode::<types::HelloMessage>(&uncrypted_body[1..]).unwrap();

    dbg!(&payload);

    /******************
     *
     *  Create Hello
     *
     ******************/

    info!("Sending HELLO message");
    let hello = message::create_hello_message(&private_key);
    utils::send_message(hello, &mut stream, &mut egress_mac, &mut egress_aes);

    /******************
     *
     *  Send STATUS message
     *
     ******************/

    info!("Sending STATUS message");

    let genesis_hash = network.genesis_hash.to_vec();
    let head_td = 0;
    let fork_id = network.fork_id.to_vec();
    let network_id = network.network_id;

    let status = eth::create_status_message(
        &genesis_hash,
        &genesis_hash,
        &head_td,
        &fork_id,
        &network_id,
    );
    utils::send_message(status, &mut stream, &mut egress_mac, &mut egress_aes);

    /******************
     *
     *  Handle STATUS message
     *
     ******************/

    info!("Handling STATUS message");
    let uncrypted_body = utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes);
    let their_current_hash = eth::parse_status_message(uncrypted_body[1..].to_vec());

    // If we do't have blocks in the database we use the best one
    if current_hash.len() == 0 {
        current_hash = their_current_hash;
    }

    /********************
     *
     *  Start database thread
     *
     ********************/

    // Create a simple streaming channel (limited buffer of 4 batch of 1024 blocks to avoid filling ram)
    let (tx, rx) = sync_channel(4);

    let _thread_handle = thread::spawn(move || {
        info!("Starting database thread");

        // Connect to database
        let mut postgres_client =
            postgres::Client::connect(&database_params, postgres::NoTls).unwrap();

        // while recv save blocks in database
        loop {
            let blocks: Vec<(Block, Vec<Transaction>)> = rx.recv().unwrap();
            database::save_blocks(&blocks, &network_arg, &mut postgres_client);

            // We are synced
            if network.genesis_hash.to_vec() == blocks.last().unwrap().0.hash.to_vec() {
                info!("We are synced !");
                break;
            }
        }

        info!("Closing thread!");
    });

    /****************************
     *
     *  START FETCHING BLOCKS
     *
     ****************************/

    loop {
        /******************
         *
         *  Send GetBlockHeaders message
         *
         ******************/

        info!("Sending GetBlockHeaders message");
        let get_blocks_headers =
            eth::create_get_block_headers_message(&current_hash, BLOCK_NUM, 0, true);
        utils::send_message(
            get_blocks_headers,
            &mut stream,
            &mut egress_mac,
            &mut egress_aes,
        );

        /******************
         *
         *  Handle BlockHeader message
         *
         ******************/

        info!("Handling BlockHeaders message");
        let mut uncrypted_body: Vec<u8>;
        let mut code;
        loop {
            uncrypted_body = utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes);

            if uncrypted_body[0] < 16 {
                info!("Code {}", uncrypted_body[0]);
                info!("{}", hex::encode(&uncrypted_body));
                code = uncrypted_body[0];

                if code == 2 {
                    // send pong
                    let pong = message::create_pong_message();
                    utils::send_message(pong, &mut stream, &mut egress_mac, &mut egress_aes);
                }
                continue;
            }

            code = uncrypted_body[0] - 16;
            if code == 4 {
                break;
            }
        }

        assert_eq!(code, 4);

        let block_headers = eth::parse_block_headers(uncrypted_body[1..].to_vec());

        // update block hash
        current_hash = block_headers.last().unwrap().parenthash.to_vec();

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

        let mut transactions: Vec<Vec<Transaction>> = vec![];

        while transactions.len() < hashes.len() {
            let get_blocks_bodies =
                eth::create_get_block_bodies_message(&hashes[transactions.len()..].to_vec());
            utils::send_message(
                get_blocks_bodies,
                &mut stream,
                &mut egress_mac,
                &mut egress_aes,
            );

            /******************
             *
             *  Handle BlockHeader message
             *
             ******************/

            info!(
                "Handling BlockBodies message ({}/{BLOCK_NUM} txs received)",
                transactions.len()
            );
            let mut uncrypted_body: Vec<u8>;
            let mut code;
            loop {
                uncrypted_body =
                    utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes);

                if uncrypted_body[0] < 16 {
                    info!("Code {}", uncrypted_body[0]);
                    trace!("{}", hex::encode(&uncrypted_body));
                    code = uncrypted_body[0];

                    if code == 2 {
                        // send pong
                        let pong = message::create_pong_message();
                        utils::send_message(pong, &mut stream, &mut egress_mac, &mut egress_aes);
                    }
                    continue;
                }

                code = uncrypted_body[0] - 16;
                if code == 6 {
                    break;
                }
            }
            assert_eq!(code, 6);

            let tmp_txs = eth::parse_block_bodies(uncrypted_body[1..].to_vec());
            transactions.extend(tmp_txs);
        }

        let mut blocks: Vec<(Block, Vec<Transaction>)> = vec![];
        let t_iter = transactions.iter();
        t_iter.enumerate().for_each(|(i, txs)| {
            blocks.push((block_headers[i].clone(), txs.to_vec()));
        });

        let current_height = blocks.last().unwrap().0.number;
        info!("Blocks n° {}", current_height);

        // send blocks to the other thread to save in database
        if blocks.len() > 0 {
            tx.send(blocks).unwrap();
        }

        if current_height == 0 {
            info!("Data fully synced");
            break;
        }
    }
}
