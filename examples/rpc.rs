use byteorder::{BigEndian, ReadBytesExt};
use std::io::prelude::*;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;

use eth_prototype::protocols::eth;
use eth_prototype::types::Transaction;
use eth_prototype::{configs, message, networks, types, utils};

const BLOCK_NUM: usize = 1024;

fn main() {
    // TRYING USING RPC-JSON

    let client = reqwest::blocking::Client::new();
    let starting_height = 18578940;

    let now = Instant::now();

    println!("Starting chrono");

    for i in 0..1024 {
        let param = serde_json::json!({"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":[format!("0x{:x}", starting_height - i), true],"id":1});

        dbg!(&param.to_string());

        let _res = client
            .post("https://ethereum.publicnode.com")
            .json(&param)
            .send()
            .unwrap();
    }

    let elapsed = now.elapsed();
    println!("Elapsed: {:.2?}", elapsed);

    // TRYNG THORUGHT PP NETWORK

    let now = Instant::now();

    // Load config values from the config file
    let config = configs::read_config();
    let network = networks::Network::find("ethereum_mainnet").unwrap();
    let mut current_hash: Vec<u8> = vec![];

    let mut stream =
        TcpStream::connect(format!("{}:{}", config.peer.ip, config.peer.port)).unwrap();
    let remote_id = config.peer.remote_id;

    let private_key =
        hex::decode("472D4B6150645267556B58703273357638792F423F4528482B4D625165546856").unwrap();
    // Should be generated randomly
    let nonce =
        hex::decode("09267e7d55aada87e46468b2838cc616f084394d6d600714b58ad7a3a2c0c870").unwrap();
    // Epheremal private key (should be random)
    let ephemeral_privkey =
        hex::decode("691bb7a2fd6647eae78a235b9d305d09f796fe8e8ce7a18aa1aa1deff9649a02").unwrap();
    // Pad (should be generated randomly)
    let pad = hex::decode("eb035e803db3b2dea4a2c724739e7edaecb14ef242f5f4df58386b10626ab4887cc84d9dea153f24526200f4089946f4c4b26c283ac7e923e0c53dd1de83682df2fe44f4fe841c480465b38533e30c373ccb0022b95d722d577828862c9fe7e87e5e730bdecd4f358c7673e0999a06190f03e6d0ca98dae5aae8f16ca81c92").unwrap();

    /******************
     *
     *  Create Auth message (EIP8 supported)
     *
     ******************/
    println!("Creating EIP8 Auth message");
    let init_msg =
        utils::create_auth_eip8(&remote_id, &private_key, &nonce, &ephemeral_privkey, &pad);

    // send the message
    println!("Sending EIP8 Auth message");
    stream.write(&init_msg).unwrap();
    stream.flush().unwrap();

    println!("waiting for answer...");
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

    println!("ACK message received");
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

    // Mutex is not used here but it use in the main program so we need it...
    let mut egress_aes = Arc::new(Mutex::new(egress_aes));
    let mut egress_mac = Arc::new(Mutex::new(egress_mac));

    println!("Frame setup done !");

    println!("Received Ack, waiting for Header");

    /******************
     *
     *  Handle HELLO
     *
     ******************/

    let uncrypted_body = utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes);

    // Should be HELLO
    assert_eq!(0x80, uncrypted_body[0]);
    let payload = rlp::decode::<types::HelloMessage>(&uncrypted_body[1..]).unwrap();

    /******************
     *
     *  Create Hello
     *
     ******************/

    println!("Sending HELLO message");
    let hello = message::create_hello_message(&private_key);
    utils::send_message(hello, &mut stream, &mut egress_mac, &mut egress_aes);

    /******************
     *
     *  Send STATUS message
     *
     ******************/

    println!("Sending STATUS message");

    let genesis_hash = network.genesis_hash.to_vec();
    let head_td = 0;
    let fork_id = network.fork_id.to_vec();
    let network_id = network.network_id;

    // let status = message::create_status_message(&genesis_hash, &genesis_hash, &head_td, &fork_id, &network_id);
    let status = eth::create_status_message(
        &68,
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

    println!("Handling STATUS message");
    let uncrypted_body = utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes);
    current_hash = eth::parse_status_message(uncrypted_body[1..].to_vec());

    /****************************
     *
     *  START FETCHING BLOCKS
     *
     ****************************/

    /******************
     *
     *  Send GetBlockHeaders message
     *
     ******************/

    println!("Sending GetBlockHeaders message");
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

    println!("Handling BlockHeaders message");
    let mut uncrypted_body: Vec<u8>;
    let mut code;
    loop {
        uncrypted_body = utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes);

        if uncrypted_body[0] < 16 {
            println!("Code {}", uncrypted_body[0]);
            println!("{}", hex::encode(&uncrypted_body));
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
    current_hash = block_headers.last().unwrap().parent_hash.to_vec();

    /******************
     *
     *  Send GetBlockBodies message
     *
     ******************/
    println!("Sending GetBlockBodies message");
    let hashes = block_headers
        .iter()
        .map(|b| b.hash.clone())
        .collect::<Vec<Vec<u8>>>();

    let mut transactions: Vec<Vec<Transaction>> = vec![];

    while transactions.len() < BLOCK_NUM {
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

        println!(
            "Handling BlockBodies message ({}/{BLOCK_NUM} txs received)",
            transactions.len()
        );
        let mut uncrypted_body: Vec<u8>;
        let mut code;
        loop {
            uncrypted_body = utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes);

            if uncrypted_body[0] < 16 {
                println!("Code {}", uncrypted_body[0]);
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

    let elapsed = now.elapsed();
    println!("Elapsed: {:.2?}", elapsed);
}
