use sha3::{Keccak256, Digest};

use super::constants::BASE_PROTOCOL_OFFSET;
use crate::types::{Block, Transaction};
use crate::message::parse_transaction;

/// NOTES: this is redundant with what we have in eth and unless we end up using this we should remove this.

// create status message following the LES protocol
pub fn create_status_message(genesis_hash: &Vec<u8>, head_hash: &Vec<u8>, head_td: &u64, fork_id: &Vec<u32>, network_id: &u32) -> Vec<u8> {
    let mut s = rlp::RlpStream::new();
    s.begin_unbounded_list();
    // Protocol version
    s.begin_list(2);
    s.append(&"protocolVersion");
    s.append(&4_u8);
    // network Id
    s.begin_list(2);
    s.append(&"networkId");
    s.append(network_id);
    // head Td
    s.begin_list(2);
    s.append(&"headTd");
    s.append(head_td);
    // head Hash
    s.begin_list(2);
    s.append(&"headHash");
    s.append(head_hash);
    // head Num
    s.begin_list(2);
    s.append(&"headNum");
    s.append(&vec![]);  
    // genesis Hash
    s.begin_list(2);
    s.append(&"genesisHash");
    s.append(genesis_hash);
    // fork ID
    s.begin_list(2);
    s.append(&"forkID");
    s.begin_list(2);
    s.append(&fork_id[0]);
    s.append(&fork_id[1]);
    // recentTxLookup
    s.begin_list(2);
    s.append(&"recentTxLookup");
    s.append(&0x01_u8);

    s.finalize_unbounded_list();

    let payload = s.as_raw();
    let code: Vec<u8> = vec![0x00 + BASE_PROTOCOL_OFFSET];

    let mut enc = snap::raw::Encoder::new();
    let payload_compressed = enc.compress_vec(&payload).unwrap();

    return [code.to_vec(), payload_compressed].concat();
}

pub fn parse_status_message_les(payload: Vec<u8>) -> u64 {
    let mut dec = snap::raw::Decoder::new();
    let message = dec.decompress_vec(&payload).unwrap();

    let r = rlp::Rlp::new(&message);
    assert!(r.is_list());

    let count = r.item_count().unwrap();
    for i in 0..count {
        let key_value = r.at(i).unwrap();

        let key: String = key_value.at(0).unwrap().as_val().unwrap();
        if key == "genesisHash" {
            let hash = key_value.at(1).unwrap().as_raw().to_vec();
            println!("Genesis hash {}", hex::encode(hash));
        }
        if key == "headNum" {
            let height: u64 = key_value.at(1).unwrap().as_val().unwrap();
            println!("found height {}", height);
            return height;
        }
    }

    assert!(false, "No height!");
    return 0;
}

pub fn create_get_block_headers_message(hash: usize, block_num: usize, skip: usize, reverse: bool) -> Vec<u8> {
    let mut s = rlp::RlpStream::new();
    s.begin_unbounded_list();
    // req ID
    s.append(&0x42_u8);

    s.begin_list(4);
    // block
    s.append(&hash);
    // block numbers
    s.append(&block_num);
    // skip
    s.append(&skip);
    // reverse
    let mut r = 0_u8;
    if reverse { r = 1_u8; };
    s.append(&r);

    s.finalize_unbounded_list();

    let payload = s.as_raw();
    let code: Vec<u8> = vec![0x02 + BASE_PROTOCOL_OFFSET];

    let mut enc = snap::raw::Encoder::new();
    let payload_compressed = enc.compress_vec(&payload).unwrap();

    return [code.to_vec(), payload_compressed].concat();
}


pub fn parse_block_headers(payload: Vec<u8>) -> Vec<Block> {
    let mut dec = snap::raw::Decoder::new();
    let message = dec.decompress_vec(&payload).unwrap();

    let r = rlp::Rlp::new(&message);
    assert!(r.is_list());

    // let req_id: usize = r.at(0).unwrap().as_val().unwrap();
    // let buffer_value: usize = r.at(1).unwrap().as_val().unwrap(); // wtf is that buffer value ?
    let block_headers = r.at(2).unwrap();

    assert!(block_headers.is_list());
    
    let mut hashes = vec![];
    let count = block_headers.item_count().unwrap();
    for i in 0..count {
        let block_header = block_headers.at(i).unwrap();

        let parent_hash: Vec<u8> = block_header.at(0).unwrap().as_val().unwrap();
        // let ommers_hash = block_header.at(1).unwrap().as_raw();
        // let coinbase = block_header.at(2).unwrap().as_raw();
        // let state_root = block_header.at(3).unwrap().as_raw();
        // let txs_root = block_header.at(4).unwrap().as_raw();
        // let receipts_root = block_header.at(5).unwrap().as_raw();
        // let bloom = block_header.at(6).unwrap().as_raw();
        // let difficulty: u64 = block_header.at(7).unwrap().as_val().unwrap();
        let number: u32 = block_header.at(8).unwrap().as_val().unwrap();
        // let gas_limit: u32 = block_header.at(9).unwrap().as_val().unwrap();
        // let gas_used: u32 = block_header.at(10).unwrap().as_val().unwrap();
        // let time: u32 = block_header.at(11).unwrap().as_val().unwrap();
        let extradata: Vec<u8> = block_header.at(12).unwrap().as_val().unwrap();
        // let mix_digest = block_header.at(13).unwrap().as_raw();
        // let block_nonce = block_header.at(14).unwrap().as_raw();
        //let basefee_per_gas: u32 = block_header.at(15).unwrap().as_val().unwrap();

        // get hash 
        let mut hasher = Keccak256::new();
        hasher.update(block_header.as_raw());
        let hash = hasher.finalize();
        hashes.push(Block { number, hash: hash.to_vec(), parenthash: parent_hash.to_vec(), extradata: extradata.to_vec() } );

        info!("Block hash : {}", hex::encode(&hash));
        info!("Number : {}", number);
    };

    return hashes;
}

pub fn create_get_block_bodies_message(hashes: &Vec<Vec<u8>>) -> Vec<u8> {
    let mut s = rlp::RlpStream::new();
    s.begin_unbounded_list();
    // req ID
    s.append(&0x42_u8);

    s.begin_list(hashes.len());

    for hash in hashes {
        s.append(hash);
    }

    s.finalize_unbounded_list();

    let payload = s.as_raw();
    let code: Vec<u8> = vec![0x04 + BASE_PROTOCOL_OFFSET];

    let mut enc = snap::raw::Encoder::new();
    let payload_compressed = enc.compress_vec(&payload).unwrap();

    return [code.to_vec(), payload_compressed].concat();
}

pub fn parse_block_bodies(payload: Vec<u8>) -> Vec<Vec<Transaction>> {
    let mut dec = snap::raw::Decoder::new();
    let message = dec.decompress_vec(&payload).unwrap();

    let r = rlp::Rlp::new(&message);
    assert!(r.is_list());

    // let req_id: usize = r.at(0).unwrap().as_val().unwrap();
    // let buffer_value: usize = r.at(1).unwrap().as_val().unwrap(); // wtf is that buffer value ?
    let block_bodies = r.at(2).unwrap();

    let mut result: Vec<Vec<Transaction>> = vec![];

    let count = block_bodies.item_count().unwrap();
    for i in 0..count {
        let block_body = block_bodies.at(i).unwrap();
        assert!(block_body.is_list());

        let transactions = block_body.at(0).unwrap();
        let count_tx = transactions.item_count().unwrap();

        info!("Transactions count : {}", count_tx);

        let mut result_transactions: Vec<Transaction> = vec![];

        for j in 0..count_tx {
            let transaction = transactions.at(j).unwrap();
            let t = parse_transaction(transaction.as_raw().to_vec());
            result_transactions.push(t);
        }

        result.push(result_transactions);
    }

    return result;
}