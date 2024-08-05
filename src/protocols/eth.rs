use sha3::{Digest, Keccak256};

use super::constants::BASE_PROTOCOL_OFFSET;
use crate::message::parse_transaction;
use crate::types::{Block, Transaction};

// Create status message following the ETH protocol
pub fn create_status_message(
    version: &usize,
    genesis_hash: &Vec<u8>,
    head_hash: &Vec<u8>,
    head_td: &u64,
    fork_id: &Vec<u32>,
    network_id: &u32,
) -> Vec<u8> {
    let mut s = rlp::RlpStream::new();
    s.begin_unbounded_list();
    // Protocol version
    s.append(version);
    // network Id
    s.append(network_id);
    // head Td
    s.append(head_td);
    // head Hash
    s.append(head_hash);
    // genesis Hash
    s.append(genesis_hash);
    // fork ID
    s.begin_list(2);
    s.append(&fork_id[0]);
    s.append(&fork_id[1]);

    s.finalize_unbounded_list();

    let payload = s.as_raw();
    let code: Vec<u8> = vec![0x00 + BASE_PROTOCOL_OFFSET];

    let mut enc = snap::raw::Encoder::new();
    let payload_compressed = enc.compress_vec(&payload).unwrap();

    return [code.to_vec(), payload_compressed].concat();
}

pub fn parse_status_message(payload: Vec<u8>) -> Vec<u8> {
    let mut dec = snap::raw::Decoder::new();
    let message = dec.decompress_vec(&payload).unwrap();

    let r = rlp::Rlp::new(&message);
    assert!(r.is_list());

    let _version: u16 = r.at(0).unwrap().as_val().unwrap();
    let _network_id: u16  = r.at(1).unwrap().as_val().unwrap();
    // let td: u16 = r.at(2).unwrap().as_val().unwrap();
    let blockhash: Vec<u8> = r.at(3).unwrap().as_val().unwrap();
    let _genesis: Vec<u8> = r.at(4).unwrap().as_val().unwrap();

    return blockhash;
}

pub fn create_get_block_headers_message(
    hash: &Vec<u8>,
    block_num: usize,
    skip: usize,
    reverse: bool,
) -> Vec<u8> {
    let mut s = rlp::RlpStream::new();
    s.begin_unbounded_list();
    // req ID
    s.append(&0x42_u8);

    s.begin_list(4);
    // block
    s.append(hash);
    // block numbers
    s.append(&block_num);
    // skip
    s.append(&skip);
    // reverse
    let mut r = 0_u8;
    if reverse {
        r = 1_u8;
    };
    s.append(&r);

    s.finalize_unbounded_list();

    let payload = s.as_raw();
    let code: Vec<u8> = vec![0x03 + BASE_PROTOCOL_OFFSET];

    let mut enc = snap::raw::Encoder::new();
    let payload_compressed = enc.compress_vec(&payload).unwrap();

    return [code.to_vec(), payload_compressed].concat();
}

pub fn parse_get_block_bodies(payload: Vec<u8>) -> usize {
    let mut dec = snap::raw::Decoder::new();
    let message = dec.decompress_vec(&payload).unwrap();

    let r = rlp::Rlp::new(&message);
    assert!(r.is_list());

    let req_id: usize = r.at(0).unwrap().as_val().unwrap();

    return req_id;
}

pub fn create_empty_block_headers_message(req_id: &usize) -> Vec<u8> {
    let mut s = rlp::RlpStream::new();

    s.begin_unbounded_list();
    s.append(req_id);

    s.begin_list(0);
    s.finalize_unbounded_list();

    let payload = s.as_raw();
    let code: Vec<u8> = vec![0x04 + BASE_PROTOCOL_OFFSET];

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
    let block_headers = r.at(1).unwrap();

    assert!(block_headers.is_list());

    let mut headers = vec![];
    let count = block_headers.item_count().unwrap();
    for i in 0..count {
        let block_header = block_headers.at(i).unwrap().as_raw();
        let block = util_parse_block_header(block_header.to_vec());
        headers.push(block);
    }

    return headers;
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
    let code: Vec<u8> = vec![0x05 + BASE_PROTOCOL_OFFSET];

    let mut enc = snap::raw::Encoder::new();
    let payload_compressed = enc.compress_vec(&payload).unwrap();

    return [code.to_vec(), payload_compressed].concat();
}

pub fn parse_block_bodies(payload: Vec<u8>) -> Vec<(Vec<Transaction>, Vec<Block>)> {
    let mut dec = snap::raw::Decoder::new();
    let message = dec.decompress_vec(&payload).unwrap();

    let r = rlp::Rlp::new(&message);
    assert!(r.is_list());

    // let req_id: usize = r.at(0).unwrap().as_val().unwrap();
    let block_bodies = r.at(1).unwrap();

    let mut result: Vec<(Vec<Transaction>, Vec<Block>)> = vec![];

    let count = block_bodies.item_count().unwrap();
    for i in 0..count {
        let block_body = block_bodies.at(i).unwrap();
        assert!(block_body.is_list());

        let transactions = block_body.at(0).unwrap();
        let count_tx = transactions.item_count().unwrap();
        let ommers = block_body.at(1).unwrap();
        let count_om = ommers.item_count().unwrap();

        trace!("Transactions count : {}", count_tx);

        let mut result_transactions: Vec<Transaction> = vec![];
        let mut result_ommers: Vec<Block> = vec![];

        for j in 0..count_tx {
            let transaction = transactions.at(j).unwrap();
            let t = parse_transaction(transaction.as_raw().to_vec());
            result_transactions.push(t);
        }

        for k in 0..count_om {
            let ommer = ommers.at(k).unwrap();
            let om = util_parse_block_header(ommer.as_raw().to_vec());
            result_ommers.push(om);
        }

        result.push((result_transactions, result_ommers));
    }

    return result;
}

pub fn util_parse_block_header(payload: Vec<u8>) -> Block {
    let r = rlp::Rlp::new(&payload);

    assert!(r.is_list());

    let parent_hash: Vec<u8> = r.at(0).unwrap().as_val().unwrap();
    let ommers_hash: Vec<u8> = r.at(1).unwrap().as_val().unwrap();
    let coinbase: Vec<u8> = r.at(2).unwrap().as_val().unwrap();
    let state_root: Vec<u8> = r.at(3).unwrap().as_val().unwrap();
    let txs_root: Vec<u8> = r.at(4).unwrap().as_val().unwrap();
    let receipts_root: Vec<u8> = r.at(5).unwrap().as_val().unwrap();
    let bloom: Vec<u8> = r.at(6).unwrap().as_val().unwrap();
    let difficulty: u64 = r.at(7).unwrap().as_val().unwrap();
    let number: u32 = r.at(8).unwrap().as_val().unwrap();
    let gas_limit: u32 = r.at(9).unwrap().as_val().unwrap();
    let gas_used: u32 = r.at(10).unwrap().as_val().unwrap();
    let time: u32 = r.at(11).unwrap().as_val().unwrap();
    let extradata: Vec<u8> = r.at(12).unwrap().as_val().unwrap();
    let mix_digest: Vec<u8> = r.at(13).unwrap().as_val().unwrap();
    let block_nonce: Vec<u8> = r.at(14).unwrap().as_val().unwrap();
    let mut basefee_per_gas: u64 = 0;
    if r.at(15).is_ok() {
        basefee_per_gas = r.at(15).unwrap().as_val().unwrap();
    }
    let mut withdrawals_root: Vec<u8> = vec![];
    if r.at(16).is_ok() {
        withdrawals_root = r.at(16).unwrap().as_val().unwrap();
    }
    // get hash
    let mut hasher = Keccak256::new();
    hasher.update(r.as_raw());
    let hash = hasher.finalize();
    trace!("Block hash : {}", hex::encode(&hash));
    trace!("Number : {}", number);
    return Block {
        hash: hash.to_vec(),
        parent_hash,
        ommers_hash,
        coinbase,
        state_root,
        txs_root,
        receipts_root,
        bloom,
        difficulty,
        number,
        gas_limit,
        gas_used,
        time,
        extradata,
        mix_digest,
        block_nonce,
        basefee_per_gas,
        withdrawals_root,
    };
}

// This is for Binance only
// This is the upgrade status message (0x0b)
// https://github.com/bnb-chain/bsc/blob/v1.2.10/eth/protocols/eth/handshake.go#L71
pub fn create_upgrade_status_message() -> Vec<u8> {
    let mut s = rlp::RlpStream::new();
    s.begin_list(1);
    s.begin_list(1);

    s.append_empty_data();

    let payload = s.as_raw();
    let code: Vec<u8> = vec![0x0b + BASE_PROTOCOL_OFFSET];

    let mut enc = snap::raw::Encoder::new();
    let payload_compressed = enc.compress_vec(&payload).unwrap();

    return [code.to_vec(), payload_compressed].concat();
}

#[cfg(test)]
mod tests {
    use crate::protocols::constants::BASE_PROTOCOL_OFFSET;

    use super::create_upgrade_status_message;

    #[test]
    fn test_create_upgrade_status_message() {
        let payload = create_upgrade_status_message();

        assert_eq!(payload[0] - BASE_PROTOCOL_OFFSET, 0x0b);

        let mut dec = snap::raw::Decoder::new();
        let message = dec.decompress_vec(&payload[1..].to_vec()).unwrap();

        assert_eq!(
            hex::encode(&message),
            "c2c180"
        );
    }
}