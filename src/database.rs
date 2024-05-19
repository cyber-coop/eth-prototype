use postgres::Client;
use std::io::prelude::*;
use std::time::Instant;

use crate::types::{Block, Transaction};
use crate::utils;

pub fn create_tables(schema_name: &String, postgres_client: &mut Client) {
    let query = format!(
        "CREATE SCHEMA IF NOT EXISTS {schema_name};
    CREATE TABLE IF NOT EXISTS {schema_name}.blocks (
        height OID NOT NULL,
        hash BYTEA,
        parenthash BYTEA NOT NULL,
        extradata BYTEA NOT NULL
    );
    CREATE TABLE IF NOT EXISTS {schema_name}.transactions (
        txid BYTEA NOT NULL,
        tx_type SMALLINT NOT NULL,
        block BYTEA NOT NULL,
        chain_id BIGINT,
        nonce OID NOT NULL,
        gas_price NUMERIC(78),
        max_priority_fee_per_gas BIGINT,
        max_fee_per_gas BIGINT,
        gas_limit BIGINT NOT NULL,
        fromaddress BYTEA NOT NULL,
        toaddress BYTEA NOT NULL,
        value NUMERIC(78) NOT NULL,
        data BYTEA NOT NULL,
        access_list JSONB,
        max_fee_per_blob_gas INTEGER,
        blob_versioned_hashes JSONB,
        v BIGINT NOT NULL,
        r BYTEA NOT NULL,
        s BYTEA NOT NULL
    );
    CREATE TABLE IF NOT EXISTS {schema_name}.contracts (
        txid BYTEA NOT NULL,
        address BYTEA NOT NULL
    );
    "
    );

    postgres_client.batch_execute(&query).unwrap();
}

pub fn save_blocks(
    blocks: &Vec<(Block, Vec<Transaction>)>,
    schema_name: &String,
    postgres_client: &mut Client,
) {
    // register in database
    let now = Instant::now();
    let mut blocks_string: String = String::new();
    let mut transactions_string: String = String::new();
    // we have a 1Gigabyte limit and the transactions bulk will go over that limit so we split it
    let mut transactions_strings: Vec<String> = vec![];
    let mut contracts_string: String = String::new();

    info!("starting to format blocks and transactions");
    blocks.iter().for_each(|(b, txs)| {
        let tmp = format!(
            "{};\\\\x{};\\\\x{};\\\\x{}\n",
            b.number,
            hex::encode(&b.hash),
            hex::encode(&b.parenthash),
            hex::encode(&b.extradata)
        );

        blocks_string.push_str(&tmp);
        txs.iter().for_each(|t| {
            let tmp = format!(
                "\\\\x{};{};\\\\x{};{};{};{};{};{};{};\\\\x{};\\\\x{};{};\\\\x{};{};{};{};{};\\\\x{};\\\\x{}\n",
                hex::encode(&t.txid),
                t.tx_type,
                hex::encode(&b.hash),
                serde_json::to_string(&t.chain_id).unwrap(),
                t.nonce,
                if let Some(gas_price) = &t.gas_price { gas_price.to_string() } else { "null".to_string() },
                if let Some(max_priority_fee_per_gas) = t.max_priority_fee_per_gas { max_priority_fee_per_gas.to_string() } else { "null".to_string() },
                if let Some(max_fee_per_gas) = t.max_fee_per_gas { max_fee_per_gas.to_string() } else { "null".to_string() },
                t.gas_limit,
                hex::encode(&t.from),
                hex::encode(&t.to),
                t.value.to_string(),
                hex::encode(&t.data),
                serde_json::to_string(&t.access_list).unwrap(),
                if let Some(max_fee_per_blob_gas) = t.max_fee_per_blob_gas { max_fee_per_blob_gas.to_string() } else { "null".to_string() },
                serde_json::to_value(&t.blob_versioned_hashes).unwrap(),
                t.v,
                hex::encode(&t.r),
                hex::encode(&t.s),
            );
            
            // if "to" adddress is empty, calculates the transaction address
            if t.to.is_empty() {
                info!("Calculating contract address");
                let tx_address: Vec <u8> = utils::calculate_tx_addr(&t.from, &t.nonce);
                let tmp = format!(
                    "\\\\x{};\\\\x{}\n",
                hex::encode(&t.txid),
                hex::encode(&tx_address));
                contracts_string.push_str(&tmp);
            }

            // verifying if we are not going over the 1Gigabyte limit if yes we start a new copy in query
            if transactions_string.as_bytes().len() + tmp.as_bytes().len() > 1000000000 {
                transactions_strings.push(transactions_string.clone());
                transactions_string = String::new();
            }
            transactions_string.push_str(&tmp);
        });
    });
    transactions_strings.push(transactions_string.clone());

    info!("Finished formating blocks and transactions message");

    // start a transaction to do rollback in case something goes wrong
    let mut transaction = postgres_client.transaction().unwrap();
    let mut block_writer = transaction
        .copy_in(format!("COPY {}.blocks FROM stdin (DELIMITER ';')", schema_name).as_str())
        .unwrap();
    block_writer.write_all(blocks_string.as_bytes()).unwrap();
    block_writer.finish().unwrap();

    let mut contract_writer = transaction
        .copy_in(format!("COPY {}.contracts FROM stdin (DELIMITER ';')", schema_name).as_str())
        .unwrap();
    contract_writer.write_all(contracts_string.as_bytes()).unwrap();
    contract_writer.finish().unwrap();

    for txs in transactions_strings {
        let mut transaction_writer = transaction
            .copy_in(
                format!(
                    "COPY {}.transactions FROM stdin (DELIMITER ';', NULL 'null')", // use ; as delimiter to avoid confusion with json
                    schema_name
                )
                .as_str(),
            )
            .unwrap();
        transaction_writer.write_all(txs.as_bytes()).unwrap();
        transaction_writer.finish().unwrap();
    }

    // commit the transaction
    transaction.commit().unwrap();

    let current_height = blocks.last().unwrap().0.number;

    info!(
        "Blocks registered in database (current_height {}) {:.2?}",
        current_height,
        now.elapsed()
    );
}

#[cfg(test)]
mod tests {
    use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
    use sha3::{Digest, Keccak256};

    #[test]
    fn test_recover() {
        let digest =
            hex::decode("9c4a3989dac0ab4808f53a83482a99506a3893fedef826b97764f6ca4bb4a864")
                .unwrap();
        let msg = secp256k1::Message::from_digest_slice(&digest).unwrap();
        dbg!(&msg);
        let recid = RecoveryId::from_i32(0).unwrap();
        let sig = RecoverableSignature::from_compact(&hex::decode("98c9df5efd59382699e7444e24bf4985a99a196f0b66626e70cfa5678dd221117e69d64e84fb0bd38a66e4557b645178853aadeb62d212361084bb88e529d708").unwrap(), recid).unwrap();
        dbg!(&sig);
        let pubkey = sig.recover(&msg).unwrap();
        dbg!(hex::encode(&pubkey.serialize_uncompressed()));

        // Calculate address!
        let mut hasher = Keccak256::new();
        hasher.update(&pubkey.serialize_uncompressed()[1..]);
        let address: Vec<u8> = hasher.finalize()[12..].to_vec();

        assert_eq!(
            hex::encode(&address),
            "b18ccf69940177f3ec62920ddb2a08ef7cb16e8f"
        );
    }

    #[test]
    fn test_recover_2() {
        let digest =
            hex::decode("183d0572f8bdfb8c12c3438485642ef55e812813cdee1bc9a8092643b48481b2")
                .unwrap();
        let msg = secp256k1::Message::from_digest_slice(&digest).unwrap();
        let recid = RecoveryId::from_i32(0).unwrap();
        let sig = RecoverableSignature::from_compact(&hex::decode("b7ff1b1f51475d9d2e6f6e12b2ae9d57951846648793a854e25daa9ef2becd9876278a0a880ba2260b4b7413f08a86ece9280c43e5643578c8eddfdaca2b2bc4").unwrap(), recid).unwrap();
        dbg!(&sig);
        let pubkey = sig.recover(&msg).unwrap();
        // let pubkey = VerifyingKey::recover_from_prehash(&digest, &sig, recid).unwrap();
        dbg!(hex::encode(&pubkey.serialize_uncompressed()));

        // Calculate address!
        let mut hasher = Keccak256::new();
        hasher.update(&pubkey.serialize_uncompressed()[1..]);
        let address: Vec<u8> = hasher.finalize()[12..].to_vec();

        assert_eq!(
            hex::encode(&address),
            "9a26f4d07d4d86fd9f6a86255ce5f0941d87767e"
        );
    }

    #[test]
    fn test_recover_3() {
        let digest =
            hex::decode("30cdea07ca81fdcfd42f3190c2684147f0cef708912fd64e745da8ba3045c223")
                .unwrap();
        let msg = secp256k1::Message::from_digest_slice(&digest).unwrap();

        let mut r: Vec<u8> = vec![0; 32];
        let mut s: Vec<u8> = vec![0; 32];
        r.copy_from_slice(
            &hex::decode("cfd6450ec934e24a7c4e9ba512de17daf16813f24feecb3a9e06c5fbe7525bb4")
                .unwrap(),
        );
        s[1..].copy_from_slice(
            &hex::decode("9b474ec4d2b1a8b5944848c19cf69a50f0e53404f4893474803062aa467065").unwrap(),
        );

        let recid = RecoveryId::from_i32(1).unwrap();
        let sig = RecoverableSignature::from_compact(&[r, s].concat().to_vec(), recid).unwrap();
        dbg!(&sig);
        let pubkey = sig.recover(&msg).unwrap();
        // let pubkey = VerifyingKey::recover_from_prehash(&digest, &sig, recid).unwrap();
        dbg!(hex::encode(&pubkey.serialize_uncompressed()));

        // Calculate address!
        let mut hasher = Keccak256::new();
        hasher.update(&pubkey.serialize_uncompressed()[1..]);
        let address: Vec<u8> = hasher.finalize()[12..].to_vec();

        assert_eq!(
            hex::encode(&address),
            "110602942a25d4c7138d9063d738f4934da18de6"
        );
    }

    #[test]
    fn test_serialize() {
        use serde::Serialize;

        #[derive(Serialize)]
        struct Hash(#[serde(with = "hex::serde")] Vec<u8>);

        #[derive(Serialize)]
        struct AccessList(Vec<(Hash, Vec<Hash>)>);

        let access_list: Option<AccessList> = Some(AccessList(vec![]));
        dbg!(serde_json::to_string(&access_list).unwrap());

        let access_list: Option<AccessList> = None;
        dbg!(serde_json::to_string(&access_list).unwrap());

        let access_list: Option<AccessList> = Some(AccessList(vec![(
            Hash(0xdead_i32.to_be_bytes().to_vec()),
            vec![Hash(0xbeef_i32.to_be_bytes().to_vec())],
        )]));
        dbg!(serde_json::to_string(&access_list).unwrap());
    }
}
