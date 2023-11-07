use postgres::Client;
use std::io::prelude::*;
use std::time::Instant;

use crate::types::{Block, Transaction};

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
        block BYTEA NOT NULL,
        nonce OID NOT NULL,
        gasprice BIGINT,
        gaslimit BIGINT,
        toaddress BYTEA NOT NULL,
        value BYTEA NOT NULL,
        data BYTEA NOT NULL,
        v BYTEA NOT NULL,
        r BYTEA NOT NULL,
        s BYTEA NOT NULL,
        raw BYTEA
    );"
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

    info!("starting to format blocks and transactions");
    blocks.iter().for_each(|(b, txs)| {
        let tmp = format!(
            "{},\\\\x{},\\\\x{},\\\\x{}\n",
            b.number,
            hex::encode(&b.hash),
            hex::encode(&b.parenthash),
            hex::encode(&b.extradata)
        );

        blocks_string.push_str(&tmp);
        txs.iter().for_each(|t| {
            let tmp = format!(
                "\\\\x{},\\\\x{},{},{},{},\\\\x{},\\\\x{},\\\\x{},{},\\\\x{},\\\\x{},\\\\x{}\n",
                hex::encode(&t.txid),
                hex::encode(&b.hash),
                t.nonce,
                t.gas_price,
                t.gas_limit,
                hex::encode(&t.to),
                hex::encode(&t.value),
                hex::encode(&t.data),
                t.v,
                hex::encode(&t.r),
                hex::encode(&t.s),
                hex::encode(&t.raw),
            );

            transactions_string.push_str(&tmp);
        });
    });
    info!("Finished formating blocks and transactions message");

    let mut block_writer = postgres_client
        .copy_in(format!("COPY {}.blocks FROM stdin (DELIMITER ',')", schema_name).as_str())
        .unwrap();
    block_writer.write_all(blocks_string.as_bytes()).unwrap();
    block_writer.finish().unwrap();

    let mut transaction_writer = postgres_client
        .copy_in(
            format!(
                "COPY {}.transactions FROM stdin (DELIMITER ',')",
                schema_name
            )
            .as_str(),
        )
        .unwrap();
    transaction_writer
        .write_all(transactions_string.as_bytes())
        .unwrap();
    transaction_writer.finish().unwrap();

    let current_height = blocks.last().unwrap().0.number;

    info!(
        "Blocks registered in database (current_height {}) {:.2?}",
        current_height,
        now.elapsed()
    );
}
