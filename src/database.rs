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
        v BIGINT NOT NULL,
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
    // we have a 1Gigabyte limit and the transactions bulk will go over that limit so we split it
    let mut transactions_strings: Vec<String> = vec![];

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
        .copy_in(format!("COPY {}.blocks FROM stdin (DELIMITER ',')", schema_name).as_str())
        .unwrap();
    block_writer.write_all(blocks_string.as_bytes()).unwrap();
    block_writer.finish().unwrap();

    for txs in transactions_strings {
        let mut transaction_writer = transaction
            .copy_in(
                format!(
                    "COPY {}.transactions FROM stdin (DELIMITER ',')",
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
