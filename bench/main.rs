#![feature(test)]

use eth_prototype::protocols::eth;
use eth_prototype::types::{Block, Transaction};
use postgres::Client;
use std::fs;
use std::io::Write;
use test::Bencher;

extern crate test;

#[bench]
fn bench_copy_in(b: &mut Bencher) {
    let mut postgres_client = Client::connect(
        &format!("host=localhost user=postgres password=wow dbname=blockchains"),
        postgres::NoTls,
    )
    .unwrap();
    let blocks = fs::read("bench/blocks_header.dat").unwrap();
    let block_headers = eth::parse_block_headers(blocks);

    let query = format!(
        "CREATE SCHEMA IF NOT EXISTS tmp;
    CREATE TABLE IF NOT EXISTS tmp.blocks (
        height OID NOT NULL,
        hash BYTEA,
        parenthash BYTEA NOT NULL,
        extradata BYTEA NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tmp.transactions (
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

    let mut blocks_string: String = String::new();
    block_headers.iter().for_each(|b| {
        let tmp = format!(
            "{},\\\\x{},\\\\x{},\\\\x{}\n",
            b.number,
            hex::encode(&b.hash),
            hex::encode(&b.parenthash),
            hex::encode(&b.extradata)
        );

        blocks_string.push_str(&tmp);
    });

    b.iter(|| {
        let mut block_writer = postgres_client
            .copy_in("COPY tmp.blocks FROM stdin (DELIMITER ',')")
            .unwrap();
        block_writer.write_all(blocks_string.as_bytes()).unwrap();
        block_writer.finish().unwrap();
    })
}

#[bench]
fn bench_insert(b: &mut Bencher) {
    let mut postgres_client = Client::connect(
        &format!("host=localhost user=postgres password=wow dbname=blockchains"),
        postgres::NoTls,
    )
    .unwrap();
    let blocks = fs::read("bench/blocks_header.dat").unwrap();
    let block_headers = eth::parse_block_headers(blocks);

    let query = format!(
        "CREATE SCHEMA IF NOT EXISTS tmp;
    CREATE TABLE IF NOT EXISTS tmp.blocks (
        height OID NOT NULL,
        hash BYTEA,
        parenthash BYTEA NOT NULL,
        extradata BYTEA NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tmp.transactions (
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

    let mut blocks_string: String = "INSERT INTO tmp.blocks values".to_string();
    block_headers.iter().for_each(|b| {
        let tmp = format!(
            "({},'\\x{}','\\x{}','\\x{}'),",
            b.number,
            hex::encode(&b.hash),
            hex::encode(&b.parenthash),
            hex::encode(&b.extradata)
        );

        blocks_string.push_str(&tmp);
    });

    blocks_string.replace_range(blocks_string.len() - 1..blocks_string.len(), ";");
    
    b.iter(|| {
        postgres_client.execute(&blocks_string, &[]).unwrap();

    })
}

#[bench]
fn bench_copy_in_blocks_and_txs(b: &mut Bencher) {
    let mut postgres_client = Client::connect(
        &format!("host=localhost user=postgres password=wow dbname=blockchains"),
        postgres::NoTls,
    )
    .unwrap();
    let blocks = fs::read("bench/blocks_header.dat").unwrap();
    let block_headers = eth::parse_block_headers(blocks);

    let mut txs_bin = fs::read("bench/txs.dat").unwrap();

    let mut blocks: Vec<(Block, Vec<Transaction>)> = vec![];
    while txs_bin.len() > 0 {
        let size = usize::from_be_bytes(txs_bin[0..8].try_into().unwrap());
        // we removed a byte so length is size-1
        let data = txs_bin[8..size+8-1].to_vec();
        let tmp = eth::parse_block_bodies(data);

        let t_iter = tmp.iter();
        t_iter.enumerate().for_each(|(i, txs)| {
            blocks.push((block_headers[i].clone(), txs.to_vec()));
        });

        txs_bin = txs_bin[size+8-1..].to_vec();
    };


    let query = format!(
        "CREATE SCHEMA IF NOT EXISTS tmp;
    CREATE TABLE IF NOT EXISTS tmp.blocks (
        height OID NOT NULL,
        hash BYTEA,
        parenthash BYTEA NOT NULL,
        extradata BYTEA NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tmp.transactions (
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

    let mut blocks_string: String = String::new();
    let mut transactions_string: String = String::new();

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

    b.iter(|| {
        let mut block_writer = postgres_client
            .copy_in("COPY tmp.blocks FROM stdin (DELIMITER ',')")
            .unwrap();
        block_writer.write_all(blocks_string.as_bytes()).unwrap();
        block_writer.finish().unwrap();

        let mut transaction_writer = postgres_client
        .copy_in(
            format!(
                "COPY tmp.transactions FROM stdin (DELIMITER ',')")
            .as_str(),
        )
        .unwrap();
    transaction_writer
        .write_all(transactions_string.as_bytes())
        .unwrap();
    transaction_writer.finish().unwrap();
    })
}

#[bench]
fn bench_insert_blocks_and_txs(b: &mut Bencher) {
    let mut postgres_client = Client::connect(
        &format!("host=localhost user=postgres password=wow dbname=blockchains"),
        postgres::NoTls,
    )
    .unwrap();
    let blocks = fs::read("bench/blocks_header.dat").unwrap();
    let block_headers = eth::parse_block_headers(blocks);

    let mut txs_bin = fs::read("bench/txs.dat").unwrap();

    let mut blocks: Vec<(Block, Vec<Transaction>)> = vec![];
    while txs_bin.len() > 0 {
        let size = usize::from_be_bytes(txs_bin[0..8].try_into().unwrap());
        // we removed a byte so length is size-1
        let data = txs_bin[8..size+8-1].to_vec();
        let tmp = eth::parse_block_bodies(data);

        let t_iter = tmp.iter();
        t_iter.enumerate().for_each(|(i, txs)| {
            blocks.push((block_headers[i].clone(), txs.to_vec()));
        });

        txs_bin = txs_bin[size+8-1..].to_vec();
    };

    let query = format!(
        "CREATE SCHEMA IF NOT EXISTS tmp;
    CREATE TABLE IF NOT EXISTS tmp.blocks (
        height OID NOT NULL,
        hash BYTEA,
        parenthash BYTEA NOT NULL,
        extradata BYTEA NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tmp.transactions (
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

    let mut blocks_string: String = "INSERT INTO tmp.blocks values".to_string();
    let mut transactions_string: String = "INSERT INTO tmp.transactions values".to_string();

    blocks.iter().for_each(|(b, txs)| {
        let tmp = format!(
            "({},'\\x{}','\\x{}','\\x{}'),",
            b.number,
            hex::encode(&b.hash),
            hex::encode(&b.parenthash),
            hex::encode(&b.extradata)
        );

        blocks_string.push_str(&tmp);

        txs.iter().for_each(|t| {
            let tmp = format!(
                "('\\x{}','\\x{}',{},{},{},'\\x{}','\\x{}','\\x{}',{},'\\x{}','\\x{}','\\x{}')",
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

    blocks_string.replace_range(blocks_string.len() - 1..blocks_string.len(), ";");
    transactions_string.replace_range(transactions_string.len() - 1..transactions_string.len(), ";");
    
    b.iter(|| {
        postgres_client.execute(&blocks_string, &[]).unwrap();
        postgres_client.execute(&transactions_string, &[]).unwrap();

    })
}
