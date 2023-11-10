#![feature(test)]

use eth_prototype::protocols::eth;
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
