use serde::Deserialize;
use std::fs::File;
use std::io::prelude::*;
use toml;

#[derive(Clone, Debug, Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub user: String,
    pub password: String,
    pub dbname: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Peer {
    pub ip: String,
    pub port: u32,
    #[serde(with = "hex::serde")]
    pub remote_id: Vec<u8>, // [u8; 64]
}

#[derive(Clone, Debug, Deserialize)]
pub struct IndexerConfig {
    pub queue_size: u32,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub database: DatabaseConfig,
    pub peers: Vec<Peer>,
    pub indexer: IndexerConfig,
}

pub fn read_config() -> Config {
    let mut file = File::open("config.toml").expect("config.toml file required");
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    let config: Config = toml::from_str(&contents).unwrap();

    return config;
}
