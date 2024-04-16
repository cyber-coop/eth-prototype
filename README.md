# Ethereum P2P indexer

This project is an indexer for Ethereum and Ethereum forks. It takes advantage of the ETH (Ethereum Wire Protocol) to fetch blocks and transactions through P2P messages. This saves a lot of space and the need to maintain a node to get data. It is also significantly faster than solution that use JSON-RPC.

In its current state, the indexer takes 48h to index mainnet from scratch.


## Requirements
- [Rust](https://www.rust-lang.org/tools/install)
- [Docker](https://docs.docker.com/engine/install/)

## Configuration

### Configuration file

You first need to create a `config.toml` file. You can use the example config file `config.example.toml`, fill the missing parts and rename it as `config.toml`.

```toml
# Database info
[database]
localhost = "localhost"
user = "postgres"
password = "wow"
dbname = "blockchains"

# Mainnet peer to connect to
[peer]
ip = "127.0.0.1"
port = 30303
remote_id = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
```
### Finding peers to connect with

If you don't have any peer to connect with, you can grab one in this [database](https://cyber.coop/network_id/1).

**NOTE**: Not all peers are working, a node-finder/tester is currently being developed.

### Configuration on local/Docker

If you want to run the indexer locally, then leave the localhost as **localhost**.

If you want to run it on Docker, please set the localhost to **postgres** in the `config.toml` file.


### Docker compose

To facilitate things, we have provided a `docker-compose.yml` file under the `contrib` folder that starts the indexer and the postgres database.

**NOTE**: There is some modification to do in the docker compose file to make the database persistent.

### Choosing the network

This Ethereum P2P indexer can run on the following networks **(only on eth/67 and eth/68)**.

```
ethereum_ropsten
ethereum_rinkeby
ethereum_goerli
ethereum_sepolia
ethereum_mainnet
binance_mainnet
```

Make sure you set the desired network in the `docker-compose.yml` file.

## Run locally

### Creating the database

First, you need to create the postgres database:

```shell
make postgres
```

Then you can check the database is properly created: 

```shell
docker ps
```

### Run the indexer

Now you can run the indexer (replace the network by the desired one)

```shell
make run network=ethereum_mainnet
```

## Run on Docker

Make sure you've set the localhost to **postgres** in the `config.toml` file, then run the following command:

```shell
docker compose -f contrib/docker-compose.yml up
```

If you've made any edits in the `docker-compose.yml` file, make sure to add **--build**.

```shell
docker compose -f contrib/docker-compose.yml up --build
```

**NOTE**: There is some modification to do in the docker compose file to make the database persistent.

### Creating the database

First, you need to create the postgres database:

```shell
make postgres
```

Then you can check the database is properly created: 

```shell
docker ps
```

### Run the indexer

Now you can run the indexer:

```shell
make run network=ethereum_mainnet
```

## A little benchmark

Depending on your hardware configuration, the indexer can run faster or slower.

Here is a test of the indexer running on two different machines (with their configurations) and their rates of total processed blocks per second to have a general idea.

### First machine

**Machine:** OVH Server
**OS:** Ubuntu 22.04 Jammy Jellyfish
**CPU:** Intel Atom N2800 - 2 cores / 4 threads - 1,86 GHz
**RAM:** 4 GB 1066 MHz
**Hard drive:** 1 TB HDD Sata

Blocks per second: 13 (average)

### Second machine

**Machine:** Macbook Pro 2020
**OS:** macOS Sonoma 14.0
**CPU:** Intel Core i5 - 4 cores / 8 threads - 1,4 GHz
**RAM:** 8 GB 2133 MHz LPDDR3
**Hard drive:** 256 GB SSD

Blocks per second: 128 (average)

## License

Do What The Fuck You Want To Public License

<a href="http://www.wtfpl.net/"><img
       src="http://www.wtfpl.net/wp-content/uploads/2012/12/wtfpl-badge-4.png"
       width="80" height="15" alt="WTFPL" /></a>