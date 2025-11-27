# Ethereum P2P indexer

This project is an indexer for Ethereum and Ethereum forks. It takes advantage of the ETH (Ethereum Wire Protocol) to fetch blocks and transactions through P2P messages. This saves a lot of space and the need to maintain a node to get data. It is also significantly faster than the solution using JSON-RPC.

In its current state, the indexer takes 48h to index mainnet from scratch.

### Compatible networks

This Ethereum P2P indexer can run on the following networks **(only on eth/67 and eth/68)**.

```
ethereum_ropsten
ethereum_rinkeby
ethereum_goerli
ethereum_sepolia
ethereum_holesky
ethereum_hoodi
ethereum_mainnet
binance_mainnet
```

## Requirements
- [Rust](https://www.rust-lang.org/tools/install)
- [Docker](https://docs.docker.com/engine/install/)

## Configuration

### Configuration file

You first need to create a `config.toml` file. You can use the example config file `config.example.toml`, fill the missing parts and rename it as `config.toml`.

You'll learn how to setup the different parts of this configuration in the next steps

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

[indexer]
queue_size = 4
```


### Finding peers to connect with

If you don't have any peer to connect with, you can grab one in this [database](https://cyber.coop/network_id/1).

**NOTE**: This database updates daily and lists all "reachable" peers but some of them allow to establish a connection, some others not, you need to try them by yourself.

### Configuration on local/Docker

If you want to run the indexer locally, then leave the localhost as **localhost**.

If you want to run it in a Docker container, set the localhost to **postgres** in the `config.toml` file.

## Quick Start (using docker compose)

To start indexing right away you can take a look at the `contrib/docker-compose.yml` file. This docker compose file starts 2 indexers (Mainnet and Holesky) and a postgres database. To make the database peristent remove the comments for the `volumes`.

You will need to create 2 configs file as described the **Configuration** section for each networks you want to index if you want to index several network.

Specifying the `NETWORK` allow to choose which network to start indexing.

`docker-compose.yml`
```YAML
services:
  indexer_ethereum_mainnet:
    build: https://github.com/cyber-coop/eth-prototype.git
    container_name: "indexer-ethereum-mainnet"
    restart: unless-stopped
    environment:
      RUST_BACKTRACE: "full"
      RUST_LOG: "eth_prototype=info"
      NETWORK: "ethereum_mainnet"
    volumes:
      - ./config.mainnet.toml:/config.toml
    depends_on:
      postgres:
        condition: service_healthy

  indexer_ethereum_holesky:
    build: https://github.com/cyber-coop/eth-prototype.git
    container_name: "indexer-ethereum-holesky"
    restart: unless-stopped
    environment:
      RUST_BACKTRACE: "full"
      RUST_LOG: "eth_prototype=info"
      NETWORK: "ethereum_holesky"
    volumes:
      - ./config.holesky.toml:/config.toml
    depends_on:
      postgres:
        condition: service_healthy


  postgres:
    image: "postgres:18"
    container_name: "postgres"
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: wow
      POSTGRES_DB: blockchains
    # ¡IMPORTANT! If you don't want to lose your data you should uncomment this
    # volumes:
    #   - ./data/:/var/lib/postgresql/
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5
```

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

Now you can run the indexer (replace the network by any of the supported networks' list)

```shell
make run network=ethereum_mainnet
```

## Troubleshooting

### Erigon 2.58 node incomplete block body

When connecting to an erigon node it seems there is some issue with devp2p for version `erigon/v2.58.2-125509e4/linux-amd64/go1.22.1`. It provides us with an incomplete block body message. The missing bytes lead to Rlp decoding error.

## License

Do What The Fuck You Want To Public License

<a href="http://www.wtfpl.net/"><img
       src="http://www.wtfpl.net/wp-content/uploads/2012/12/wtfpl-badge-4.png"
       width="80" height="15" alt="WTFPL" /></a>