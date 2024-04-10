# Ethereum P2P indexer

This project is an indexer for Ethereum and Ethereum forks. It takes advantage of the ETH (Ethereum Wire Protocol) to fetch blocks and transactions through P2P messages. This saves a lot of space and the need to maintain a node to get data. It is also significantly faster than solution that use JSON-RPC.

In its current state, the indexer takes 48h to index mainnet from scratch.

## Requirements
- [Rust](https://www.rust-lang.org/tools/install)
- [Docker](https://docs.docker.com/engine/install/)

## Run

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


### Docker compose

To facilitate things, we have provided a `docker-compose.yml` file under the `contrib` folder that the start the indexer and the postgres database.

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

## License

Do What The Fuck You Want To Public License

<a href="http://www.wtfpl.net/"><img
       src="http://www.wtfpl.net/wp-content/uploads/2012/12/wtfpl-badge-4.png"
       width="80" height="15" alt="WTFPL" /></a>