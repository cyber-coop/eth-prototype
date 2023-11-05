# Ethereum P2P indexer

This project is an indexer for Ethereum and Ethereum forks. It takes advantage of the ETH (Ethereum Wire Protocol) to fetch blocks and transactions throught P2P messages. This save a lot of space and the need to maintain a node to get data.

This has been developped for researchers and academics who might be intersted in the Ethereum block chain data (or Binance because it works also with bsc).

In its current state, the indexer might take 30 days for fully sync mainnet. However it is only a PoC for now and there is many possible optimizations that could reduce significatly the indexing time.

## Run

### Configuration file

You need first to create a `config.toml` file. You can us the example config file `config.example.toml` and fill the missing parts.

```toml
# Database info
[database]
localhost = "localhost"
user = "postgres"
password = "wow"
dbname = "blockchains"

# Mainnet peer to connect to
[Peer]
ip = "127.0.0.1"
port = 30303
id = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
```

### Docker compose

To facilitate things, we have provided a `docker-compose.yml` file that the start the indexer and the postgres database.

**NOTE**: There is some modification to in the docker compose file to make the databse persistent.

## License

![WTFPL](http://www.wtfpl.net/wp-content/uploads/2012/12/logo-220x1601.png)
DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE