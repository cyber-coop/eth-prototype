# Ethereum P2P indexer

This project is an indexer for Ethereum and Ethereum forks. It takes advantage of the ETH (Ethereum Wire Protocol) to fetch blocks and transactions throught P2P messages. This save a lot of space and the need to maintain a node to get data. It is also significantly faster than solution that use JSON-RPC.

In its current state, the indexer take 48h to index mainnet from scratch.

## Run

### Configuration file

You need first to create a `config.toml` file. You can use the example config file `config.example.toml` and fill the missing parts.

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

### Docker compose

To facilitate things, we have provided a `docker-compose.yml` file under the `contrib` folder that the start the indexer and the postgres database.

**NOTE**: There is some modification to in the docker compose file to make the database persistent.

## License

Do What The Fuck You Want To Public License

<a href="http://www.wtfpl.net/"><img
       src="http://www.wtfpl.net/wp-content/uploads/2012/12/wtfpl-badge-4.png"
       width="80" height="15" alt="WTFPL" /></a>