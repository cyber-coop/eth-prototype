##### BUILDER #####
FROM rustlang/rust:nightly as builder

WORKDIR /usr/src/eth-prototype
COPY . .
RUN cargo install --path .

##### RUNNER #####
FROM debian:buster-slim

LABEL author="Lola Rigaut-Luczak <me@laflemme.lol>"
LABEL description="Custom node that allow indexing blocks and transactions from block chains (Ethereum version)."

COPY --from=builder /usr/local/cargo/bin/eth-prototype /usr/local/bin/eth-prototype

RUN apt-get update && rm -rf /var/lib/apt/lists/*

# default env
ENV RUST_LOG "eth_prototype=info"
ENV NETWORK "ethereum_rinkeby"

CMD eth-prototype ${NETWORK}