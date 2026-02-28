##### BUILDER #####
FROM rust:1.93-slim-trixie AS builder

WORKDIR /usr/src/eth-prototype

COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/eth-prototype/target \
    cargo install --path .

##### RUNNER #####
FROM debian:trixie-slim

LABEL author="Lola Rigaut-Luczak <me@laflemme.lol>"
LABEL description="Custom node that allow indexing blocks and transactions from block chains (Ethereum version)."

COPY --from=builder /usr/local/cargo/bin/eth-prototype /usr/local/bin/eth-prototype

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# default env
ENV RUST_LOG="eth_prototype=info"
ENV NETWORK="ethereum_mainnet"

ENTRYPOINT ["/bin/sh", "-c", "exec eth-prototype ${NETWORK}"]