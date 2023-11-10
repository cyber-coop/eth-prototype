# TODO

- [x] Create `setup_frame` function in `utils.rs`
- [x] Bigint value in sql not big enought
- [x] RLP too long error
- [x] More networks:
    * [x] ~~Rinkeby~~ Deprecated
    * [x] Sepolia
    * [x] Goerli
    * [x] Ethereum Mainnet
    * [x] Binance Mainnet
- [x] Cli command to manage network
- [x] Resume indexing
- [x] Fixing weird transaction that are not list
- [x] Properly handle ETH ~~and LES capabilities~~ (we will only do ETH because EF doesn't want me to)
- [x] Handle all kinds of tx. Add optional `raw_tx` for not legacy tx. (https://eips.ethereum.org/EIPS/eip-1559)
- [x] Fix the ping being answer when saving block (and it takes more than 20 seconds)
- [x] Peer info in the config file instead of hardcoded
- [ ] Generate randomly data that should be genereated randomly
- [x] Move tests from `main.rs` in their own folder to clear things
- [ ] Publish image to docker hub. Make it easier to deploy.