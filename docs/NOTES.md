# NOTES

## Find r duplicates

## Data dump

```
pg_dump -n ethereum_rinkeby -d blockchains -U postgres --no-owner -F tar -f ethereum_rinkeby.tar
```

## Look for contract creation tx

```
$ SELECT * FROM ethereum_mainnet.transactions WHERE toaddress = '\x' LIMIT 10;
```

## Select signatures values

```
$ SELECT txid, 0 AS index, r, s, 'Ethereum Rinkeby' as network FROM ethereum_rinkeby.transactions;
```

## Get all the public keys

Well we can't because we need to recover the public key from signature

## Get all the accounts (addresses)

We get all the `toaddress` addresses.
```
$ SELECT DISTINCT toaddress FROM ethereum_rinkeby.transactions;
```

We can't get all the from addresses because we need to recover from signature.
