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

## Look at transactions per contract

```
CREATE MATERIALIZED VIEW contracts AS SELECT c.address, COUNT(DISTINCT t.txid) FROM ethereum_mainnet.transactions t RIGHT JOIN ethereum_mainnet.contracts c ON c.address = t.toaddress GROUP BY c.address;
```

## Troubelshooting

### Rospten transaction index

There is apparently 2 transactions with the same txid in Rospten but that are included in different blocks.

```
blockchains=# SELECT * FROM ethereum_ropsten.transactions WHERE txid = '\x1abfd69255ca1791da6a00c729707348d63670221aaacbac5160dbb234430e7a'
blockchains-# ;
	                                txid                                |                               block                                | nonce | gasprice | gaslimit |                 toaddress                 
 | value |                                                                    data                                                                    |  v   |                                 r                   
               |                                 s                                  |                                                                                                                              
                                                      raw                                                                                                                                                          
                           
--------------------------------------------------------------------+--------------------------------------------------------------------+-------+----------+----------+-------------------------------------------
-+-------+--------------------------------------------------------------------------------------------------------------------------------------------+------+-----------------------------------------------------
---------------+--------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
---------------------------
 \x1abfd69255ca1791da6a00c729707348d63670221aaacbac5160dbb234430e7a | \x5efe8c021dd98b0b834d1377f596a156a58c710af92153639ac0be10039c5e38 |   991 |        0 |    29817 | \x0908376b760421303711e9c397ec897897258f3a
 | \x    | \x095ea7b3000000000000000000000000d61144557dfb4953c20c376affa6b4a3780c99d1000000000000000000000000000000000000000000000000e92596fd62900000 | \x31 | \x40d755b31bff08bf0db5df9cf957636ab07171403705e8c350
b3e448f1f95713 | \x74cdf82ad3993075dd35fd1a3f4c4146058ecf4d82f122d9abacd1a6f9e273d2 | \x02f8b1038203df8459682f008459682f0e827479940908376b760421303711e9c397ec897897258f3a80b844095ea7b3000000000000000000000000d61
144557dfb4953c20c376affa6b4a3780c99d1000000000000000000000000000000000000000000000000e92596fd62900000c001a040d755b31bff08bf0db5df9cf957636ab07171403705e8c350b3e448f1f95713a074cdf82ad3993075dd35fd1a3f4c4146058ecf
4d82f122d9abacd1a6f9e273d2
 \x1abfd69255ca1791da6a00c729707348d63670221aaacbac5160dbb234430e7a | \xc48beccf35e6f73bc1e79c60cb19c77eccff6b964a3a8bcd179c6e8b181ccded |   991 |        0 |    29817 | \x0908376b760421303711e9c397ec897897258f3a
 | \x    | \x095ea7b3000000000000000000000000d61144557dfb4953c20c376affa6b4a3780c99d1000000000000000000000000000000000000000000000000e92596fd62900000 | \x31 | \x40d755b31bff08bf0db5df9cf957636ab07171403705e8c350
b3e448f1f95713 | \x74cdf82ad3993075dd35fd1a3f4c4146058ecf4d82f122d9abacd1a6f9e273d2 | \x02f8b1038203df8459682f008459682f0e827479940908376b760421303711e9c397ec897897258f3a80b844095ea7b3000000000000000000000000d61
144557dfb4953c20c376affa6b4a3780c99d1000000000000000000000000000000000000000000000000e92596fd62900000c001a040d755b31bff08bf0db5df9cf957636ab07171403705e8c350b3e448f1f95713a074cdf82ad3993075dd35fd1a3f4c4146058ecf
4d82f122d9abacd1a6f9e273d2
(2 rows)
```

In order to create index we need to remove one...
