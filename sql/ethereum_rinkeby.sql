-- Ethereum Rinkeby

--- Quick Analyze

ANALYZE ethereum_rinkeby.blocks;
ANALYZE ethereum_rinkeby.transactions;

-- Ropsten have duplicates that we need to remove...
CREATE TABLE ethereum_rinkeby.tx_dup AS SELECT s.txid, s.block FROM ethereum_rinkeby.transactions s JOIN (SELECT txid, count(*) FROM ethereum_rinkeby.transactions GROUP BY txid HAVING COUNT(*) > 1) d ON s.txid = d.txid ORDER BY s.txid;
DELETE FROM ethereum_rinkeby.transactions t USING (SELECT DISTINCT ON (txid) * FROM ethereum_rinkeby.tx_dup) dup WHERE t.txid = dup.txid AND t.block = dup.block;

--- Create Primary key and Foreign key
ALTER TABLE ethereum_rinkeby.blocks ADD CONSTRAINT hash_pk PRIMARY KEY (hash);
ALTER TABLE ethereum_rinkeby.transactions ADD CONSTRAINT txid_pk PRIMARY KEY (txid);
ALTER TABLE ethereum_rinkeby.transactions ADD CONSTRAINT block_fk FOREIGN KEY(block) REFERENCES ethereum_rinkeby.blocks(hash);

--- Create Index
---- We use B-Tree indexing because later we want to do more insert of new transactions and it is supposedly faster 
CREATE INDEX index_toaddress ON ethereum_rinkeby.transactions using btree (toaddress);
