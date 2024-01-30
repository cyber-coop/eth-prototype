-- Ethereum Rinkeby

--- Quick Analyze

ANALYZE ethereum_rinkeby.blocks;
ANALYZE ethereum_rinkeby.transactions;

--- Create Primary key and Foreign key
ALTER TABLE ethereum_rinkeby.blocks ADD CONSTRAINT hash_pk PRIMARY KEY (hash);
ALTER TABLE ethereum_rinkeby.transactions ADD CONSTRAINT txid_pk PRIMARY KEY (txid);
ALTER TABLE ethereum_rinkeby.transactions ADD CONSTRAINT block_fk FOREIGN KEY(block) REFERENCES ethereum_rinkeby.blocks(hash);

--- Create Index
---- We use B-Tree indexing because later we want to do more insert of new transactions and it is supposedly faster 
CREATE INDEX index_toaddress ON ethereum_rinkeby.transactions using btree (toaddress);
