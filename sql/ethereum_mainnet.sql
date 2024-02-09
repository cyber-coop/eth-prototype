-- Ethereum Mainnet

--- Quick Analyze

ANALYZE ethereum_mainnet.blocks;
ANALYZE ethereum_mainnet.transactions;

--- Create Primary key and Foreign key
ALTER TABLE ethereum_mainnet.blocks ADD CONSTRAINT hash_pk PRIMARY KEY (hash);
ALTER TABLE ethereum_mainnet.transactions ADD CONSTRAINT txid_pk PRIMARY KEY (txid);
ALTER TABLE ethereum_mainnet.transactions ADD CONSTRAINT block_fk FOREIGN KEY(block) REFERENCES ethereum_mainnet.blocks(hash);

--- Create Index
---- We use B-Tree indexing because later we want to do more insert of new transactions and it is supposedly faster 
CREATE INDEX index_toaddress ON ethereum_mainnet.transactions using btree (toaddress);
