-- Ethereum Ropsten

--- Quick Analyze

ANALYZE ethereum_ropsten.blocks;
ANALYZE ethereum_ropsten.transactions;

--- Create Primary key and Foreign key
ALTER TABLE ethereum_ropsten.blocks ADD CONSTRAINT hash_pk PRIMARY KEY (hash);
ALTER TABLE ethereum_ropsten.transactions ADD CONSTRAINT txid_pk PRIMARY KEY (txid);
ALTER TABLE ethereum_ropsten.transactions ADD CONSTRAINT block_fk FOREIGN KEY(block) REFERENCES ethereum_ropsten.blocks(hash);

--- Create Index
---- We use B-Tree indexing because later we want to do more insert of new transactions and it is supposedly faster 
CREATE INDEX index_toaddress ON ethereum_ropsten.transactions using btree (toaddress);
