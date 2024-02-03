-- Ethereum Sepolia

--- Quick Analyze

ANALYZE ethereum_sepolia.blocks;
ANALYZE ethereum_sepolia.transactions;

--- Create Primary key and Foreign key
ALTER TABLE ethereum_sepolia.blocks ADD CONSTRAINT hash_pk PRIMARY KEY (hash);
ALTER TABLE ethereum_sepolia.transactions ADD CONSTRAINT txid_pk PRIMARY KEY (txid);
ALTER TABLE ethereum_sepolia.transactions ADD CONSTRAINT block_fk FOREIGN KEY(block) REFERENCES ethereum_sepolia.blocks(hash);

--- Create Index
---- We use B-Tree indexing because later we want to do more insert of new transactions and it is supposedly faster 
CREATE INDEX index_toaddress ON ethereum_sepolia.transactions using btree (toaddress);
