-- Ethereum Goerli

--- Quick Analyze

ANALYZE ethereum_goerli.blocks;
ANALYZE ethereum_goerli.transactions;

--- Create Primary key and Foreign key
ALTER TABLE ethereum_goerli.blocks ADD CONSTRAINT hash_pk PRIMARY KEY (hash);
ALTER TABLE ethereum_goerli.transactions ADD CONSTRAINT block_fk FOREIGN KEY(block) REFERENCES ethereum_goerli.blocks(hash);

--- Create Index
---- We use B-Tree indexing because later we want to do more insert of new transactions and it is supposedly faster 
CREATE INDEX index_toaddress ON ethereum_goerli.transactions using btree (toaddress);
