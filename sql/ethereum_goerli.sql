-- Ethereum Goerli

--- Quick Analyze

ANALYZE ethereum_goerli.blocks;
ANALYZE ethereum_goerli.transactions;
ANALYZE ethereum_goerli.ommers;

--- Create Primary key and Foreign key
ALTER TABLE ethereum_goerli.blocks ADD CONSTRAINT hash_pk PRIMARY KEY (hash);
ALTER TABLE ethereum_goerli.transactions ADD CONSTRAINT block_fk FOREIGN KEY(block) REFERENCES ethereum_goerli.blocks(hash);
ALTER TABLE ethereum_goerli.ommers ADD CONSTRAINT phash_pk PRIMARY KEY (hash);
ALTER TABLE ethereum_goerli.ommers ADD CONSTRAINT ommersblock_fk FOREIGN KEY (canonical_hash) REFERENCES ethereum_goerli.blocks (hash);

--- Create Index
---- We use B-Tree indexing because later we want to do more insert of new transactions and it is supposedly faster 
CREATE INDEX i_toaddress ON ethereum_goerli.transactions using btree (toaddress);
CREATE INDEX i_blocknumber ON ethereum_goerli.blocks using btree (number);
CREATE INDEX i_txid ON ethereum_goerli.transactions using btree (txid);
CREATE INDEX i_block ON ethereum_goerli.transactions using btree (block);
CREATE INDEX i_ommerphash ON ethereum_goerli.ommers using btree (canonical_hash);