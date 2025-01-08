-- Ethereum Holesky

--- Quick Analyze

ANALYZE ethereum_holesky.blocks;
ANALYZE ethereum_holesky.transactions;
ANALYZE ethereum_holesky.ommers;

--- Create Primary key and Foreign key
ALTER TABLE ethereum_holesky.blocks ADD CONSTRAINT hash_pk PRIMARY KEY (hash);
ALTER TABLE ethereum_holesky.transactions ADD CONSTRAINT block_fk FOREIGN KEY(block) REFERENCES ethereum_holesky.blocks(hash);
ALTER TABLE ethereum_holesky.ommers ADD CONSTRAINT phash_pk PRIMARY KEY (hash);
ALTER TABLE ethereum_holesky.ommers ADD CONSTRAINT ommersblock_fk FOREIGN KEY (canonical_hash) REFERENCES ethereum_holesky.blocks (hash);

--- Create Index
---- We use B-Tree indexing because later we want to do more insert of new transactions and it is supposedly faster 
CREATE INDEX i_toaddress ON ethereum_holesky.transactions using btree (toaddress);
CREATE INDEX i_blocknumber ON ethereum_holesky.blocks using btree (number);
CREATE INDEX i_txid ON ethereum_holesky.transactions using btree (txid);
CREATE INDEX i_block ON ethereum_holesky.transactions using btree (block);
CREATE INDEX i_ommerphash ON ethereum_holesky.ommers using btree (canonical_hash);