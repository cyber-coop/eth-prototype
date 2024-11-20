-- Ethereum Rinkeby

--- Quick Analysis

ANALYZE ethereum_rinkeby.blocks;
ANALYZE ethereum_rinkeby.transactions;
ANALYZE ethereum_rinkeby.ommers;

--- Create Primary and Foreign keys
ALTER TABLE ethereum_rinkeby.blocks ADD CONSTRAINT hash_pk PRIMARY KEY (hash);
ALTER TABLE ethereum_rinkeby.transactions ADD CONSTRAINT block_fk FOREIGN KEY (block) REFERENCES ethereum_rinkeby.blocks (hash);
ALTER TABLE ethereum_rinkeby.ommers ADD CONSTRAINT phash_pk PRIMARY KEY (hash);
ALTER TABLE ethereum_rinkeby.ommers ADD CONSTRAINT ommersblock_fk FOREIGN KEY (canonical_hash) REFERENCES ethereum_rinkeby.blocks (hash);

--- Create Index
---- We use B-Tree indexing because we want to do more inserts of new transactions later and it is supposedly faster 
CREATE INDEX i_toaddress ON ethereum_rinkeby.transactions using btree (toaddress);
CREATE INDEX i_blocknumber ON ethereum_rinkeby.blocks using btree (number);
CREATE INDEX i_txid ON ethereum_rinkeby.transactions using btree (txid);
CREATE INDEX i_block ON ethereum_rinkeby.transactions using btree (block);
CREATE INDEX i_ommerphash ON ethereum_rinkeby.ommers using btree (canonical_hash);