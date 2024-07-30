-- Ethereum Ropsten

--- Quick Analysis

ANALYZE ethereum_ropsten.blocks;
ANALYZE ethereum_ropsten.transactions;
ANALYZE ethereum_ropsten.ommers;

--- Create Primary and Foreign keys
ALTER TABLE ethereum_ropsten.blocks ADD CONSTRAINT hash_pk PRIMARY KEY (hash);
ALTER TABLE ethereum_ropsten.transactions ADD CONSTRAINT block_fk FOREIGN KEY (block) REFERENCES ethereum_ropsten.blocks (hash);
ALTER TABLE ethereum_ropsten.ommers ADD CONSTRAINT phash_pk PRIMARY KEY (hash);
ALTER TABLE ethereum_ropsten.ommers ADD CONSTRAINT ommersblock_fk FOREIGN KEY (canonical_hash) REFERENCES ethereum_ropsten.blocks (hash);

--- Create Index
---- We use B-Tree indexing because we want to do more inserts of new transactions later and it is supposedly faster 
CREATE INDEX i_blocknumber ON ethereum_ropsten.blocks using btree (number);
CREATE INDEX i_txid ON ethereum_ropsten.transactions using btree (txid);
CREATE INDEX i_txid ON ethereum_ropsten.transactions using btree (block);
CREATE INDEX i_ommerphash ON ethereum_ropsten.ommers using btree (canonical_hash);