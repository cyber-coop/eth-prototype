-- Ethereum Mainnet

--- Quick Analysis

ANALYZE ethereum_mainnet.blocks;
ANALYZE ethereum_mainnet.transactions;
ANALYZE ethereum_mainnet.ommers;

--- Create Primary and Foreign keys
ALTER TABLE ethereum_mainnet.blocks ADD CONSTRAINT hash_pk PRIMARY KEY (hash);
ALTER TABLE ethereum_mainnet.transactions ADD CONSTRAINT block_fk FOREIGN KEY (block) REFERENCES ethereum_mainnet.blocks (hash);
ALTER TABLE ethereum_mainnet.ommers ADD CONSTRAINT phash_pk PRIMARY KEY (hash);
ALTER TABLE ethereum_mainnet.ommers ADD CONSTRAINT ommersblock_fk FOREIGN KEY (canonical_hash) REFERENCES ethereum_mainnet.blocks (hash);

--- Create Index
---- We use B-Tree indexing because we want to do more inserts of new transactions later and it is supposedly faster 
CREATE INDEX i_blocknumber ON ethereum_mainnet.blocks using btree (number);
CREATE INDEX i_txid ON ethereum_mainnet.transactions using btree (txid);
CREATE INDEX i_txid ON ethereum_mainnet.transactions using btree (block);
CREATE INDEX i_ommerphash ON ethereum_mainnet.ommers using btree (canonical_hash);