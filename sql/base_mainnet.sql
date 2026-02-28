-- Base Mainnet

--- Quick Analysis

ANALYZE base_mainnet.blocks;
ANALYZE base_mainnet.transactions;
ANALYZE base_mainnet.ommers;

--- Create Primary and Foreign keys
ALTER TABLE base_mainnet.blocks ADD CONSTRAINT hash_pk PRIMARY KEY (hash);
ALTER TABLE base_mainnet.transactions ADD CONSTRAINT block_fk FOREIGN KEY (block) REFERENCES base_mainnet.blocks (hash);
ALTER TABLE base_mainnet.ommers ADD CONSTRAINT phash_pk PRIMARY KEY (hash);
ALTER TABLE base_mainnet.ommers ADD CONSTRAINT ommersblock_fk FOREIGN KEY (canonical_hash) REFERENCES base_mainnet.blocks (hash);

--- Create Index
---- We use B-Tree indexing because we want to do more inserts of new transactions later and it is supposedly faster 
CREATE INDEX i_toaddress ON base_mainnet.transactions using btree (toaddress);
CREATE INDEX i_fromaddress ON base_mainnet.transactions using btree (fromaddress);
CREATE INDEX i_blocknumber ON base_mainnet.blocks using btree (number);
CREATE INDEX i_txid ON base_mainnet.transactions using btree (txid);
CREATE INDEX i_block ON base_mainnet.transactions using btree (block);
CREATE INDEX i_ommerphash ON base_mainnet.ommers using btree (canonical_hash);