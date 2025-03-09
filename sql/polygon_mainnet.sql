-- Polygon Mainnet

--- Quick Analysis

ANALYZE polygon_mainnet.blocks;
ANALYZE polygon_mainnet.transactions;
ANALYZE polygon_mainnet.ommers;

--- Create Primary and Foreign keys
ALTER TABLE polygon_mainnet.blocks ADD CONSTRAINT hash_pk PRIMARY KEY (hash);
ALTER TABLE polygon_mainnet.transactions ADD CONSTRAINT block_fk FOREIGN KEY (block) REFERENCES polygon_mainnet.blocks (hash);
ALTER TABLE polygon_mainnet.ommers ADD CONSTRAINT phash_pk PRIMARY KEY (hash);
ALTER TABLE polygon_mainnet.ommers ADD CONSTRAINT ommersblock_fk FOREIGN KEY (canonical_hash) REFERENCES polygon_mainnet.blocks (hash);

--- Create Index
---- We use B-Tree indexing because we want to do more inserts of new transactions later and it is supposedly faster 
CREATE INDEX i_toaddress ON polygon_mainnet.transactions using btree (toaddress);
CREATE INDEX i_blocknumber ON polygon_mainnet.blocks using btree (number);
CREATE INDEX i_txid ON polygon_mainnet.transactions using btree (txid);
CREATE INDEX i_block ON polygon_mainnet.transactions using btree (block);
CREATE INDEX i_ommerphash ON polygon_mainnet.ommers using btree (canonical_hash);