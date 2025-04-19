-- Binance Mainnet

--- Quick Analysis

ANALYZE binance_mainnet.blocks;
ANALYZE binance_mainnet.transactions;
ANALYZE binance_mainnet.ommers;

--- Create Primary and Foreign keys
ALTER TABLE binance_mainnet.blocks ADD CONSTRAINT hash_pk PRIMARY KEY (hash);
ALTER TABLE binance_mainnet.transactions ADD CONSTRAINT block_fk FOREIGN KEY (block) REFERENCES binance_mainnet.blocks (hash);
ALTER TABLE binance_mainnet.ommers ADD CONSTRAINT phash_pk PRIMARY KEY (hash);
ALTER TABLE binance_mainnet.ommers ADD CONSTRAINT ommersblock_fk FOREIGN KEY (canonical_hash) REFERENCES binance_mainnet.blocks (hash);

--- Create Index
---- We use B-Tree indexing because we want to do more inserts of new transactions later and it is supposedly faster 
CREATE INDEX i_toaddress ON binance_mainnet.transactions using btree (toaddress);
CREATE INDEX i_blocknumber ON binance_mainnet.blocks using btree (number);
CREATE INDEX i_txid ON binance_mainnet.transactions using btree (txid);
CREATE INDEX i_block ON binance_mainnet.transactions using btree (block);
CREATE INDEX i_ommerphash ON binance_mainnet.ommers using btree (canonical_hash);