-- Ethereum Rinkeby

--- Quick Analyze

ANALYZE test.blocks;
ANALYZE test.transactions;
ANALYZE test.ommers;

--- Create Primary and Foreign keys
ALTER TABLE test.blocks ADD CONSTRAINT hash_pk PRIMARY KEY (hash);
ALTER TABLE test.transactions ADD CONSTRAINT block_fk FOREIGN KEY (block) REFERENCES test.blocks (hash);
ALTER TABLE test.ommers ADD CONSTRAINT phash_pk PRIMARY KEY (hash);
ALTER TABLE test.ommers ADD CONSTRAINT ommersblock_fk FOREIGN KEY (canonical_hash) REFERENCES test.blocks (hash);

--- Create Index
---- We use B-Tree indexing because we want to do more inserts of new transactions later and it is supposedly faster 
CREATE INDEX i_blocknumber ON test.blocks using btree (number);
CREATE INDEX i_txid ON test.transactions using btree (txid);
CREATE INDEX i_ommerphash ON test.ommers using btree (canonical_hash);