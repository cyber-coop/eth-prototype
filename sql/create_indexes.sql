--- Quick Analysis

ANALYZE {schema}.blocks;
ANALYZE {schema}.transactions;
ANALYZE {schema}.ommers;

--- Create Primary and Foreign keys
ALTER TABLE {schema}.blocks ADD CONSTRAINT hash_pk PRIMARY KEY (hash);
ALTER TABLE {schema}.transactions ADD CONSTRAINT block_fk FOREIGN KEY (block) REFERENCES {schema}.blocks (hash);
ALTER TABLE {schema}.ommers ADD CONSTRAINT phash_pk PRIMARY KEY (hash);
ALTER TABLE {schema}.ommers ADD CONSTRAINT ommersblock_fk FOREIGN KEY (canonical_hash) REFERENCES {schema}.blocks (hash);

--- Create Index
---- We use B-Tree indexing because we want to do more inserts of new transactions later and it is supposedly faster
CREATE INDEX i_toaddress ON {schema}.transactions using btree (toaddress);
CREATE INDEX i_fromaddress ON {schema}.transactions using btree (fromaddress);
CREATE INDEX i_blocknumber ON {schema}.blocks using btree (number);
CREATE INDEX i_txid ON {schema}.transactions using btree (txid);
CREATE INDEX i_block ON {schema}.transactions using btree (block);
CREATE INDEX i_ommerphash ON {schema}.ommers using btree (canonical_hash);
