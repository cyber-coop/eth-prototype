-- Ethereum Ropsten

--- Quick Analysis

ANALYZE ethereum_ropsten.blocks;
ANALYZE ethereum_ropsten.transactions;
ANALYZE ethereum_ropsten.ommers;

-- Ropsten have duplicates that we need to remove...
CREATE TABLE ethereum_ropsten.tx_dup AS SELECT s.txid, s.block FROM ethereum_ropsten.transactions s JOIN (SELECT txid, count(*) FROM ethereum_ropsten.transactions GROUP BY txid HAVING COUNT(*) > 1) d ON s.txid = d.txid ORDER BY s.txid;
DELETE FROM ethereum_ropsten.transactions t USING (SELECT DISTINCT ON (txid) * FROM ethereum_ropsten.tx_dup) dup WHERE t.txid = dup.txid AND t.block = dup.block;

--- Create Primary and Foreign keys
ALTER TABLE ethereum_ropsten.blocks ADD CONSTRAINT hash_pk PRIMARY KEY (hash);
ALTER TABLE ethereum_ropsten.blocks ADD CONSTRAINT number_fk FOREIGN KEY (number);
ALTER TABLE ethereum_ropsten.transactions ADD CONSTRAINT txid_pk PRIMARY KEY (txid);
ALTER TABLE ethereum_ropsten.transactions ADD CONSTRAINT block_fk FOREIGN KEY (block) REFERENCES ethereum_ropsten.blocks (hash);
ALTER TABLE ethereum_ropsten.ommers ADD CONSTRAINT phash_pk PRIMARY KEY (hash);
ALTER TABLE ethereum_ropsten.ommers ADD CONSTRAINT ommersblock_fk FOREIGN KEY (canonical_hash) REFERENCES ethereum_ropsten.blocks (hash);

--- Create Index
---- We use B-Tree indexing because we want to do more inserts of new transactions later and it is supposedly faster 
CREATE INDEX i_blocknumber ON ethereum_ropsten.blocks using btree (number);
CREATE INDEX i_txblock ON ethereum_ropsten.transactions using btree (block);
CREATE INDEX i_ommerphash ON ethereum_ropsten.ommers using btree (canonical_hash);