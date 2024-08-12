-- Ethereum Sepolia

--- Quick Analyze

ANALYZE ethereum_sepolia.blocks;
ANALYZE ethereum_sepolia.transactions;
ANALYZE ethereum_sepolia.ommers;

--- Create Primary key and Foreign key
ALTER TABLE ethereum_sepolia.blocks ADD CONSTRAINT hash_pk PRIMARY KEY (hash);
ALTER TABLE ethereum_sepolia.transactions ADD CONSTRAINT block_fk FOREIGN KEY(block) REFERENCES ethereum_sepolia.blocks(hash);
ALTER TABLE ethereum_sepolia.ommers ADD CONSTRAINT phash_pk PRIMARY KEY (hash);
ALTER TABLE ethereum_sepolia.ommers ADD CONSTRAINT ommersblock_fk FOREIGN KEY (canonical_hash) REFERENCES ethereum_sepolia.blocks (hash);

--- Create Index
---- We use B-Tree indexing because later we want to do more insert of new transactions and it is supposedly faster 
CREATE INDEX i_toaddress ON ethereum_sepolia.transactions using btree (toaddress);
CREATE INDEX i_blocknumber ON ethereum_sepolia.blocks using btree (number);
CREATE INDEX i_txid ON ethereum_sepolia.transactions using btree (txid);
CREATE INDEX i_txid ON ethereum_sepolia.transactions using btree (block);
CREATE INDEX i_ommerphash ON ethereum_sepolia.ommers using btree (canonical_hash);