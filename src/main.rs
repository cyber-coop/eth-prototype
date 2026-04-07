use secp256k1::{rand, SecretKey};
use std::collections::VecDeque;
use std::env;
use std::error;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;
use tokio::task::JoinSet;

use eth_prototype::connection::Connection;
use eth_prototype::eth;
use eth_prototype::types::{Block, Receipt, Transaction, Withdrawal};
use eth_prototype::{configs, database, message, networks, types, utils};

#[macro_use]
extern crate log;

// max value seems to be 1024 (https://github.com/ethereum/go-ethereum/blob/master/eth/protocols/eth/handler.go#L40)
const BLOCK_NUM: usize = 1024;

fn main() {
    // Init log
    env_logger::init();

    info!("Ethereum mini node in rust");

    // Read cli args for network value
    let network_arg: String = env::args()
        .nth(1)
        .expect("expecting a network (ethereum_ropsten, ethereum_rinkeby, ethereum_goerli, ethereum_sepolia, ethereum_holesky, ethereum_hoodi, ethereum_mainnet or binance_mainnet).");
    let network = networks::Network::find(network_arg.as_str()).unwrap();

    // Load config values from the config file
    let config = configs::read_config();
    let mut current_hash: Vec<u8> = vec![];
    let mut reverse = true; // when we init syncing we go from the tip to the genesis block

    /******************
     *
     *  Connect to postgres
     *
     ******************/
    let mut postgres_client: postgres::Client;
    let database_params: String = format!(
        "host={} user={} password={} dbname={}",
        config.database.host,
        config.database.user,
        config.database.password,
        config.database.dbname
    );
    loop {
        let result = postgres::Client::connect(&database_params, postgres::NoTls);

        match result {
            Ok(client) => {
                postgres_client = client;
                break;
            }
            Err(_) => {
                warn!("Fail to connect to database. Retrying in 20 seconds...");
                thread::sleep(Duration::from_secs(20));
            }
        }
    }
    info!("Connected to database");

    // create the tables if they don't exist
    database::create_tables(&network_arg, &mut postgres_client);

    // get the hash of the next block in the chain going reverse
    // we should check if we are at the genesis block and that the parenthash is 0x0000......
    let result = postgres_client.query(format!("SELECT parent_hash FROM {0}.blocks WHERE number = (SELECT MIN(number) FROM {0}.blocks);", network_arg).as_str(), &[]).unwrap();

    if result.len() > 0 {
        let row = &result[0];
        let hash = row.try_get(0);
        match hash {
            Ok(h) => {
                current_hash = h;
            }
            Err(_) => {
                error!("Fail to get hash of the minimum block");
            }
        }

        if current_hash
            == hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
        {
            info!("We are already synced completly!");

            // We get the highest block to keep indexing the new ones
            let result = postgres_client.query(format!("SELECT hash, number FROM {0}.blocks WHERE number = (SELECT MAX(number) FROM {0}.blocks);", network_arg).as_str(), &[]).unwrap();

            let row = &result[0];
            let hash = row.try_get(0);

            match hash {
                Ok(h) => {
                    current_hash = h;
                    reverse = false; // The initial sync has been done. We keep indexing the new incoming blocks now.
                }
                Err(_) => {
                    error!("Fail to get hash of the max block");
                }
            }

            info!("We now save the new incoming blocks");
        }

        info!("We are starting at hash {}", hex::encode(&current_hash));
    }

    /********************
     *
     *  Start database thread
     *
     ********************/

    // Create a queue with a maximum of 102400 blocks (100 * 1024 = 102400 blocks). We query blocks by batch of 1024 blocks.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<
        Vec<(
            Block,
            Vec<Transaction>,
            Vec<Block>,
            Vec<Withdrawal>,
            Vec<Receipt>,
        )>,
    >(100);

    let db_params = database_params.clone();
    let database_handle = thread::spawn(move || {
        info!("Starting database thread");

        // Connect to database
        let mut postgres_client = postgres::Client::connect(&db_params, postgres::NoTls).unwrap();

        // while recv save blocks in database
        // Out-of-order batches are held in a cache keyed by their first block
        // number until the missing predecessor arrives.
        type Batch = Vec<(
            Block,
            Vec<Transaction>,
            Vec<Block>,
            Vec<Withdrawal>,
            Vec<Receipt>,
        )>;
        let mut last_block_number: Option<u32> = None;
        let mut cache: std::collections::BTreeMap<u32, Batch> = std::collections::BTreeMap::new();

        'recv: loop {
            let blocks: Batch = rx.blocking_recv().unwrap();

            let first_number = blocks.first().unwrap().0.number;
            let is_contiguous = last_block_number
                .map(|last| last.abs_diff(first_number) == 1)
                .unwrap_or(true);

            if !is_contiguous {
                info!(
                    "Caching out-of-order batch starting at block {} (last saved: {:?})",
                    first_number, last_block_number
                );
                cache.insert(first_number, blocks);
                continue;
            }

            // Save this batch then drain any cached batches that are now contiguous.
            let mut to_save: Option<Batch> = Some(blocks);
            while let Some(batch) = to_save {
                database::save_blocks(&batch, &network_arg, &mut postgres_client);
                let last = batch.last().unwrap().0.number;
                last_block_number = Some(last);

                if network.genesis_hash.to_vec() == batch.last().unwrap().0.hash.to_vec() {
                    info!("We are synced ! We are creating the indexes on the tables... This will take a while.");
                    utils::open_exec_sql_file(&network_arg, &mut postgres_client);
                    break 'recv;
                }

                // Look for a cached batch whose first block is adjacent to `last`.
                to_save = last
                    .checked_sub(1)
                    .and_then(|k| cache.remove(&k))
                    .or_else(|| cache.remove(&(last + 1)));
            }
        }

        info!("Closing thread!");
    });

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut connections: Vec<Connection> = vec![];
        let mut tasks = JoinSet::new();

        for peer in config.peers {
            // match run(
            //     peer,
            //     network,
            //     &database_params,
            //     &mut current_hash,
            //     reverse,
            //     &tx,
            // )
            // .await
            // {
            //     Ok(()) => {
            //         // We are done
            //         break;
            //     }
            //     Err(_) => {
            //         // next peer
            //         continue;
            //     }
            // };

            tasks.spawn(async move { Connection::connect(peer, network).await });
        }

        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(connection)) => {
                    info!("Connection established");
                    connections.push(connection);
                }
                Ok(Err(e)) => warn!("Failed to connect to peer: {}", e),
                Err(e) => warn!("Task panicked: {:?}", e),
            }
        }

        info!("Tried all peers");

        // Find the best hash among all the connections
        let mut counts: std::collections::HashMap<Vec<u8>, usize> =
            std::collections::HashMap::new();
        for conn in connections.iter() {
            *counts.entry(conn.latest_blockhash().clone()).or_insert(0) += 1;
        }
        if let Some((best_hash, count)) = counts.into_iter().max_by_key(|(_, c)| *c) {
            info!(
                "Most common blockhash ({} peers): {}",
                count,
                hex::encode(&best_hash)
            );

            // If we are already synced and we are saving new blocks, lets verify that we don't have the already highest block from this peer.
            // Sometimes peers are stuck and don't have new blocks. We need to disconnect from those.
            if !reverse {
                // We need to go one block back
                let (pg_client, pg_conn) =
                    tokio_postgres::connect(&database_params, tokio_postgres::NoTls)
                        .await
                        .expect("to connect to database");
                tokio::spawn(async move {
                    if let Err(e) = pg_conn.await {
                        warn!("postgres connection error: {}", e);
                    }
                });
                let result = pg_client
                    .query(
                        &format!(
                            "SELECT * FROM {0}.blocks WHERE hash = '\\x{1}';",
                            network.to_string(),
                            hex::encode(&best_hash)
                        ),
                        &[],
                    )
                    .await
                    .unwrap();

                if result.len() > 0 {
                    warn!("We already have their latets block");
                }
            }

            // If we don't have blocks in the database we use the best one
            if current_hash.len() == 0 {
                current_hash = best_hash;
            }
        }

        let mut pool: VecDeque<Connection> = connections.into_iter().collect();

        if reverse {
            // Reverse sync (tip → genesis): pipeline header requests across
            // connections while bodies/receipts are fetched concurrently.
            // Tasks return Ok(conn) on success or Err(block_headers) so the
            // batch can be retried on a different connection.
            let done = Arc::new(AtomicBool::new(false));
            let mut body_tasks: JoinSet<Result<Connection, Vec<Block>>> = JoinSet::new();
            let mut retry_queue: VecDeque<Vec<Block>> = VecDeque::new();

            'outer: loop {
                if done.load(Ordering::Relaxed) {
                    break;
                }

                // Get an available connection; if the pool is empty wait for a
                // body task to finish and reclaim its connection (or a retry batch).
                let mut conn = loop {
                    if let Some(c) = pool.pop_front() {
                        break c;
                    }
                    match body_tasks.join_next().await {
                        Some(Ok(Ok(c))) => pool.push_back(c),
                        Some(Ok(Err(headers))) => {
                            warn!("Task failed, re-queuing batch of {} headers", headers.len());
                            retry_queue.push_back(headers);
                        }
                        Some(Err(e)) => warn!("Body task panicked: {:?}", e),
                        None => {
                            warn!("No connections left");
                            break 'outer;
                        }
                    }
                };

                let block_headers = if let Some(headers) = retry_queue.pop_front() {
                    info!("Retrying batch of {} headers on new connection", headers.len());
                    headers
                } else {
                    info!("Sending GetBlockHeaders (starting {})", hex::encode(&current_hash));
                    let get_headers =
                        eth::create_get_block_headers_message(&current_hash, BLOCK_NUM, 0, true);
                    if conn.tx_write.send(get_headers).await.is_err() {
                        warn!("Connection lost, dropping");
                        continue;
                    }

                    let headers_body = loop {
                        match conn.rx_tcp.recv().await {
                            Some(body) if body[0].saturating_sub(16) == 4 => break Some(body),
                            Some(_) => continue,
                            None => break None,
                        }
                    };
                    let headers_body = match headers_body {
                        Some(b) => b,
                        None => continue,
                    };

                    let headers = eth::parse_block_headers(headers_body[1..].to_vec());
                    if headers.is_empty() {
                        warn!("No block headers received");
                        pool.push_back(conn);
                        break;
                    }

                    current_hash = headers.last().unwrap().parent_hash.to_vec();
                    headers
                };

                let tx_clone = tx.clone();
                let done_clone = done.clone();
                body_tasks.spawn(async move {
                    let mut conn = conn;
                    let hashes: Vec<Vec<u8>> =
                        block_headers.iter().map(|b| b.hash.clone()).collect();
                    let eth_version = conn.eth_protocol_version;

                    let mut transactions: Vec<(Vec<Transaction>, Vec<Block>, Vec<Withdrawal>)> =
                        vec![];
                    while transactions.len() < hashes.len() {
                        info!(
                            "Sending GetBlockBodies ({}/{})",
                            transactions.len(),
                            hashes.len()
                        );
                        let get_bodies = eth::create_get_block_bodies_message(
                            &hashes[transactions.len()..].to_vec(),
                        );
                        if conn.tx_write.send(get_bodies).await.is_err() {
                            warn!("Connection lost during GetBlockBodies, will retry batch");
                            return Err(block_headers);
                        }
                        loop {
                            match conn.rx_tcp.recv().await {
                                Some(body) if body[0].saturating_sub(16) == 6 => {
                                    transactions
                                        .extend(eth::parse_block_bodies(body[1..].to_vec()));
                                    break;
                                }
                                Some(_) => continue,
                                None => {
                                    warn!(
                                        "Connection closed during GetBlockBodies, will retry batch"
                                    );
                                    return Err(block_headers);
                                }
                            }
                        }
                    }

                    let mut receipts: Vec<Vec<Receipt>> = vec![];
                    if eth_version == 69 {
                        while receipts.len() < hashes.len() {
                            info!(
                                "Sending GetReceipts ({}/{})",
                                receipts.len(),
                                hashes.len()
                            );
                            let get_receipts = eth::create_get_receipts_message(
                                &hashes[receipts.len()..].to_vec(),
                            );
                            if conn.tx_write.send(get_receipts).await.is_err() {
                                warn!("Connection lost during GetReceipts, will retry batch");
                                return Err(block_headers);
                            }
                            loop {
                                match conn.rx_tcp.recv().await {
                                    Some(body) if body[0].saturating_sub(16) == 16 => {
                                        receipts.extend(eth::parse_receipts(body[1..].to_vec()));
                                        break;
                                    }
                                    Some(_) => continue,
                                    None => {
                                        warn!("Connection closed during GetReceipts, will retry batch");
                                        return Err(block_headers);
                                    }
                                }
                            }
                        }
                    }

                    let blocks: Vec<_> = block_headers
                        .iter()
                        .enumerate()
                        .map(|(i, header)| {
                            let (txs, ommers, withdrawals) = transactions[i].clone();
                            let block_receipts =
                                if eth_version == 69 { receipts[i].clone() } else { vec![] };
                            (header.clone(), txs, ommers, withdrawals, block_receipts)
                        })
                        .collect();

                    let current_height = blocks.last().unwrap().0.number;
                    info!("Blocks n° {}", current_height);

                    if tx_clone.send(blocks).await.is_err() {
                        warn!("DB channel closed");
                        return Err(block_headers);
                    }

                    if current_height == 0 {
                        info!("Data fully synced");
                        done_clone.store(true, Ordering::Relaxed);
                        return Ok(conn);
                    }

                    Ok(conn)
                });
            }

            while body_tasks.join_next().await.is_some() {}
        } else {
            // Forward sync (tracking the tip): sequential, one batch at a time,
            // rotating through peers. No parallelism needed since new blocks
            // arrive slowly (~12s apart).
            let mut retry_headers: Option<Vec<Block>> = None;

            'outer: loop {
                let mut conn = match pool.pop_front() {
                    Some(c) => c,
                    None => {
                        warn!("No connections left");
                        break;
                    }
                };

                let block_headers = if let Some(headers) = retry_headers.take() {
                    info!("Retrying batch of {} headers on new connection", headers.len());
                    headers
                } else {
                    info!("Sending GetBlockHeaders (starting {})", hex::encode(&current_hash));
                    let get_headers =
                        eth::create_get_block_headers_message(&current_hash, BLOCK_NUM, 0, false);
                    if conn.tx_write.send(get_headers).await.is_err() {
                        warn!("Connection lost, dropping");
                        continue;
                    }

                    let headers_body = loop {
                        match conn.rx_tcp.recv().await {
                            Some(body) if body[0].saturating_sub(16) == 4 => break Some(body),
                            Some(_) => continue,
                            None => break None,
                        }
                    };
                    let headers_body = match headers_body {
                        Some(b) => b,
                        None => continue,
                    };

                    let headers = eth::parse_block_headers(headers_body[1..].to_vec());
                    if headers.is_empty() {
                        warn!("No new block headers, waiting...");
                        pool.push_back(conn);
                        tokio::time::sleep(Duration::from_secs(15)).await;
                        continue;
                    }

                    // Skip the first header: it's current_hash, which is
                    // already in the DB. The peer returns it inclusive.
                    let headers: Vec<Block> = headers.into_iter().skip(1).collect();
                    if headers.is_empty() {
                        warn!("No new block headers, waiting...");
                        pool.push_back(conn);
                        tokio::time::sleep(Duration::from_secs(15)).await;
                        continue;
                    }

                    current_hash = headers.last().unwrap().hash.to_vec();
                    headers
                };

                let hashes: Vec<Vec<u8>> =
                    block_headers.iter().map(|b| b.hash.clone()).collect();
                let eth_version = conn.eth_protocol_version;

                let mut transactions: Vec<(Vec<Transaction>, Vec<Block>, Vec<Withdrawal>)> =
                    vec![];
                while transactions.len() < hashes.len() {
                    info!(
                        "Sending GetBlockBodies ({}/{})",
                        transactions.len(),
                        hashes.len()
                    );
                    let get_bodies = eth::create_get_block_bodies_message(
                        &hashes[transactions.len()..].to_vec(),
                    );
                    if conn.tx_write.send(get_bodies).await.is_err() {
                        warn!("Connection lost during GetBlockBodies, will retry batch");
                        retry_headers = Some(block_headers);
                        continue 'outer;
                    }
                    loop {
                        match conn.rx_tcp.recv().await {
                            Some(body) if body[0].saturating_sub(16) == 6 => {
                                transactions.extend(eth::parse_block_bodies(body[1..].to_vec()));
                                break;
                            }
                            Some(_) => continue,
                            None => {
                                warn!("Connection closed during GetBlockBodies, will retry batch");
                                retry_headers = Some(block_headers);
                                continue 'outer;
                            }
                        }
                    }
                }

                let mut receipts: Vec<Vec<Receipt>> = vec![];
                if eth_version == 69 {
                    while receipts.len() < hashes.len() {
                        info!("Sending GetReceipts ({}/{})", receipts.len(), hashes.len());
                        let get_receipts = eth::create_get_receipts_message(
                            &hashes[receipts.len()..].to_vec(),
                        );
                        if conn.tx_write.send(get_receipts).await.is_err() {
                            warn!("Connection lost during GetReceipts, will retry batch");
                            retry_headers = Some(block_headers);
                            continue 'outer;
                        }
                        loop {
                            match conn.rx_tcp.recv().await {
                                Some(body) if body[0].saturating_sub(16) == 16 => {
                                    receipts.extend(eth::parse_receipts(body[1..].to_vec()));
                                    break;
                                }
                                Some(_) => continue,
                                None => {
                                    warn!("Connection closed during GetReceipts, will retry batch");
                                    retry_headers = Some(block_headers);
                                    continue 'outer;
                                }
                            }
                        }
                    }
                }

                let blocks: Vec<_> = block_headers
                    .iter()
                    .enumerate()
                    .map(|(i, header)| {
                        let (txs, ommers, withdrawals) = transactions[i].clone();
                        let block_receipts =
                            if eth_version == 69 { receipts[i].clone() } else { vec![] };
                        (header.clone(), txs, ommers, withdrawals, block_receipts)
                    })
                    .collect();

                let current_height = blocks.last().unwrap().0.number;
                info!("Blocks n° {}", current_height);

                if tx.send(blocks).await.is_err() {
                    warn!("DB channel closed");
                    break;
                }

                pool.push_back(conn);
            }
        }
    });

    // need to wait for database thread to finish
    database_handle.join().unwrap();
}
