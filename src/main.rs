use std::collections::VecDeque;
use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tokio::task::JoinSet;

use eth_prototype::connection::{BLOCK_BODIES_CODE, BLOCK_HEADERS_CODE, Connection, RECEIPTS_CODE};
use eth_prototype::eth;
use eth_prototype::types::{Block, Receipt, Transaction, Withdrawal};
use eth_prototype::{configs, database, networks, utils, verify};

#[macro_use]
extern crate log;

// max value seems to be 1024 (https://github.com/ethereum/go-ethereum/blob/master/eth/protocols/eth/handler.go#L40)
const BLOCK_NUM: usize = 1024;

// Blocks this close to the tip can still be reorged out. The initial reverse
// sync starts this many blocks behind the tip; forward sync catches up later
// and handles reorgs.
const REORG_SAFETY_DEPTH: usize = 64;

// How long forward sync waits for the database thread to save a batch.
const DB_CONFIRM_TIMEOUT: Duration = Duration::from_secs(600);

/// Connects to Postgres, retrying every 20 seconds until it succeeds.
fn connect_with_retry(params: &str) -> postgres::Client {
    loop {
        match postgres::Client::connect(params, postgres::NoTls) {
            Ok(client) => return client,
            Err(e) => {
                warn!(
                    "Fail to connect to database ({}). Retrying in 20 seconds...",
                    e
                );
                thread::sleep(Duration::from_secs(20));
            }
        }
    }
}

type LastConfirmed = std::sync::Mutex<Option<(u32, Vec<u8>)>>;

/// Waits until the database thread has saved block `number` (or later).
/// Returns false on timeout or if the database thread has stopped.
async fn wait_for_db<T>(
    last_confirmed: &LastConfirmed,
    number: u32,
    db_sender: &tokio::sync::mpsc::Sender<T>,
) -> bool {
    let deadline = tokio::time::Instant::now() + DB_CONFIRM_TIMEOUT;
    loop {
        if matches!(*last_confirmed.lock().unwrap(), Some((n, _)) if n >= number) {
            return true;
        }
        if db_sender.is_closed() || tokio::time::Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

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
    let mut current_number: u32 = 0; // only meaningful for forward sync
    let mut reverse = true; // when we init syncing we go from the tip to the genesis block

    /******************
     *
     *  Connect to postgres
     *
     ******************/
    let database_params: String = format!(
        "host={} user={} password={} dbname={}",
        config.database.host,
        config.database.user,
        config.database.password,
        config.database.dbname
    );
    let mut postgres_client = connect_with_retry(&database_params);
    info!("Connected to database");

    // create the tables if they don't exist
    database::create_tables(&network.to_string(), &mut postgres_client);

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
            let number: i32 = row.get(1);

            match hash {
                Ok(h) => {
                    current_hash = h;
                    current_number = number as u32;
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

    // Create a queue with a maximum of 20480 blocks (20 * 1024 = 20480 blocks). We query blocks by batch of 1024 blocks.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<
        Vec<(
            Block,
            Vec<Transaction>,
            Vec<Block>,
            Vec<Withdrawal>,
            Vec<Receipt>,
        )>,
    >(20);

    // Shared between DB thread and forward sync: last block number + hash confirmed saved.
    // Forward sync also resets it when rolling back a re-orged block, so the DB
    // thread knows which batch comes next.
    let last_confirmed: Arc<LastConfirmed> = Arc::new(std::sync::Mutex::new(if reverse {
        None
    } else {
        Some((current_number, current_hash.clone()))
    }));
    let last_confirmed_db = last_confirmed.clone();

    let db_params = database_params.clone();
    let database_handle = thread::spawn(move || {
        info!("Starting database thread");

        // Connect to database
        let mut postgres_client = connect_with_retry(&db_params);

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
        let mut cache: std::collections::BTreeMap<u32, Batch> = std::collections::BTreeMap::new();

        'recv: loop {
            let Some(blocks) = rx.blocking_recv() else {
                // Every sender is gone: the sync loops have stopped.
                break 'recv;
            };

            // Always cache first — never blindly trust whichever batch happens to
            // arrive first. With concurrent body tasks, completion order and dispatch
            // order differ, so the first arrival isn't necessarily the legitimate
            // starting point.
            let first_number = blocks.first().unwrap().0.number;
            cache.insert(first_number, blocks);

            // Drain whatever is now reachable from the current position (the last
            // confirmed block, shared with forward sync). On bootstrap
            // (last_block_number is None) the anchor is the highest key we've seen so
            // far in the cache, since reverse sync dispatches strictly downward from
            // the tip and that key can only ever be reached by the legitimate first batch.
            loop {
                let last_block_number = last_confirmed_db.lock().unwrap().as_ref().map(|(n, _)| *n);
                let batch = match last_block_number {
                    // Reverse sync descends (key = last - 1); forward sync ascends
                    // (key = last + 1) — try both since this thread serves either.
                    Some(last) => last
                        .checked_sub(1)
                        .and_then(|k| cache.remove(&k))
                        .or_else(|| cache.remove(&(last + 1))),
                    None => cache
                        .keys()
                        .next_back()
                        .copied()
                        .and_then(|k| cache.remove(&k)),
                };
                let Some(batch) = batch else { break };

                // Retry transient failures (e.g. Postgres restarting) with backoff.
                // Each attempt is a single transaction, so a failed one leaves nothing behind.
                let mut delay = Duration::from_secs(1);
                loop {
                    match database::save_blocks(&batch, &network_arg, &mut postgres_client) {
                        Ok(()) => break,
                        Err(e) if database::is_permanent_error(e.as_ref()) => {
                            error!(
                                "Cannot save blocks n° {} to {}: {}. Stopping database thread.",
                                batch.first().unwrap().0.number,
                                batch.last().unwrap().0.number,
                                e
                            );
                            break 'recv;
                        }
                        Err(e) => {
                            warn!("Failed to save blocks ({}), retrying in {:?}", e, delay);
                            thread::sleep(delay);
                            delay = (delay * 2).min(Duration::from_secs(60));
                            if postgres_client.is_closed() {
                                postgres_client = connect_with_retry(&db_params);
                            }
                        }
                    }
                }
                let last = batch.last().unwrap().0.number;
                *last_confirmed_db.lock().unwrap() =
                    Some((last, batch.last().unwrap().0.hash.clone()));

                if network.genesis_hash.to_vec() == batch.last().unwrap().0.hash.to_vec() {
                    info!(
                        "We are synced ! We are creating the indexes on the tables... This will take a while."
                    );
                    utils::open_exec_sql_file(&network_arg, &mut postgres_client);
                    break 'recv;
                }
            }
        }

        info!("Closing thread!");
    });

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut connections: Vec<Connection> = vec![];
        let mut tasks = JoinSet::new();

        for peer in config.peers {
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

        let mut start_from_tip = false;

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
                start_from_tip = true;
            }
        }

        // Receipts are only fetched over eth69. Batches are spread across all peers
        // in the pool, so mixing eth68 and eth69 peers would leave holes in the
        // receipts table. If any eth69 peer is available, use only those.
        let eth69_count = connections
            .iter()
            .filter(|c| c.eth_protocol_version == 69)
            .count();
        if eth69_count > 0 {
            if eth69_count < connections.len() {
                info!(
                    "Using only the {} eth69 peers (dropping {} older peers) so every batch has receipts",
                    eth69_count,
                    connections.len() - eth69_count
                );
            }
            connections.retain(|c| c.eth_protocol_version == 69);
        } else if !connections.is_empty() {
            warn!("No eth69 peers available: syncing without receipts");
        }

        let mut pool: VecDeque<Connection> = connections.into_iter().collect();

        // Don't start the initial sync at the tip itself: recent blocks can still be
        // reorged out and reverse sync never revisits them. Start REORG_SAFETY_DEPTH
        // blocks back; forward sync fetches the rest once the initial sync is done.
        if reverse && start_from_tip {
            while let Some(mut conn) = pool.pop_front() {
                let req_id = eth::next_request_id();
                let msg = eth::create_get_block_headers_message(
                    &current_hash,
                    REORG_SAFETY_DEPTH + 1,
                    0,
                    true,
                    req_id,
                );
                let Some(body) = conn.request(msg, BLOCK_HEADERS_CODE, req_id).await else {
                    continue;
                };
                let headers = eth::parse_block_headers(&body);
                if headers.is_empty() {
                    warn!("Peer returned no headers for the tip, trying next peer");
                    continue;
                }
                if let Err(e) = verify::verify_header_chain(
                    &headers,
                    &current_hash,
                    true,
                    REORG_SAFETY_DEPTH + 1,
                ) {
                    warn!("Invalid tip headers from peer, dropping connection: {}", e);
                    continue;
                }
                let start = headers.last().unwrap();
                info!(
                    "Starting initial sync {} blocks behind the tip, at block n° {} ({})",
                    headers.len() - 1,
                    start.number,
                    hex::encode(&start.hash)
                );
                current_hash = start.hash.clone();
                pool.push_front(conn);
                break;
            }
        }

        if reverse {
            // Reverse sync (tip → genesis): pipeline header requests across
            // connections while bodies/receipts are fetched concurrently.
            // Tasks return Ok(conn) on success or Err(block_headers) so the
            // batch can be retried on a different connection.
            let done = Arc::new(AtomicBool::new(false));
            let mut body_tasks: JoinSet<Result<Connection, Vec<Block>>> = JoinSet::new();
            let mut retry_queue: VecDeque<Vec<Block>> = VecDeque::new();

            'outer: loop {
                // The database thread stops on errors it cannot recover from; batches
                // would only be re-queued forever.
                if tx.is_closed() {
                    error!("Database thread stopped, stopping sync");
                    break;
                }

                // Get an available connection; if the pool is empty or the concurrency
                // limit is reached, wait for a body task to finish first. We only stop
                // once every in-flight batch has completed, so a batch that fails late
                // is still re-queued instead of being dropped.
                let mut conn = loop {
                    // `done` means no more headers to request; retries may still be pending.
                    let has_work = !retry_queue.is_empty() || !done.load(Ordering::Relaxed);
                    if has_work && body_tasks.len() < 10 {
                        if let Some(c) = pool.pop_front() {
                            break c;
                        }
                    }
                    if body_tasks.is_empty() {
                        if has_work {
                            warn!(
                                "No connections left ({} batches still to retry)",
                                retry_queue.len()
                            );
                        }
                        break 'outer;
                    }
                    match body_tasks.join_next().await {
                        Some(Ok(Ok(c))) => pool.push_back(c),
                        Some(Ok(Err(headers))) => {
                            warn!("Task failed, re-queuing batch of {} headers", headers.len());
                            retry_queue.push_back(headers);
                        }
                        // Cannot happen: panics are caught inside the task and turned into Err(headers).
                        Some(Err(e)) => error!("Body task aborted: {:?}", e),
                        None => break 'outer,
                    }
                };

                let block_headers = if let Some(headers) = retry_queue.pop_front() {
                    info!("Retrying batch of {} headers on new connection", headers.len());
                    headers
                } else {
                    info!("Sending GetBlockHeaders (starting {})", hex::encode(&current_hash));
                    let req_id = eth::next_request_id();
                    let get_headers = eth::create_get_block_headers_message(
                        &current_hash,
                        BLOCK_NUM,
                        0,
                        true,
                        req_id,
                    );
                    let Some(headers_body) =
                        conn.request(get_headers, BLOCK_HEADERS_CODE, req_id).await
                    else {
                        warn!("No headers response, dropping connection");
                        continue;
                    };

                    let headers = eth::parse_block_headers(&headers_body);
                    if headers.is_empty() {
                        // Stop requesting headers but let in-flight batches finish.
                        warn!("No block headers received");
                        pool.push_back(conn);
                        done.store(true, Ordering::Relaxed);
                        continue;
                    }

                    if let Err(e) =
                        verify::verify_header_chain(&headers, &current_hash, true, BLOCK_NUM)
                    {
                        // Drop the peer; the same request goes to the next connection.
                        warn!("Invalid block headers from peer, dropping connection: {}", e);
                        continue;
                    }

                    current_hash = headers.last().unwrap().parent_hash.to_vec();
                    headers
                };

                let tx_clone = tx.clone();
                let done_clone = done.clone();
                // Copy kept by the outer task so the batch can be re-queued if the
                // fetch panics (e.g. a malformed peer message hitting an unwrap).
                let headers_copy = block_headers.clone();
                body_tasks.spawn(async move {
                    let fetch = tokio::spawn(async move {
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
                            let req_id = eth::next_request_id();
                            let get_bodies = eth::create_get_block_bodies_message(
                                &hashes[transactions.len()..].to_vec(),
                                req_id,
                            );
                            let Some(body) =
                                conn.request(get_bodies, BLOCK_BODIES_CODE, req_id).await
                            else {
                                warn!("GetBlockBodies failed, will retry batch");
                                return Err(block_headers);
                            };
                            let bodies = eth::parse_block_bodies(&body);
                            if bodies.is_empty() {
                                warn!("Peer returned no block bodies, will retry batch");
                                return Err(block_headers);
                            }
                            let roots: Vec<_> = bodies.iter().map(|(r, _)| r.clone()).collect();
                            if let Err(e) = verify::verify_block_bodies(
                                &block_headers[transactions.len()..],
                                &roots,
                            ) {
                                warn!("Invalid block bodies from peer, will retry batch: {}", e);
                                return Err(block_headers);
                            }
                            transactions.extend(bodies.into_iter().map(|(_, b)| b));
                        }

                        let mut receipts: Vec<Vec<Receipt>> = vec![];
                        if eth_version == 69 {
                            while receipts.len() < hashes.len() {
                                info!(
                                    "Sending GetReceipts ({}/{})",
                                    receipts.len(),
                                    hashes.len()
                                );
                                let req_id = eth::next_request_id();
                                let get_receipts = eth::create_get_receipts_message(
                                    &hashes[receipts.len()..].to_vec(),
                                    req_id,
                                );
                                let Some(body) =
                                    conn.request(get_receipts, RECEIPTS_CODE, req_id).await
                                else {
                                    warn!("GetReceipts failed, will retry batch");
                                    return Err(block_headers);
                                };
                                let batch_receipts = eth::parse_receipts(&body);
                                if batch_receipts.is_empty() {
                                    warn!("Peer returned no receipts, will retry batch");
                                    return Err(block_headers);
                                }
                                let roots: Vec<_> =
                                    batch_receipts.iter().map(|(root, _)| *root).collect();
                                if let Err(e) = verify::verify_receipts(
                                    &block_headers[receipts.len()..],
                                    &roots,
                                ) {
                                    warn!("Invalid receipts from peer, will retry batch: {}", e);
                                    return Err(block_headers);
                                }
                                receipts.extend(batch_receipts.into_iter().map(|(_, r)| r));
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

                    match fetch.await {
                        Ok(result) => result,
                        Err(e) => {
                            warn!("Body task panicked: {:?}", e);
                            Err(headers_copy)
                        }
                    }
                });
            }
        } else {
            // Forward sync (tracking the tip): sequential, one batch at a time,
            // rotating through peers. No parallelism needed since new blocks
            // arrive slowly (~12s apart).
            let mut retry_headers: Option<Vec<Block>> = None;

            // Tokio-postgres client used only for re-org rollback queries.
            let (reorg_pg_client, reorg_pg_conn) =
                tokio_postgres::connect(&database_params, tokio_postgres::NoTls)
                    .await
                    .expect("to connect to database for re-org handling");
            tokio::spawn(async move {
                if let Err(e) = reorg_pg_conn.await {
                    warn!("reorg postgres connection error: {}", e);
                }
            });

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
                    // Make sure everything sent so far is saved before asking for more:
                    // a rollback must not race the DB thread saving the block it deletes.
                    if !wait_for_db(&last_confirmed, current_number, &tx).await {
                        error!("Database thread stopped or did not save block n° {} in time, stopping.", current_number);
                        break 'outer;
                    }

                    // Ask by number for the blocks after ours, then check the first one
                    // builds on our block. Asking by hash would hide a re-org: peers
                    // answer a non-canonical hash with that header alone.
                    let next_number = current_number + 1;
                    info!("Sending GetBlockHeaders (starting n° {})", next_number);
                    let req_id = eth::next_request_id();
                    let get_headers = eth::create_get_block_headers_message(
                        &next_number,
                        BLOCK_NUM,
                        0,
                        false,
                        req_id,
                    );
                    let Some(headers_body) =
                        conn.request(get_headers, BLOCK_HEADERS_CODE, req_id).await
                    else {
                        warn!("No headers response, dropping connection");
                        continue;
                    };

                    let headers = eth::parse_block_headers(&headers_body);

                    // Empty response: the peer has no block after ours yet.
                    if headers.is_empty() {
                        pool.push_back(conn);
                        if pool.len() == 1 {
                            warn!("No new block headers and no other peers to try, stopping.");
                            break 'outer;
                        }
                        warn!("No new block headers, waiting...");
                        tokio::time::sleep(Duration::from_secs(15)).await;
                        continue;
                    }

                    let first = &headers[0];
                    let first_hash = first.hash.clone();
                    if first.number != next_number {
                        warn!(
                            "Peer answered with block n° {} instead of n° {}, dropping connection",
                            first.number, next_number
                        );
                        continue;
                    }
                    if let Err(e) =
                        verify::verify_header_chain(&headers, &first_hash, false, BLOCK_NUM)
                    {
                        // Drop the peer; the same request goes to the next connection.
                        warn!("Invalid block headers from peer, dropping connection: {}", e);
                        continue;
                    }

                    // The next block doesn't build on ours: our block was re-orged out.
                    // Roll it back and try again from its parent; deeper re-orgs repeat this.
                    if first.parent_hash != current_hash {
                        pool.push_back(conn);
                        warn!(
                            "Re-org detected: block n° {} has parent {} but we have {}. Rolling back one block.",
                            next_number,
                            hex::encode(&headers[0].parent_hash),
                            hex::encode(&current_hash)
                        );
                        let schema = network.to_string();
                        let parent = reorg_pg_client
                            .query_opt(
                                &format!(
                                    "SELECT parent_hash FROM {}.blocks WHERE hash = $1;",
                                    schema
                                ),
                                &[&current_hash],
                            )
                            .await;
                        match parent {
                            Ok(Some(row)) => {
                                let parent_hash: Vec<u8> = row.get(0);
                                for stmt in [
                                    format!("DELETE FROM {0}.receipts WHERE txid IN (SELECT txid FROM {0}.transactions WHERE block = $1)", schema),
                                    format!("DELETE FROM {0}.contracts WHERE txid IN (SELECT txid FROM {0}.transactions WHERE block = $1)", schema),
                                    format!("DELETE FROM {0}.transactions WHERE block = $1", schema),
                                    format!("DELETE FROM {0}.withdrawals WHERE block_hash = $1", schema),
                                    format!("DELETE FROM {0}.ommers WHERE canonical_hash = $1", schema),
                                    format!("DELETE FROM {0}.blocks WHERE hash = $1", schema),
                                ] {
                                    reorg_pg_client.execute(&stmt, &[&current_hash]).await.unwrap();
                                }
                                warn!(
                                    "Rolled back block n° {} ({}). Resuming from parent {}.",
                                    current_number,
                                    hex::encode(&current_hash),
                                    hex::encode(&parent_hash)
                                );
                                current_hash = parent_hash;
                                current_number -= 1;
                            }
                            Ok(None) => {
                                warn!("Block {} not found in DB during re-org rollback, resetting to max known block.", hex::encode(&current_hash));
                                match reorg_pg_client.query_opt(
                                    &format!("SELECT hash, number FROM {}.blocks WHERE number = (SELECT MAX(number) FROM {}.blocks);", schema, schema),
                                    &[],
                                ).await {
                                    Ok(Some(row)) => {
                                        current_hash = row.get(0);
                                        current_number = row.get::<_, i32>(1) as u32;
                                        warn!("Resuming from max known block n° {}: {}", current_number, hex::encode(&current_hash));
                                    }
                                    _ => {
                                        warn!("No known blocks in DB, stopping forward sync.");
                                        break 'outer;
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Re-org rollback query failed: {}", e);
                                continue;
                            }
                        }
                        // Tell the DB thread the next batch starts right after the new position.
                        *last_confirmed.lock().unwrap() =
                            Some((current_number, current_hash.clone()));
                        continue;
                    }

                    current_hash = headers.last().unwrap().hash.to_vec();
                    current_number = headers.last().unwrap().number;
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
                    let req_id = eth::next_request_id();
                    let get_bodies = eth::create_get_block_bodies_message(
                        &hashes[transactions.len()..].to_vec(),
                        req_id,
                    );
                    let Some(body) = conn.request(get_bodies, BLOCK_BODIES_CODE, req_id).await
                    else {
                        warn!("GetBlockBodies failed, will retry batch");
                        retry_headers = Some(block_headers);
                        continue 'outer;
                    };
                    let bodies = eth::parse_block_bodies(&body);
                    if bodies.is_empty() {
                        warn!("Peer returned no block bodies, will retry batch");
                        retry_headers = Some(block_headers);
                        continue 'outer;
                    }
                    let roots: Vec<_> = bodies.iter().map(|(r, _)| r.clone()).collect();
                    if let Err(e) =
                        verify::verify_block_bodies(&block_headers[transactions.len()..], &roots)
                    {
                        warn!("Invalid block bodies from peer, will retry batch: {}", e);
                        retry_headers = Some(block_headers);
                        continue 'outer;
                    }
                    transactions.extend(bodies.into_iter().map(|(_, b)| b));
                }

                let mut receipts: Vec<Vec<Receipt>> = vec![];
                if eth_version == 69 {
                    while receipts.len() < hashes.len() {
                        info!("Sending GetReceipts ({}/{})", receipts.len(), hashes.len());
                        let req_id = eth::next_request_id();
                        let get_receipts = eth::create_get_receipts_message(
                            &hashes[receipts.len()..].to_vec(),
                            req_id,
                        );
                        let Some(body) = conn.request(get_receipts, RECEIPTS_CODE, req_id).await
                        else {
                            warn!("GetReceipts failed, will retry batch");
                            retry_headers = Some(block_headers);
                            continue 'outer;
                        };
                        let batch_receipts = eth::parse_receipts(&body);
                        if batch_receipts.is_empty() {
                            warn!("Peer returned no receipts, will retry batch");
                            retry_headers = Some(block_headers);
                            continue 'outer;
                        }
                        let roots: Vec<_> = batch_receipts.iter().map(|(root, _)| *root).collect();
                        if let Err(e) =
                            verify::verify_receipts(&block_headers[receipts.len()..], &roots)
                        {
                            warn!("Invalid receipts from peer, will retry batch: {}", e);
                            retry_headers = Some(block_headers);
                            continue 'outer;
                        }
                        receipts.extend(batch_receipts.into_iter().map(|(_, r)| r));
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
