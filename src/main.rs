use eth_prototype::configs::Peer;
use eth_prototype::networks::Network;
use rand::Rng;
use secp256k1::rand::RngCore;
use secp256k1::{rand, SecretKey};
use std::env;
use std::error;
use std::net::SocketAddr;
use std::str::FromStr;
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
        loop {
            let blocks: Vec<(
                Block,
                Vec<Transaction>,
                Vec<Block>,
                Vec<Withdrawal>,
                Vec<Receipt>,
            )> = rx.blocking_recv().unwrap();
            database::save_blocks(&blocks, &network_arg, &mut postgres_client);

            // We are synced
            if network.genesis_hash.to_vec() == blocks.last().unwrap().0.hash.to_vec() {
                info!("We are synced ! We are creating the indexes on the tables... This will take a while.");
                // Open, read and execute SQL scripts at the end of sync
                utils::open_exec_sql_file(&network_arg, &mut postgres_client);
                break;
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
                let mut postgres_client =
                    postgres::Client::connect(&database_params, postgres::NoTls)
                        .expect("to connect to database");
                let result = postgres_client
                    .query(
                        format!(
                            "SELECT * FROM {0}.blocks WHERE hash = '\\x{1}';",
                            network.to_string(),
                            hex::encode(&best_hash)
                        )
                        .as_str(),
                        &[],
                    )
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

        // Fetch blocks from a random connection
        loop {
            if connections.is_empty() {
                warn!("No connections left");
                break;
            }

            let idx = rand::thread_rng().gen_range(0..connections.len());
            let conn = &mut connections[idx];

            // Send GetBlockHeaders
            info!(
                "Sending GetBlockHeaders (starting {})",
                hex::encode(&current_hash)
            );
            let get_headers =
                eth::create_get_block_headers_message(&current_hash, BLOCK_NUM, 0, reverse);
            if conn.tx_write.send(get_headers).await.is_err() {
                warn!("Connection {} lost, removing", idx);
                connections.remove(idx);
                continue;
            }

            // Wait for BlockHeaders (code 4)
            let headers_body = loop {
                match conn.rx_tcp.recv().await {
                    Some(body) if body[0].saturating_sub(16) == 4 => break Some(body),
                    Some(_) => continue,
                    None => break None,
                }
            };
            let headers_body = match headers_body {
                Some(b) => b,
                None => {
                    connections.remove(idx);
                    continue;
                }
            };

            let block_headers = eth::parse_block_headers(headers_body[1..].to_vec());
            if block_headers.is_empty() {
                warn!("No block headers received");
                break;
            }

            // Update current_hash for next batch
            if reverse {
                current_hash = block_headers.last().unwrap().parent_hash.to_vec();
            } else {
                current_hash = block_headers.last().unwrap().hash.to_vec();
            }

            let hashes: Vec<Vec<u8>> = block_headers.iter().map(|b| b.hash.clone()).collect();

            // Send GetBlockBodies, looping until all bodies are received
            let mut transactions: Vec<(Vec<Transaction>, Vec<Block>, Vec<Withdrawal>)> = vec![];
            while transactions.len() < hashes.len() {
                info!(
                    "Sending GetBlockBodies ({}/{})",
                    transactions.len(),
                    hashes.len()
                );
                let get_bodies =
                    eth::create_get_block_bodies_message(&hashes[transactions.len()..].to_vec());
                conn.tx_write.send(get_bodies).await.unwrap();

                // Wait for BlockBodies (code 6)
                loop {
                    match conn.rx_tcp.recv().await {
                        Some(body) if body[0].saturating_sub(16) == 6 => {
                            transactions.extend(eth::parse_block_bodies(body[1..].to_vec()));
                            break;
                        }
                        Some(_) => continue,
                        None => break,
                    }
                }
            }

            // Fetch receipts (eth69 only)
            let mut receipts: Vec<Vec<Receipt>> = vec![];
            if conn.eth_protocol_version == 69 {
                while receipts.len() < hashes.len() {
                    info!("Sending GetReceipts ({}/{})", receipts.len(), hashes.len());
                    let get_receipts =
                        eth::create_get_receipts_message(&hashes[receipts.len()..].to_vec());
                    conn.tx_write.send(get_receipts).await.unwrap();

                    // Wait for Receipts (code 16)
                    loop {
                        match conn.rx_tcp.recv().await {
                            Some(body) if body[0].saturating_sub(16) == 16 => {
                                receipts.extend(eth::parse_receipts(body[1..].to_vec()));
                                break;
                            }
                            Some(_) => continue,
                            None => break,
                        }
                    }
                }
            }

            let blocks: Vec<_> = block_headers
                .iter()
                .enumerate()
                .map(|(i, header)| {
                    let (txs, ommers, withdrawals) = transactions[i].clone();
                    let block_receipts = if conn.eth_protocol_version == 69 {
                        receipts[i].clone()
                    } else {
                        vec![]
                    };
                    (header.clone(), txs, ommers, withdrawals, block_receipts)
                })
                .collect();

            let current_height = blocks.last().unwrap().0.number;
            info!("Blocks n° {}", current_height);

            if tx.send(blocks).await.is_err() {
                warn!("DB channel closed");
                break;
            }

            if current_height == 0 {
                info!("Data fully synced");
                break;
            }
        }
    });

    // need to wait for database thread to finish
    database_handle.join().unwrap();
}

async fn run(
    peer: Peer,
    network: Network,
    database_params: &String,
    current_hash: &mut Vec<u8>,
    reverse: bool,
    tx: &tokio::sync::mpsc::Sender<
        Vec<(
            Block,
            Vec<Transaction>,
            Vec<Block>,
            Vec<Withdrawal>,
            Vec<Receipt>,
        )>,
    >,
) -> Result<(), Box<dyn error::Error + Send + Sync>> {
    // Connect to the peer
    let connection = Connection::connect(peer, network).await?;
    let their_blockhash = connection.latest_blockhash();

    // If we are already synced and we are saving new blocks, lets verify that we don't have the already highest block from this peer.
    // Sometimes peers are stuck and don't have new blocks. We need to disconnect from those.
    if !reverse {
        // We need to go one block back
        let mut postgres_client = postgres::Client::connect(&database_params, postgres::NoTls)
            .expect("to connect to database");
        let result = postgres_client
            .query(
                format!(
                    "SELECT * FROM {0}.blocks WHERE hash = '\\x{1}';",
                    network.to_string(),
                    hex::encode(their_blockhash)
                )
                .as_str(),
                &[],
            )
            .unwrap();

        if result.len() > 0 {
            warn!("We already have their latets block");
            return Err("Peer not synced".into());
        }
    }

    // If we don't have blocks in the database we use the best one
    if current_hash.len() == 0 {
        *current_hash = connection.latest_blockhash().clone();
    }

    /****************************
     *
     *  START FETCHING BLOCKS
     *
     ****************************/

    // loop {
    //     /******************
    //      *
    //      *  Send GetBlockHeaders message
    //      *
    //      ******************/
    //     info!(
    //         "Sending GetBlockHeaders message (starting {})",
    //         hex::encode(&current_hash)
    //     );

    //     let get_blocks_headers =
    //         eth::create_get_block_headers_message(&current_hash, BLOCK_NUM, 0, reverse);
    //     utils::send_message(get_blocks_headers, &stream, &egress_mac, &egress_aes).await?;

    //     /******************
    //      *
    //      *  Handle BlockHeader message
    //      *
    //      ******************/
    //     info!("Handling BlockHeaders message");
    //     let mut uncrypted_body: Vec<u8>;
    //     let mut code;
    //     loop {
    //         uncrypted_body = rx_tcp.recv().await.ok_or("channel closed")?;

    //         code = uncrypted_body[0] - 16;
    //         if code == 4 {
    //             break;
    //         }
    //     }

    //     assert_eq!(code, 4);

    //     let block_headers = eth::parse_block_headers(uncrypted_body[1..].to_vec());

    //     // update block hash
    //     if reverse {
    //         *current_hash = block_headers.last().unwrap().parent_hash.to_vec();
    //     } else {
    //         if block_headers.len() == 0 {
    //             warn!("No block founds");

    //             // We need to go one block back
    //             let mut postgres_client =
    //                 postgres::Client::connect(&database_params, postgres::NoTls)
    //                     .expect("to connect to database");
    //             let result = postgres_client.query(format!("SELECT parent_hash, hash, number FROM {0}.blocks WHERE number = (SELECT MAX(number) FROM {0}.blocks);", network.to_string()).as_str(), &[]).unwrap();

    //             let hash: Vec<u8> = result[0].try_get(1).unwrap();
    //             match result[0].try_get(0) {
    //                 Ok(h) => {
    //                     *current_hash = h;
    //                 }
    //                 Err(_) => {
    //                     error!("Fail to get hash of the minimum block");
    //                 }
    //             }

    //             // Delete the block we cannot find anymore
    //             info!(
    //                 "Deleting block {} on network {}",
    //                 hex::encode(&hash),
    //                 network.to_string()
    //             );
    //             postgres_client.batch_execute(format!("DELETE FROM {0}.transactions WHERE block = '\\x{1}'; DELETE FROM {0}.blocks WHERE hash = '\\x{1}';", network.to_string(), hex::encode(&hash)).as_str()).unwrap();

    //             continue;
    //         }

    //         let last_block = block_headers.last().unwrap();

    //         // Verify if the block has ben created less than 600 seconds ago (1hr). Blocks are being created every 15 seconds.
    //         if SystemTime::now()
    //             .duration_since(SystemTime::UNIX_EPOCH)
    //             .unwrap()
    //             .as_secs() as u32
    //             - last_block.time
    //             < 600
    //         {
    //             trace!("We have the latest created block. Waiting 15 seconds.");
    //             tokio::time::sleep(Duration::from_secs(15)).await;
    //         } else {
    //             // if the last block is older than 1hr we are assuming the node is not receiving new blocks
    //             if current_hash.as_slice() == last_block.hash.as_slice() {
    //                 warn!("Last block is our current block");
    //                 return Err("No new blocks".into());
    //             }
    //         }

    //         *current_hash = last_block.hash.to_vec();
    //     }

    //     /******************
    //      *
    //      *  Send GetBlockBodies message
    //      *
    //      ******************/
    //     info!("Sending GetBlockBodies message");
    //     let hashes = block_headers
    //         .iter()
    //         .map(|b| b.hash.clone())
    //         .collect::<Vec<Vec<u8>>>();

    //     let mut transactions: Vec<(Vec<Transaction>, Vec<Block>, Vec<Withdrawal>)> = vec![];

    //     while transactions.len() < hashes.len() {
    //         let get_blocks_bodies =
    //             eth::create_get_block_bodies_message(&hashes[transactions.len()..].to_vec());
    //         utils::send_message(get_blocks_bodies, &stream, &egress_mac, &egress_aes).await?;

    //         /******************
    //          *
    //          *  Handle BlockHeader message
    //          *
    //          ******************/
    //         let mut uncrypted_body: Vec<u8>;
    //         let mut code;
    //         loop {
    //             uncrypted_body = rx_tcp.recv().await.ok_or("channel closed")?;

    //             code = uncrypted_body[0] - 16;
    //             if code == 6 {
    //                 break;
    //             }
    //         }
    //         assert_eq!(code, 6);

    //         let tmp_txs = eth::parse_block_bodies(uncrypted_body[1..].to_vec());
    //         transactions.extend(tmp_txs);

    //         info!(
    //             "Handling BlockBodies message ({}/{} block bodies received)",
    //             transactions.len(),
    //             hashes.len()
    //         );
    //     }

    //     /******************
    //      *
    //      *  Send GetReceipts message
    //      *
    //      ******************/
    //     // TODO: implement ETH 69 to be able to get receipts. Older protocols support it but are more of a struggle to implement.
    //     info!("Sending GetReceipts message");
    //     let mut receipts: Vec<Vec<Receipt>> = vec![];

    //     if version == 69 {
    //         while receipts.len() < hashes.len() {
    //             let get_receipts =
    //                 eth::create_get_receipts_message(&hashes[receipts.len()..].to_vec());
    //             utils::send_message(get_receipts, &stream, &egress_mac, &egress_aes).await?;

    //             /******************
    //              *
    //              *  Handle Receipts message
    //              *
    //              ******************/
    //             let mut uncrypted_body: Vec<u8>;
    //             let mut code;
    //             loop {
    //                 uncrypted_body = rx_tcp.recv().await.ok_or("channel closed")?;

    //                 code = uncrypted_body[0] - 16;
    //                 if code == 16 {
    //                     break;
    //                 }
    //             }
    //             assert_eq!(code, 16);

    //             let tmp_rpt: Vec<Vec<Receipt>> = eth::parse_receipts(uncrypted_body[1..].to_vec());
    //             receipts.extend(tmp_rpt);

    //             info!(
    //                 "Handling Receipts message ({}/{} block receipts received)",
    //                 receipts.len(),
    //                 hashes.len()
    //             );
    //         }
    //     }

    // let mut blocks: Vec<(
    //     Block,
    //     Vec<Transaction>,
    //     Vec<Block>,
    //     Vec<Withdrawal>,
    //     Vec<Receipt>,
    // )> = vec![];
    // let t_iter = transactions.iter();
    // t_iter
    //     .enumerate()
    //     .for_each(|(i, (txs, ommers, withdrawals))| {
    //         blocks.push((
    //             block_headers[i].clone(),
    //             txs.to_owned(),
    //             ommers.to_owned(),
    //             withdrawals.to_owned(),
    //             if version == 69 {
    //                 receipts[i].clone()
    //             } else {
    //                 vec![]
    //             },
    //         ));
    //     });

    //     let current_height = blocks.last().unwrap().0.number;
    //     info!("Blocks n° {}", current_height);

    //     // We already have the first block of the current batch when toward the tip of the chain
    //     if !reverse {
    //         blocks.remove(0);
    //     }

    //     // send blocks to the other thread to save in database
    //     if blocks.len() > 0 {
    //         tx.send(blocks).await?;
    //     }

    //     if current_height == 0 {
    //         info!("Data fully synced");

    //         drop(tcp_handle);

    //         break;
    //     }
    // }

    let _ = connection.handle.await;

    Ok(())
}
