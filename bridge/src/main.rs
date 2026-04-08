/// Kerrigan Bridge — shield sync server for light wallets.
///
/// Connects to a Kerrigan full node via JSON-RPC, scans for Sapling
/// transactions, and serves compact shield data over HTTP.
///
/// Usage:
///   kerrigan-bridge --rpc-url http://127.0.0.1:9998 --rpc-user rpc --rpc-pass rpc
mod api;
mod config;
mod index;
mod rpc;
mod scanner;
mod stream;

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use tokio::sync::RwLock;

use api::AppState;
use config::Config;
use index::ShieldIndex;
use rpc::RpcClient;

/// Scan for new blocks and index them. Shared by ZMQ and polling.
fn index_new_blocks(
    rpc_url: &str,
    rpc_user: &str,
    rpc_pass: &str,
    state: &Arc<AppState>,
    index_path: &str,
    source: &str,
) {
    let rpc = RpcClient::new(rpc_url, rpc_user, rpc_pass);
    let chain_height = match rpc.get_block_count() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("  [{source}] RPC error: {e}");
            return;
        }
    };

    let rt = tokio::runtime::Handle::current();
    let last_scanned = rt.block_on(async { state.index.read().await.last_scanned });

    let scan_from = last_scanned + 1;
    if scan_from > chain_height {
        return;
    }

    match scanner::scan_range(&rpc, scan_from, chain_height, |_, _| {}) {
        Ok(blocks) => {
            let count = blocks.len();
            rt.block_on(async {
                let mut index = state.index.write().await;
                for block in &blocks {
                    index.add_shield_block(block.height);
                }
                index.last_scanned = chain_height;
                let _ = index.save(index_path);
            });
            if count > 0 {
                eprintln!("  [{source}] Indexed {count} new shield block(s) (chain: {chain_height})");
            }
        }
        Err(e) => {
            eprintln!("  [{source}] Scan error: {e}");
        }
    }
}

#[tokio::main]
async fn main() {
    let config = Config::parse();

    println!("  Kerrigan Bridge v{}", env!("CARGO_PKG_VERSION"));
    println!("  Node:  {}", config.rpc_url);
    println!("  Port:  {}", config.port);
    println!();

    // Connect to node
    let rpc = RpcClient::new(&config.rpc_url, &config.rpc_user, &config.rpc_pass);

    // Verify connection
    let chain_height = match rpc.get_block_count() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Failed to connect to Kerrigan node: {e}");
            eprintln!("Is the node running at {}?", config.rpc_url);
            std::process::exit(1);
        }
    };
    println!("  Chain height: {chain_height}");

    // Load or create shield index
    let mut index = ShieldIndex::load_or_new(&config.index_path, config.start_height);
    let scan_from = index.last_scanned + 1;

    if scan_from <= chain_height {
        println!("  Scanning blocks {scan_from}..{chain_height} for Sapling data...");

        match scanner::scan_range(&rpc, scan_from, chain_height, |current, total| {
            if total > 0 && current % 100 == 0 {
                let pct = current * 100 / total;
                eprint!("\r  Scanning: {pct}% ({current}/{total})");
            }
        }) {
            Ok(blocks) => {
                let count = blocks.len();
                for block in &blocks {
                    index.add_shield_block(block.height);
                }
                index.last_scanned = chain_height;

                if let Err(e) = index.save(&config.index_path) {
                    eprintln!("\n  Warning: failed to save index: {e}");
                }

                eprintln!();
                println!("  Found {count} shield blocks ({} total indexed)",
                    index.shield_heights.len());
            }
            Err(e) => {
                eprintln!("\n  Scan error: {e}");
                eprintln!("  Continuing with partial index...");
            }
        }
    } else {
        println!("  Index up to date ({} shield blocks)",
            index.shield_heights.len());
    }

    // Build app state
    let state = Arc::new(AppState {
        rpc,
        index: RwLock::new(index),
        index_path: config.index_path.clone(),
        hash_cache: RwLock::new(api::HashCache::new(1000)),
    });

    // Routes
    let app = Router::new()
        .route("/getshielddata", get(api::get_shield_data))
        .route("/getblockcount", get(api::get_block_count))
        .route("/getshieldblocks", get(api::get_shield_blocks))
        .route("/sendrawtransaction", post(api::send_raw_transaction))
        .with_state(state.clone());

    // ZMQ listener — instant block notifications when it works
    {
        let s = state.clone();
        let zmq_url = config.zmq_url.clone();
        let rpc_url = config.rpc_url.clone();
        let rpc_user = config.rpc_user.clone();
        let rpc_pass = config.rpc_pass.clone();
        let index_path = config.index_path.clone();
        tokio::spawn(async move {
            use futures::StreamExt;
            loop {
                eprintln!("  [zmq] Subscribing to {zmq_url}...");
                let mut subscriber = match bitcoincore_zmq::subscribe_async(&[&zmq_url]) {
                    Ok(sub) => {
                        eprintln!("  [zmq] Connected");
                        sub
                    }
                    Err(e) => {
                        eprintln!("  [zmq] Failed: {e} — retrying in 30s");
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                        continue;
                    }
                };

                while let Some(msg) = subscriber.next().await {
                    let msg = match msg {
                        Ok(m) => m,
                        Err(e) => {
                            eprintln!("  [zmq] Error: {e} — reconnecting");
                            break;
                        }
                    };
                    if !matches!(msg, bitcoincore_zmq::Message::HashBlock(_, _)) {
                        continue;
                    }

                    let s2 = s.clone();
                    let r = rpc_url.clone();
                    let u = rpc_user.clone();
                    let p = rpc_pass.clone();
                    let i = index_path.clone();
                    tokio::task::spawn_blocking(move || {
                        index_new_blocks(&r, &u, &p, &s2, &i, "ZMQ");
                    }).await.ok();
                }

                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
    }

    // Polling loop — always runs, catches anything ZMQ misses
    {
        let s = state.clone();
        let rpc_url = config.rpc_url.clone();
        let rpc_user = config.rpc_user.clone();
        let rpc_pass = config.rpc_pass.clone();
        let index_path = config.index_path.clone();
        tokio::spawn(async move {
            eprintln!("  [poll] Active (10s interval)");
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;

                // Quick check: does last scanned block have a nextblockhash?
                let last_scanned = s.index.read().await.last_scanned;
                let rpc = RpcClient::new(&rpc_url, &rpc_user, &rpc_pass);
                let has_next = match rpc.get_block_hash(last_scanned) {
                    Ok(hash) => match rpc.get_block(&hash, 1) {
                        Ok(json) => json.get("nextblockhash").is_some(),
                        Err(_) => false,
                    },
                    Err(_) => false,
                };
                if !has_next {
                    continue;
                }

                let s2 = s.clone();
                let r = rpc_url.clone();
                let u = rpc_user.clone();
                let p = rpc_pass.clone();
                let i = index_path.clone();
                tokio::task::spawn_blocking(move || {
                    index_new_blocks(&r, &u, &p, &s2, &i, "Poll");
                }).await.ok();
            }
        });
    }

    // Serve
    let addr = format!("0.0.0.0:{}", config.port);
    println!();
    println!("  Listening on http://{addr}");
    println!();

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            let tag = "\x1b[31mError:\x1b[0m";
            eprintln!("  {tag} Cannot bind to {addr}: {e}");
            eprintln!("  Is another process using port {}?", config.port);
            std::process::exit(1);
        }
    };

    axum::serve(listener, app)
        .await
        .expect("server error");
}
