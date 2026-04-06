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
    });

    // Clone for background task before router takes ownership
    let bg_state = state.clone();
    let bg_config = config.clone();

    // Routes
    let app = Router::new()
        .route("/getshielddata", get(api::get_shield_data))
        .route("/getblockcount", get(api::get_block_count))
        .route("/getshieldblocks", get(api::get_shield_blocks))
        .route("/sendrawtransaction", post(api::send_raw_transaction))
        .with_state(state);

    // Background block scanner — subscribes to ZMQ hashblock notifications
    tokio::spawn(async move {
        eprintln!("  [zmq] Subscribing to {}", bg_config.zmq_url);

        let mut subscriber = match bitcoincore_zmq::subscribe_async(&[&bg_config.zmq_url]) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  [zmq] Failed to subscribe: {e} — falling back to no live updates");
                return;
            }
        };

        use futures::StreamExt;
        while let Some(msg) = subscriber.next().await {
            let msg = match msg {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("  [zmq] Error: {e}");
                    continue;
                }
            };

            // We only care about hashblock notifications
            if !matches!(msg, bitcoincore_zmq::Message::HashBlock(_, _)) {
                continue;
            }

            eprintln!("  [zmq] New block notification");

            // Scan new blocks since our last indexed height
            let last_scanned = bg_state.index.read().await.last_scanned;

            let rpc_url = bg_state.rpc.url().to_string();
            let rpc_user = bg_state.rpc.user().to_string();
            let rpc_pass = bg_state.rpc.pass().to_string();

            let scan_from = last_scanned + 1;
            let scan_result = tokio::task::spawn_blocking(move || {
                let rpc = RpcClient::new(&rpc_url, &rpc_user, &rpc_pass);
                let chain_height = rpc.get_block_count()
                    .map_err(|e| scanner::ScanError::Rpc(format!("{e}")))?;
                let blocks = scanner::scan_range(&rpc, scan_from, chain_height, |_, _| {})?;
                Ok::<(Vec<_>, u32), scanner::ScanError>((blocks, chain_height))
            }).await;

            if let Ok(Ok((blocks, chain_height))) = scan_result {
                let mut index = bg_state.index.write().await;
                let new_count = blocks.len();
                for block in &blocks {
                    index.add_shield_block(block.height);
                }
                index.last_scanned = chain_height;
                let _ = index.save(&bg_config.index_path);

                if new_count > 0 {
                    eprintln!("  [zmq] Indexed {new_count} new shield block(s) at height {chain_height}");
                }
            }
        }

        eprintln!("  [zmq] Subscriber ended");
    });

    // Serve
    let addr = format!("0.0.0.0:{}", config.port);
    println!();
    println!("  Bridge listening on http://{addr}");
    println!("  Scanning for new blocks every 30s");
    println!("  Endpoints:");
    println!("    GET  /getshielddata?startBlock=N");
    println!("    GET  /getblockcount");
    println!("    GET  /getshieldblocks");
    println!("    POST /sendrawtransaction");
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
