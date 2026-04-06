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

    // Routes
    let app = Router::new()
        .route("/getshielddata", get(api::get_shield_data))
        .route("/getblockcount", get(api::get_block_count))
        .route("/getshieldblocks", get(api::get_shield_blocks))
        .route("/sendrawtransaction", post(api::send_raw_transaction))
        .with_state(state);

    // Serve
    let addr = format!("0.0.0.0:{}", config.port);
    println!();
    println!("  Bridge listening on http://{addr}");
    println!("  Endpoints:");
    println!("    GET  /getshielddata?startBlock=N");
    println!("    GET  /getblockcount");
    println!("    GET  /getshieldblocks");
    println!("    POST /sendrawtransaction");
    println!();

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind");

    axum::serve(listener, app)
        .await
        .expect("server error");
}
