/// Kerrigan Bridge — shield sync server for light wallets.
///
/// Connects to a Kerrigan full node via JSON-RPC, scans for Sapling
/// transactions, and serves compact shield data over HTTP.
///
/// Usage:
///   kerrigan-bridge --rpc-url http://127.0.0.1:9998 --rpc-user rpc --rpc-pass rpc
mod api;
mod cache;
mod config;
mod index;
mod rpc;
mod scanner;
mod shield_cache;
mod stream;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use tokio::sync::RwLock;

use api::AppState;
use cache::BlockCache;
use config::Config;
use index::ShieldIndex;
use rpc::RpcClient;

/// Scan for new blocks and index them. Shared by ZMQ and polling.
///
/// Detects chain reorganizations by verifying the parent hash chain.
/// On reorg, walks back to the fork point and invalidates cached blocks.
fn index_new_blocks(
    rpc_url: &str,
    rpc_user: &str,
    rpc_pass: &str,
    state: &Arc<AppState>,
    index_path: &str,
    source: &str,
) {
    // Mutual-exclusion gate: ZMQ and poll can both fire at the same tip,
    // and the filter-then-append critical section below is not atomic. Without
    // this, the loser of the race would double-append the same blocks into
    // shield.bin. If someone else is already indexing, just return — the
    // winner will cover whatever we would have done.
    if state.indexing.compare_exchange(
        false,
        true,
        Ordering::SeqCst,
        Ordering::SeqCst,
    ).is_err() {
        return;
    }
    // RAII guard so the flag is released on every exit path (including
    // panics and early returns).
    struct IndexingGuard<'a>(&'a std::sync::atomic::AtomicBool);
    impl Drop for IndexingGuard<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }
    let _guard = IndexingGuard(&state.indexing);

    let rpc = RpcClient::new(rpc_url, rpc_user, rpc_pass);
    let chain_height = match rpc.get_block_count() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("  [{source}] RPC error: {e}");
            return;
        }
    };

    // Update global chain height (used for rehydration)
    state.chain_height.store(chain_height, Ordering::Relaxed);

    let rt = tokio::runtime::Handle::current();
    let last_scanned = rt.block_on(async { state.index.read().await.last_scanned });

    let scan_from = last_scanned + 1;
    if scan_from > chain_height {
        return;
    }

    // --- Reorg detection ---
    // Check if the first new block's previousblockhash matches our cache.
    if let Ok(new_hash) = rpc.get_block_hash(scan_from) {
        if let Ok(new_block) = rpc.get_block(&new_hash, 1) {
            if let Some(prev_hash) = new_block.get("previousblockhash").and_then(|v| v.as_str()) {
                let reorged = state.block_cache.read().unwrap().detect_reorg(scan_from, prev_hash);
                if reorged {
                    // Walk back to find the fork point
                    let fork_height = find_fork_point(&rpc, &state.block_cache, scan_from);
                    eprintln!("  [{source}] Reorg detected! Fork at height {fork_height}");
                    state.block_cache.write().unwrap().invalidate_from(fork_height);

                    // Also remove reorged shield heights from the index
                    rt.block_on(async {
                        let mut index = state.index.write().await;
                        index.remove_from(fork_height);
                        index.last_scanned = fork_height.saturating_sub(1);
                        let _ = index.save(index_path);
                    });
                }
            }
        }
    }

    // Re-read last_scanned (may have changed from reorg handling)
    let last_scanned = rt.block_on(async { state.index.read().await.last_scanned });
    let scan_from = last_scanned + 1;
    if scan_from > chain_height {
        return;
    }

    match scanner::scan_range(&rpc, scan_from, chain_height, &state.block_cache, chain_height, |_, _| {}) {
        Ok(blocks) => {
            rt.block_on(async {
                // Filter against index to prevent ZMQ+poll race duplicates
                let index = state.index.read().await;
                let new_blocks: Vec<_> = blocks.iter()
                    .filter(|b| !index.shield_heights.contains(&b.height))
                    .cloned()
                    .collect();
                drop(index);

                if new_blocks.is_empty() {
                    return;
                }

                let count = new_blocks.len();
                let new_bytes = stream::encode_shield_stream(
                    &new_blocks, api::StreamFormat::Compact,
                );

                // Append to shield.bin on disk
                let cache_entries = {
                    let mut file = state.cache_file.lock().await;
                    shield_cache::append_blocks(&mut file, &new_blocks).ok()
                };

                // Append to in-memory buffer
                {
                    let mut buffer = state.shield_buffer.write().await;
                    buffer.extend_from_slice(&new_bytes);
                }

                // Update index with byte offsets
                let mut index = state.index.write().await;
                if let Some(entries) = cache_entries {
                    for (height, offset, _len) in entries {
                        index.add(height, offset);
                    }
                } else {
                    for block in &new_blocks {
                        index.add_shield_block(block.height);
                    }
                }
                index.last_scanned = chain_height;
                let _ = index.save(index_path);

                if count > 0 {
                    eprintln!("  [{source}] Indexed {count} new shield block(s) (chain: {chain_height})");
                }
            });
        }
        Err(e) => {
            eprintln!("  [{source}] Scan error: {e}");
        }
    }
}

/// Walk backwards from `height` to find where the chain diverges from cache.
///
/// Returns the fork height (first block where our cached hash disagrees
/// with the node). Walks at most 100 blocks back as a safety limit.
fn find_fork_point(
    rpc: &RpcClient,
    block_cache: &std::sync::RwLock<BlockCache>,
    height: u32,
) -> u32 {
    let cache = block_cache.read().unwrap();
    let mut h = height.saturating_sub(1);
    let limit = height.saturating_sub(100);

    while h > limit {
        match cache.hash_for_height(h) {
            Some(cached_hash) => {
                if let Ok(node_hash) = rpc.get_block_hash(h) {
                    if node_hash == cached_hash {
                        return h + 1; // This height matches — fork starts above
                    }
                }
                h -= 1;
            }
            None => return h + 1, // No cache entry — assume fork starts here
        }
    }

    h + 1
}

#[tokio::main]
async fn main() {
    let config = Config::parse();

    println!("  Kerrigan Bridge v{}", env!("CARGO_PKG_VERSION"));
    println!("  Node:  {}", config.rpc_url);
    println!("  Port:  {}", config.port);

    // Resolve data_dir to an absolute path. Create it if missing, fail fast if
    // that's not possible. Logging the resolved path here is what lets ops
    // notice a "you're-writing-state-to-the-wrong-place" restart before it
    // silently orphans shield.bin in an unrelated directory.
    let data_dir = match std::fs::create_dir_all(&config.data_dir)
        .and_then(|_| std::fs::canonicalize(&config.data_dir))
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to prepare data-dir {:?}: {e}", config.data_dir);
            std::process::exit(1);
        }
    };
    let index_path: String = data_dir.join("shield_index.json").to_string_lossy().into_owned();
    let cache_path: String = data_dir.join("shield.bin").to_string_lossy().into_owned();
    println!("  State: {}", data_dir.display());
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
    let (mut index, index_rebuilt) = ShieldIndex::load_or_new(&index_path, config.start_height);
    let scan_from = index.last_scanned + 1;

    // Block cache — 1000 blocks covers the tip range where most traffic is
    let block_cache = std::sync::RwLock::new(BlockCache::new(1000));

    // Recover shield.bin on crash, or truncate if index was rebuilt from scratch
    if index_rebuilt {
        // Index format changed or was corrupt — truncate shield.bin to avoid duplicates
        eprintln!("  Index rebuilt — truncating shield.bin");
        std::fs::write(&cache_path, []).ok();
    } else if let Some(last_good) = shield_cache::recover_cache(&cache_path) {
        eprintln!("  Cache recovered — last complete block: {last_good}");
    }
    let mut cache_file = shield_cache::open_cache(&cache_path)
        .expect("failed to open shield.bin");

    if scan_from <= chain_height {
        println!("  Scanning blocks {scan_from}..{chain_height} for Sapling data...");

        match scanner::scan_range(&rpc, scan_from, chain_height, &block_cache, chain_height, |current, total| {
            if total > 0 && current % 100 == 0 {
                let pct = current * 100 / total;
                eprint!("\r  Scanning: {pct}% ({current}/{total})");
            }
        }) {
            Ok(blocks) => {
                let count = blocks.len();

                // Append to shield.bin and record byte offsets
                match shield_cache::append_blocks(&mut cache_file, &blocks) {
                    Ok(entries) => {
                        for (height, offset, _len) in entries {
                            index.add(height, offset);
                        }
                    }
                    Err(e) => {
                        eprintln!("\n  Warning: shield.bin write failed: {e}");
                        for block in &blocks {
                            index.add_shield_block(block.height);
                        }
                    }
                }
                index.last_scanned = chain_height;

                if let Err(e) = index.save(&index_path) {
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

    // Load entire shield.bin into memory for zero-disk-I/O serving
    let shield_buffer = std::fs::read(&cache_path).unwrap_or_default();
    let buffer_mb = shield_buffer.len() as f64 / (1024.0 * 1024.0);
    println!("  Shield buffer: {buffer_mb:.1} MB in memory");

    // Build app state
    let state = Arc::new(AppState {
        rpc,
        index: RwLock::new(index),
        index_path: index_path.clone(),
        hash_cache: RwLock::new(api::HashCache::new(1000)),
        block_cache,
        chain_height: AtomicU32::new(chain_height),
        zmq_active: std::sync::atomic::AtomicBool::new(false),
        indexing: std::sync::atomic::AtomicBool::new(false),
        cache_file: tokio::sync::Mutex::new(cache_file),
        shield_buffer: RwLock::new(shield_buffer),
    });

    // Routes
    let app = Router::new()
        .route("/getshielddata", get(api::get_shield_data))
        .route("/getblockcount", get(api::get_block_count))
        .route("/getshieldblocks", get(api::get_shield_blocks))
        .route("/sendrawtransaction", post(api::send_raw_transaction))
        .route("/params/{filename}", get(api::serve_sapling_params))
        .with_state(state.clone());

    // ZMQ listener — the fast path. When the node publishes a hashblock we
    // catch up instantly. Not the only indexing path, though: the polling
    // loop below always runs as a safety net, because ZMQ can silently stall
    // (socket stays open but the node stops servicing subscribers) and we'd
    // have no way to tell from here.
    {
        let s = state.clone();
        let zmq_url = config.zmq_url.clone();
        let rpc_url = config.rpc_url.clone();
        let rpc_user = config.rpc_user.clone();
        let rpc_pass = config.rpc_pass.clone();
        let index_path_z = index_path.clone();
        tokio::spawn(async move {
            use futures::StreamExt;
            loop {
                eprintln!("  [zmq] Subscribing to {zmq_url}...");
                let mut subscriber = match bitcoincore_zmq::subscribe_async(&[&zmq_url]) {
                    Ok(sub) => {
                        s.zmq_active.store(true, std::sync::atomic::Ordering::Relaxed);
                        eprintln!("  [zmq] Connected");
                        sub
                    }
                    Err(e) => {
                        s.zmq_active.store(false, std::sync::atomic::Ordering::Relaxed);
                        eprintln!("  [zmq] Failed: {e} — retrying in 30s (polling continues)");
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                        continue;
                    }
                };

                while let Some(msg) = subscriber.next().await {
                    let msg = match msg {
                        Ok(m) => m,
                        Err(e) => {
                            s.zmq_active.store(false, std::sync::atomic::Ordering::Relaxed);
                            eprintln!("  [zmq] Error: {e} — reconnecting (polling continues)");
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
                    let i = index_path_z.clone();
                    tokio::task::spawn_blocking(move || {
                        index_new_blocks(&r, &u, &p, &s2, &i, "ZMQ");
                    }).await.ok();
                }

                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
    }

    // Polling loop — unconditional 30s safety net.
    //
    // Runs regardless of `zmq_active`. If ZMQ is healthy this mostly no-ops
    // (a single getblockcount RPC to the local node, and `index_new_blocks`
    // early-exits when `scan_from > chain_height`, plus `shield_heights`
    // dedupes against any block ZMQ already indexed). If ZMQ silently stalls
    // the way the Dash/PIVX-family publisher tends to, this picks up every
    // missed block within ≤30s — which is the whole point.
    {
        let s = state.clone();
        let rpc_url = config.rpc_url.clone();
        let rpc_user = config.rpc_user.clone();
        let rpc_pass = config.rpc_pass.clone();
        let index_path_p = index_path.clone();
        tokio::spawn(async move {
            eprintln!("  [poll] Safety net — 30s interval, always on");
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;

                let s2 = s.clone();
                let r = rpc_url.clone();
                let u = rpc_user.clone();
                let p = rpc_pass.clone();
                let i = index_path_p.clone();
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
