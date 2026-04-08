/// HTTP API — axum endpoints for the bridge.
use std::io::Write;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::index::ShieldIndex;
use crate::rpc::RpcClient;
use crate::scanner;
use crate::stream;

/// Write elapsed time directly to stderr — zero allocation.
pub fn log_timing(start: std::time::Instant, label: &str) {
    let ms = start.elapsed().as_secs_f64() * 1000.0;
    let stderr = std::io::stderr();
    let mut w = stderr.lock();
    if ms >= 1000.0 {
        let _ = writeln!(w, "  [proxy {:.1}s] {label}", ms / 1000.0);
    } else if ms >= 1.0 {
        let _ = writeln!(w, "  [proxy {:.0}ms] {label}", ms);
    } else {
        let _ = writeln!(w, "  [proxy {:.2}ms] {label}", ms);
    }
}

/// Shared application state.
pub struct AppState {
    pub rpc: RpcClient,
    pub index: RwLock<ShieldIndex>,
    #[allow(dead_code)]
    pub index_path: String,
    /// LRU cache: height → block hash. Eliminates redundant getblockhash RPCs.
    #[allow(dead_code)]
    pub hash_cache: RwLock<HashCache>,
}

/// Fixed-size LRU cache for block height → hash mappings.
#[allow(dead_code)]
pub struct HashCache {
    entries: std::collections::HashMap<u32, String>,
    order: std::collections::VecDeque<u32>,
    capacity: usize,
}

impl HashCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: std::collections::HashMap::with_capacity(capacity),
            order: std::collections::VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    #[allow(dead_code)]
    pub fn get(&self, height: u32) -> Option<&str> {
        self.entries.get(&height).map(|s| s.as_str())
    }

    #[allow(dead_code)]
    pub fn insert(&mut self, height: u32, hash: String) {
        if self.entries.contains_key(&height) {
            return;
        }
        if self.entries.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(height, hash);
        self.order.push_back(height);
    }
}

// ---------------------------------------------------------------------------
// GET /getshielddata?startBlock=N
// ---------------------------------------------------------------------------

/// Stream format for the compact shield protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum StreamFormat {
    /// Compact (default): strips proofs/sigs, keeps out_ciphertext for sender
    /// recovery. Safe for imports, resyncs, and multi-device. (724 bytes/output)
    #[default]
    Compact,
    /// Compact+: additionally strips out_ciphertext for rapid bootstrap of
    /// freshly created wallets with no history to recover. (644 bytes/output)
    #[serde(rename = "compactplus")]
    CompactPlus,
}

#[derive(Deserialize)]
pub struct ShieldDataQuery {
    #[serde(rename = "startBlock")]
    pub start_block: Option<u32>,
    /// Stream format: "compact" (default) or "compactplus" (new wallet bootstrap)
    #[serde(default)]
    pub format: StreamFormat,
}

/// Serve compact shield data as a binary stream.
///
/// For each shield block >= startBlock, fetches the block from the node,
/// extracts compact Sapling data, and streams it in the binary wire format.
pub async fn get_shield_data(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ShieldDataQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let start = query.start_block.unwrap_or(500);
    let format = query.format;
    let timer = std::time::Instant::now();

    // Get shield block heights from the index
    let heights = {
        let index = state.index.read().await;
        index.heights_from(start)
    };
    eprintln!("  [shielddata] {} shield blocks to serve", heights.len());

    if heights.is_empty() {
        // Return empty binary response
        return Ok((
            StatusCode::OK,
            [("Content-Type", "application/octet-stream")],
            Vec::new(),
        ));
    }

    // Fetch and encode blocks (blocking RPC calls in spawn_blocking)
    let rpc_url = state.rpc.url().to_string();
    let rpc_user = state.rpc.user().to_string();
    let rpc_pass = state.rpc.pass().to_string();

    let stream = tokio::task::spawn_blocking(move || {
        let rpc = RpcClient::new(&rpc_url, &rpc_user, &rpc_pass);
        let mut blocks = Vec::new();

        for height in heights {
            match scanner::scan_block(&rpc, height) {
                Ok(Some(block)) => blocks.push(block),
                Ok(None) => {} // Index was stale — block no longer has shield data
                Err(e) => return Err(format!("scan error at height {height}: {e}")),
            }
        }

        Ok(stream::encode_shield_stream(&blocks, format))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("task error: {e}")))?
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    log_timing(timer, "getshielddata");
    Ok((
        StatusCode::OK,
        [("Content-Type", "application/octet-stream")],
        stream,
    ))
}

// ---------------------------------------------------------------------------
// GET /getblockcount
// ---------------------------------------------------------------------------

/// Return the current block height from the node.
pub async fn get_block_count(
    State(state): State<Arc<AppState>>,
) -> Result<String, (StatusCode, String)> {
    let timer = std::time::Instant::now();
    let count = state
        .rpc
        .get_block_count()
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("node error: {e}")))?;
    log_timing(timer, "getblockcount");
    Ok(count.to_string())
}

// ---------------------------------------------------------------------------
// GET /getshieldblocks
// ---------------------------------------------------------------------------

/// Return a JSON array of all shield block heights.
pub async fn get_shield_blocks(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<u32>> {
    let timer = std::time::Instant::now();
    let index = state.index.read().await;
    let result = Json(index.shield_heights.clone());
    log_timing(timer, "getshieldblocks");
    result
}

// ---------------------------------------------------------------------------
// POST /sendrawtransaction (body = hex string)
// ---------------------------------------------------------------------------

/// Broadcast a raw transaction to the network.
pub async fn send_raw_transaction(
    State(state): State<Arc<AppState>>,
    body: String,
) -> Result<String, (StatusCode, String)> {
    let hex = body.trim();
    eprintln!("  [broadcast] Received tx hex ({} bytes)", hex.len());

    match state.rpc.send_raw_transaction(hex) {
        Ok(txid) => {
            eprintln!("  [broadcast] Success: {txid}");
            Ok(txid)
        }
        Err(e) => {
            let msg = format!("{e}");
            eprintln!("  [broadcast] FAILED: {msg}");
            // Return 400 with error details (not 502) so client sees the message
            Err((StatusCode::BAD_REQUEST, msg))
        }
    }
}
