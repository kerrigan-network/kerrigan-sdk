/// HTTP API — axum endpoints for the bridge.
use std::io::Write;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::cache::BlockCache;
use crate::index::ShieldIndex;
use crate::rpc::RpcClient;

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
    /// Block cache: `(hash, verbosity)` → stripped JSON. Eliminates repeated
    /// `getblock` RPCs when multiple clients sync the same blocks.
    pub block_cache: std::sync::RwLock<BlockCache>,
    /// Current chain height — updated by ZMQ/polling, used for rehydration.
    pub chain_height: AtomicU32,
    /// True when ZMQ is connected and receiving blocks. Polling is disabled.
    pub zmq_active: std::sync::atomic::AtomicBool,
    /// Persistent shield.bin cache file handle.
    pub cache_file: tokio::sync::Mutex<std::fs::File>,
    /// In-memory shield buffer — the entire shield.bin held in RAM.
    /// Requests serve slices directly from this buffer (zero disk I/O).
    pub shield_buffer: RwLock<Vec<u8>>,
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
/// For the default Compact format, serves directly from the in-memory
/// shield buffer (zero RPC, zero disk I/O). For CompactPlus, re-fetches
/// and encodes on-the-fly.
pub async fn get_shield_data(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ShieldDataQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let start = query.start_block.unwrap_or(500);
    let format = query.format;
    let timer = std::time::Instant::now();

    // Fast path: serve default Compact format from in-memory buffer
    if format == StreamFormat::Compact {
        let offset = {
            let index = state.index.read().await;
            match index.offset_for_height(start) {
                Some(o) => o as usize,
                None => {
                    log_timing(timer, "getshielddata (empty)");
                    return Ok((
                        StatusCode::OK,
                        [("Content-Type", "application/octet-stream")],
                        Vec::new(),
                    ));
                }
            }
        };

        let buffer = state.shield_buffer.read().await;
        if offset >= buffer.len() {
            log_timing(timer, "getshielddata (empty)");
            return Ok((
                StatusCode::OK,
                [("Content-Type", "application/octet-stream")],
                Vec::new(),
            ));
        }

        let data = buffer[offset..].to_vec();
        drop(buffer);
        log_timing(timer, "getshielddata (buffer)");
        return Ok((
            StatusCode::OK,
            [("Content-Type", "application/octet-stream")],
            data,
        ));
    }

    // CompactPlus: derive from the Compact buffer by stripping cv + out_ciphertext
    let offset = {
        let index = state.index.read().await;
        match index.offset_for_height(start) {
            Some(o) => o as usize,
            None => {
                log_timing(timer, "getshielddata (empty)");
                return Ok((
                    StatusCode::OK,
                    [("Content-Type", "application/octet-stream")],
                    Vec::new(),
                ));
            }
        }
    };

    let buffer = state.shield_buffer.read().await;
    if offset >= buffer.len() {
        log_timing(timer, "getshielddata (empty)");
        return Ok((
            StatusCode::OK,
            [("Content-Type", "application/octet-stream")],
            Vec::new(),
        ));
    }

    let data = compact_to_compact_plus(&buffer[offset..]);
    drop(buffer);
    log_timing(timer, "getshielddata (buffer→compact+)");
    Ok((
        StatusCode::OK,
        [("Content-Type", "application/octet-stream")],
        data,
    ))
}

/// Transform a Compact (0x04) stream into CompactPlus (0x05) by stripping
/// cv (32 bytes) and out_ciphertext (80 bytes) from each output.
///
/// Walks the length-prefixed packets in the buffer, copies block markers
/// as-is, and rewrites compact tx packets with the fields removed.
fn compact_to_compact_plus(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len()); // will be smaller
    let mut pos = 0;

    while pos + 4 <= data.len() {
        let pkt_len = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
        let pkt_end = pos + 4 + pkt_len;
        if pkt_end > data.len() { break; }

        let pkt_type = data[pos + 4];

        if pkt_type == 0x5d {
            // Block marker — copy as-is
            out.extend_from_slice(&data[pos..pkt_end]);
        } else if pkt_type == 0x04 && pkt_len >= 3 {
            // Compact tx → CompactPlus: strip cv(32) + out_ct(80) per output
            let num_spends = data[pos + 5] as usize;
            let num_outputs = data[pos + 6] as usize;

            // Calculate new packet size: type(1) + nSpends(1) + nOutputs(1)
            //   + spends(num_spends * 32) + outputs(num_outputs * 644)
            let new_pkt_len = 3 + num_spends * 32 + num_outputs * 644;
            out.extend_from_slice(&(new_pkt_len as u32).to_le_bytes());
            out.push(0x05); // CompactPlus type
            out.push(num_spends as u8);
            out.push(num_outputs as u8);

            // Copy nullifiers (32 bytes each)
            let mut src = pos + 7; // after type + nSpends + nOutputs
            for _ in 0..num_spends {
                out.extend_from_slice(&data[src..src + 32]);
                src += 32;
            }

            // Copy outputs, skipping cv (first 32) and out_ct (last 80)
            for _ in 0..num_outputs {
                // src layout: cv(32) + cmu(32) + epk(32) + enc(580) + out_ct(80) = 756
                let cmu_start = src + 32; // skip cv
                let enc_end = cmu_start + 32 + 32 + 580; // cmu + epk + enc
                out.extend_from_slice(&data[cmu_start..enc_end]); // 644 bytes
                src += 756;
            }
        } else {
            // Unknown packet — copy as-is
            out.extend_from_slice(&data[pos..pkt_end]);
        }

        pos = pkt_end;
    }

    out
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

// ---------------------------------------------------------------------------
// GET /params/:filename — proxy Sapling proving parameters with CORS
// ---------------------------------------------------------------------------

/// Proxy Sapling parameter files from download.z.cash with CORS headers.
/// Cached in memory after first fetch to avoid repeated downloads.
static PARAMS_CACHE: std::sync::LazyLock<tokio::sync::RwLock<std::collections::HashMap<String, Vec<u8>>>> =
    std::sync::LazyLock::new(|| tokio::sync::RwLock::new(std::collections::HashMap::new()));

pub async fn serve_sapling_params(
    Path(filename): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Only allow known param files
    if filename != "sapling-output.params" && filename != "sapling-spend.params" {
        return Err((StatusCode::NOT_FOUND, "Unknown params file".into()));
    }

    // Check cache
    {
        let cache = PARAMS_CACHE.read().await;
        if let Some(data) = cache.get(&filename) {
            return Ok((
                [
                    (header::CONTENT_TYPE, "application/octet-stream"),
                    (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
                ],
                data.clone(),
            ));
        }
    }

    // Fetch from z.cash
    let url = format!("https://download.z.cash/downloads/{filename}");
    eprintln!("  [params] Downloading {filename} from {url}...");

    let resp = reqwest::get(&url).await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Download failed: {e}")))?;

    if !resp.status().is_success() {
        return Err((StatusCode::BAD_GATEWAY, format!("Upstream returned {}", resp.status())));
    }

    let bytes = resp.bytes().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Read failed: {e}")))?;
    let data = bytes.to_vec();

    eprintln!("  [params] Cached {filename} ({} bytes)", data.len());

    // Cache
    {
        let mut cache = PARAMS_CACHE.write().await;
        cache.insert(filename, data.clone());
    }

    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        data,
    ))
}
