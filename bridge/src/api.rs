/// HTTP API — axum endpoints for the bridge.

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

/// Shared application state.
pub struct AppState {
    pub rpc: RpcClient,
    pub index: RwLock<ShieldIndex>,
    pub index_path: String,
}

// ---------------------------------------------------------------------------
// GET /getshielddata?startBlock=N
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ShieldDataQuery {
    #[serde(rename = "startBlock")]
    pub start_block: Option<u32>,
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
    eprintln!("  [shielddata] Request startBlock={start}");

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

        Ok(stream::encode_shield_stream(&blocks))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("task error: {e}")))?
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

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
    let count = state
        .rpc
        .get_block_count()
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("node error: {e}")))?;
    Ok(count.to_string())
}

// ---------------------------------------------------------------------------
// GET /getshieldblocks
// ---------------------------------------------------------------------------

/// Return a JSON array of all shield block heights.
pub async fn get_shield_blocks(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<u32>> {
    let index = state.index.read().await;
    Json(index.shield_heights.clone())
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
