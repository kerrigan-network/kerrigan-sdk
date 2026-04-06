/// Block scanner — extracts Sapling transactions from the Kerrigan node.
///
/// Uses verbosity 1 (txid list) + getrawtransaction (raw hex) to avoid the
/// node's broken JSON serialization of Sapling txs (MoneyRange bug in TxToUniv).
/// Chains through blocks via `nextblockhash` (one getblock call per block).

use kerrigan_sdk::encoding;
use kerrigan_sdk::sapling::sync::{RawShieldBlock, BlockEntry};

use crate::rpc::RpcClient;

/// Sapling transaction marker: version 3 (LE u16) + type 10 (LE u16).
const SAPLING_TX_HEADER: [u8; 4] = [0x03, 0x00, 0x0a, 0x00];

// ---------------------------------------------------------------------------
// Block scanning
// ---------------------------------------------------------------------------

/// Scan a single block by hash for Sapling transactions.
///
/// Uses verbosity 1 to get the tx list (avoids TxToUniv crash), then
/// fetches raw hex for each tx and checks for the Sapling header.
fn scan_block_inner(
    rpc: &RpcClient,
    block_json: &serde_json::Value,
    height: u32,
) -> Result<Option<RawShieldBlock>, ScanError> {
    let txids = block_json
        .get("tx")
        .and_then(|t| t.as_array())
        .ok_or(ScanError::Parse("missing 'tx' array in block".into()))?;

    let mut entries = Vec::new();

    for txid_val in txids {
        let txid = txid_val
            .as_str()
            .ok_or(ScanError::Parse("txid not a string".into()))?;

        // Fetch raw transaction hex
        let raw_hex = match rpc.get_raw_transaction(txid, false) {
            Ok(val) => match val.as_str() {
                Some(s) => s.to_string(),
                None => continue,
            },
            Err(e) => {
                eprintln!("  Warning: getrawtransaction({txid}): {e} — skipping tx");
                continue;
            }
        };

        // Decode hex to bytes
        let tx_bytes = match encoding::hex_decode(&raw_hex) {
            Ok(b) => b,
            Err(_) => continue,
        };

        // Check for Sapling tx header (version 3, type 10)
        if tx_bytes.len() >= 4 && tx_bytes[..4] == SAPLING_TX_HEADER {
            entries.push(BlockEntry::FullTx(tx_bytes));
        }
    }

    if entries.is_empty() {
        Ok(None)
    } else {
        Ok(Some(RawShieldBlock { height, entries }))
    }
}

/// Scan a single block by height (standalone).
pub fn scan_block(rpc: &RpcClient, height: u32) -> Result<Option<RawShieldBlock>, ScanError> {
    let hash = rpc
        .get_block_hash(height)
        .map_err(|e| ScanError::Rpc(format!("getblockhash({height}): {e}")))?;

    // Verbosity 1 = block with txid list (no decoded txs, no crash)
    let block_json = rpc
        .get_block(&hash, 1)
        .map_err(|e| ScanError::Rpc(format!("getblock({hash}): {e}")))?;

    let h = block_json
        .get("height")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(height);

    scan_block_inner(rpc, &block_json, h)
}

/// Scan a range of blocks by chaining via `nextblockhash`.
///
/// Only calls `getblockhash` once (for the first block), then follows the
/// chain — one `getblock` call per block + one `getrawtransaction` per tx.
///
/// Skips blocks that return RPC errors and continues scanning.
pub fn scan_range(
    rpc: &RpcClient,
    start: u32,
    end: u32,
    on_progress: impl Fn(u32, u32),
) -> Result<Vec<RawShieldBlock>, ScanError> {
    let mut shield_blocks = Vec::new();
    let total = end.saturating_sub(start) + 1;
    let mut errors = 0u32;

    // Get the first block hash
    let mut current_hash = rpc
        .get_block_hash(start)
        .map_err(|e| ScanError::Rpc(format!("getblockhash({start}): {e}")))?;

    for height in start..=end {
        on_progress(height - start, total);

        // Fetch block at verbosity 1 (txid list only)
        let block_json = match rpc.get_block(&current_hash, 1) {
            Ok(json) => json,
            Err(e) => {
                eprintln!("\n  Warning: block {height} ({current_hash}): {e} — skipping");
                errors += 1;

                // Try to recover by fetching the next hash directly
                match rpc.get_block_hash(height + 1) {
                    Ok(hash) => {
                        current_hash = hash;
                        continue;
                    }
                    Err(_) => break,
                }
            }
        };

        // Extract Sapling txs
        match scan_block_inner(rpc, &block_json, height) {
            Ok(Some(block)) => {
                let tx_count = block.entries.len();
                shield_blocks.push(block);
                if tx_count > 0 {
                    eprintln!("\n  Found shield block {height} ({tx_count} Sapling tx{})",
                        if tx_count == 1 { "" } else { "s" });
                }
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("\n  Warning: block {height} parse error: {e} — skipping");
                errors += 1;
            }
        }

        // Chain to next block
        match block_json.get("nextblockhash").and_then(|v| v.as_str()) {
            Some(next) => current_hash = next.to_string(),
            None => break,
        }
    }

    on_progress(total, total);

    if errors > 0 {
        eprintln!("\n  Completed with {errors} skipped block(s)");
    }

    Ok(shield_blocks)
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ScanError {
    Rpc(String),
    Parse(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rpc(e) => write!(f, "scanner RPC error: {e}"),
            Self::Parse(e) => write!(f, "scanner parse error: {e}"),
        }
    }
}

impl std::error::Error for ScanError {}
