/// Block scanner — extracts compact Sapling data from the Kerrigan node.
///
/// Chains through blocks via `nextblockhash` (one RPC call per block instead
/// of two). Skips blocks that return RPC errors instead of aborting the scan.

use kerrigan_sdk::encoding;
use kerrigan_sdk::sapling::sync::{CompactSaplingOutput, CompactTransaction, RawShieldBlock, BlockEntry};
use serde_json::Value;
use zcash_note_encryption::ENC_CIPHERTEXT_SIZE;

use crate::rpc::RpcClient;

// ---------------------------------------------------------------------------
// Block scanning
// ---------------------------------------------------------------------------

/// Scan a single block by hash. Returns the block JSON and optional shield data.
///
/// Uses the block JSON directly (caller already has the hash from chaining).
pub fn scan_block_json(block_json: &Value, height: u32) -> Result<Option<RawShieldBlock>, ScanError> {
    let txs = block_json
        .get("tx")
        .and_then(|t| t.as_array())
        .ok_or(ScanError::Parse("missing 'tx' array in block".into()))?;

    let mut entries = Vec::new();

    for tx in txs {
        if let Some(compact) = extract_compact_tx(tx)? {
            entries.push(BlockEntry::CompactTx(compact));
        }
    }

    if entries.is_empty() {
        Ok(None)
    } else {
        Ok(Some(RawShieldBlock { height, entries }))
    }
}

/// Scan a single block by height (standalone, uses 2 RPC calls).
pub fn scan_block(rpc: &RpcClient, height: u32) -> Result<Option<RawShieldBlock>, ScanError> {
    let hash = rpc
        .get_block_hash(height)
        .map_err(|e| ScanError::Rpc(format!("getblockhash({height}): {e}")))?;

    let block_json = rpc
        .get_block(&hash, 2)
        .map_err(|e| ScanError::Rpc(format!("getblock({hash}): {e}")))?;

    scan_block_json(&block_json, height)
}

/// Scan a range of blocks by chaining via `nextblockhash`.
///
/// Only calls `getblockhash` once (for the first block), then follows the
/// chain via `nextblockhash` — one RPC call per block instead of two.
///
/// Skips blocks that return RPC errors and continues scanning.
/// Calls `on_progress(current, total)` after each block.
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

        // Fetch block (verbosity 2 = full decoded txs)
        let block_json = match rpc.get_block(&current_hash, 2) {
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
                    Err(_) => break, // Can't recover — stop scanning
                }
            }
        };

        // Extract shield data
        match scan_block_json(&block_json, height) {
            Ok(Some(block)) => shield_blocks.push(block),
            Ok(None) => {}
            Err(e) => {
                eprintln!("\n  Warning: block {height} parse error: {e} — skipping");
                errors += 1;
            }
        }

        // Chain to next block via nextblockhash
        match block_json.get("nextblockhash").and_then(|v| v.as_str()) {
            Some(next) => current_hash = next.to_string(),
            None => break, // We've reached the chain tip
        }
    }

    on_progress(total, total);

    if errors > 0 {
        eprintln!("\n  Completed with {errors} skipped block(s)");
    }

    Ok(shield_blocks)
}

// ---------------------------------------------------------------------------
// Transaction extraction
// ---------------------------------------------------------------------------

/// Extract compact Sapling data from a decoded transaction JSON.
///
/// Returns `None` if the transaction has no Sapling spends or outputs.
fn extract_compact_tx(tx: &Value) -> Result<Option<CompactTransaction>, ScanError> {
    let spends = tx.get("vShieldedSpend").and_then(|v| v.as_array());
    let outputs = tx.get("vShieldedOutput").and_then(|v| v.as_array());

    let has_spends = spends.map_or(false, |s| !s.is_empty());
    let has_outputs = outputs.map_or(false, |o| !o.is_empty());

    if !has_spends && !has_outputs {
        return Ok(None);
    }

    // Extract nullifiers from spends
    let mut nullifiers = Vec::new();
    if let Some(spends) = spends {
        for spend in spends {
            let nf_hex = spend
                .get("nullifier")
                .and_then(|v| v.as_str())
                .ok_or(ScanError::Parse("spend missing 'nullifier'".into()))?;

            let nf_bytes = hex_to_32(nf_hex, "nullifier")?;
            nullifiers.push(nf_bytes);
        }
    }

    // Extract compact data from outputs
    let mut compact_outputs = Vec::new();
    if let Some(outputs) = outputs {
        for output in outputs {
            let cmu_hex = output
                .get("cmu")
                .and_then(|v| v.as_str())
                .ok_or(ScanError::Parse("output missing 'cmu'".into()))?;

            let epk_hex = output
                .get("ephemeralKey")
                .and_then(|v| v.as_str())
                .ok_or(ScanError::Parse("output missing 'ephemeralKey'".into()))?;

            let enc_hex = output
                .get("encCiphertext")
                .and_then(|v| v.as_str())
                .ok_or(ScanError::Parse("output missing 'encCiphertext'".into()))?;

            let cmu = hex_to_32(cmu_hex, "cmu")?;
            let epk = hex_to_32(epk_hex, "ephemeralKey")?;

            let enc_bytes = encoding::hex_decode(enc_hex)
                .map_err(|e| ScanError::Parse(format!("encCiphertext hex: {e}")))?;

            if enc_bytes.len() != ENC_CIPHERTEXT_SIZE {
                return Err(ScanError::Parse(format!(
                    "encCiphertext wrong size: {} (expected {ENC_CIPHERTEXT_SIZE})",
                    enc_bytes.len()
                )));
            }

            let mut enc_ciphertext = [0u8; ENC_CIPHERTEXT_SIZE];
            enc_ciphertext.copy_from_slice(&enc_bytes);

            compact_outputs.push(CompactSaplingOutput {
                cmu,
                epk,
                enc_ciphertext,
            });
        }
    }

    Ok(Some(CompactTransaction {
        nullifiers,
        outputs: compact_outputs,
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decode a hex string to a 32-byte array.
fn hex_to_32(hex: &str, field_name: &str) -> Result<[u8; 32], ScanError> {
    let bytes = encoding::hex_decode(hex)
        .map_err(|e| ScanError::Parse(format!("{field_name} hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| ScanError::Parse(format!("{field_name}: expected 32 bytes")))
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
