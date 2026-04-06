/// Block scanner — extracts compact Sapling data from the Kerrigan node.
///
/// Scans blocks via RPC, detects Sapling transactions, and extracts only
/// the fields a light wallet needs (nullifiers, cmu, epk, enc_ciphertext).

use kerrigan_sdk::encoding;
use kerrigan_sdk::sapling::sync::{CompactSaplingOutput, CompactTransaction, RawShieldBlock, BlockEntry};
use serde_json::Value;
use zcash_note_encryption::ENC_CIPHERTEXT_SIZE;

use crate::rpc::RpcClient;

// ---------------------------------------------------------------------------
// Block scanning
// ---------------------------------------------------------------------------

/// Scan a single block at the given height for Sapling transactions.
///
/// Returns `None` if the block has no Sapling data, `Some(block)` otherwise.
pub fn scan_block(rpc: &RpcClient, height: u32) -> Result<Option<RawShieldBlock>, ScanError> {
    let hash = rpc
        .get_block_hash(height)
        .map_err(|e| ScanError::Rpc(format!("getblockhash({height}): {e}")))?;

    // Verbosity 2 = full decoded transactions
    let block_json = rpc
        .get_block(&hash, 2)
        .map_err(|e| ScanError::Rpc(format!("getblock({hash}): {e}")))?;

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

/// Scan a range of blocks, returning only those with Sapling data.
///
/// Calls `on_progress(current, total)` after each block.
pub fn scan_range(
    rpc: &RpcClient,
    start: u32,
    end: u32,
    on_progress: impl Fn(u32, u32),
) -> Result<Vec<RawShieldBlock>, ScanError> {
    let mut shield_blocks = Vec::new();
    let total = end.saturating_sub(start) + 1;

    for height in start..=end {
        on_progress(height - start, total);

        if let Some(block) = scan_block(rpc, height)? {
            shield_blocks.push(block);
        }
    }

    on_progress(total, total);
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
