/// Block scanner — extracts Sapling transactions from the Kerrigan node.
///
/// Uses verbosity 1 (txid list) + getrawtransaction (raw hex) to avoid the
/// node's broken JSON serialization of Sapling txs (MoneyRange bug in TxToUniv).
/// Chains through blocks via `nextblockhash` (one getblock call per block).

use kerrigan_sdk::encoding;
use kerrigan_sdk::sapling::sync::{
    CompactSaplingOutput, CompactTransaction, RawShieldBlock, BlockEntry,
};
use zcash_note_encryption::ENC_CIPHERTEXT_SIZE;

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
            match parse_kerrigan_sapling_tx(&tx_bytes) {
                Ok(Some(compact)) => entries.push(BlockEntry::CompactTx(compact)),
                Ok(None) => {} // No shielded data in payload
                Err(e) => {
                    eprintln!("  Warning: parse Kerrigan tx: {e} — sending as raw");
                    entries.push(BlockEntry::FullTx(tx_bytes));
                }
            }
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
// Kerrigan type 10 raw transaction parser
// ---------------------------------------------------------------------------

/// Parse a raw Kerrigan type 10 transaction and extract compact Sapling data.
///
/// Format: header(4) + vin + vout + locktime(4) + extraPayload
/// Payload: nVersion(2) + spends + outputs + valueBalance(8) + bindingSig(64)
fn parse_kerrigan_sapling_tx(data: &[u8]) -> Result<Option<CompactTransaction>, String> {
    let mut pos = 4; // skip header

    // Skip vin
    let (vin_count, bytes_read) = read_compact_size(data, pos)?;
    pos += bytes_read;
    for _ in 0..vin_count {
        pos += 32 + 4; // prevout: txid + vout
        let (script_len, br) = read_compact_size(data, pos)?;
        pos += br + script_len; // scriptSig
        pos += 4; // sequence
        if pos > data.len() { return Err("truncated vin".into()); }
    }

    // Skip vout
    let (vout_count, bytes_read) = read_compact_size(data, pos)?;
    pos += bytes_read;
    for _ in 0..vout_count {
        pos += 8; // value
        let (script_len, br) = read_compact_size(data, pos)?;
        pos += br + script_len; // scriptPubKey
        if pos > data.len() { return Err("truncated vout".into()); }
    }

    // Skip nLockTime
    pos += 4;

    // Read extra payload
    let (payload_len, bytes_read) = read_compact_size(data, pos)?;
    pos += bytes_read;

    if pos + payload_len > data.len() {
        return Err("truncated payload".into());
    }

    let payload = &data[pos..pos + payload_len];
    parse_sapling_payload(payload)
}

/// Parse the Sapling extra payload to extract compact data.
fn parse_sapling_payload(data: &[u8]) -> Result<Option<CompactTransaction>, String> {
    let mut pos = 2; // skip payload nVersion (u16)

    // Spend descriptions
    let (num_spends, br) = read_compact_size(data, pos)?;
    pos += br;

    let mut nullifiers = Vec::new();
    for _ in 0..num_spends {
        if pos + 384 > data.len() { return Err("truncated spend".into()); }
        // cv(32) + anchor(32) + nullifier(32) + rk(32) + proof(192) + sig(64)
        let mut nf = [0u8; 32];
        nf.copy_from_slice(&data[pos + 64..pos + 96]); // nullifier at offset 64
        nullifiers.push(nf);
        pos += 384;
    }

    // Output descriptions
    let (num_outputs, br) = read_compact_size(data, pos)?;
    pos += br;

    let mut outputs = Vec::new();
    for _ in 0..num_outputs {
        if pos + 948 > data.len() { return Err("truncated output".into()); }
        // cv(32) + cmu(32) + epk(32) + enc(580) + out(80) + proof(192)
        let mut cmu = [0u8; 32];
        cmu.copy_from_slice(&data[pos + 32..pos + 64]); // cmu at offset 32 (after cv)

        let mut epk = [0u8; 32];
        epk.copy_from_slice(&data[pos + 64..pos + 96]); // epk at offset 64

        let mut enc_ciphertext = [0u8; ENC_CIPHERTEXT_SIZE];
        enc_ciphertext.copy_from_slice(&data[pos + 96..pos + 96 + ENC_CIPHERTEXT_SIZE]);

        outputs.push(CompactSaplingOutput { cmu, epk, enc_ciphertext });
        pos += 948;
    }

    if nullifiers.is_empty() && outputs.is_empty() {
        return Ok(None);
    }

    Ok(Some(CompactTransaction { nullifiers, outputs }))
}

/// Read a Bitcoin compact size (varint) from data at offset.
/// Returns (value, bytes_consumed).
fn read_compact_size(data: &[u8], pos: usize) -> Result<(usize, usize), String> {
    if pos >= data.len() { return Err("read past end".into()); }
    match data[pos] {
        n if n < 253 => Ok((n as usize, 1)),
        253 => {
            if pos + 3 > data.len() { return Err("truncated varint".into()); }
            Ok((u16::from_le_bytes([data[pos+1], data[pos+2]]) as usize, 3))
        }
        254 => {
            if pos + 5 > data.len() { return Err("truncated varint".into()); }
            Ok((u32::from_le_bytes([data[pos+1], data[pos+2], data[pos+3], data[pos+4]]) as usize, 5))
        }
        255 => {
            if pos + 9 > data.len() { return Err("truncated varint".into()); }
            Ok((u64::from_le_bytes([
                data[pos+1], data[pos+2], data[pos+3], data[pos+4],
                data[pos+5], data[pos+6], data[pos+7], data[pos+8],
            ]) as usize, 9))
        }
        _ => unreachable!(),
    }
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
