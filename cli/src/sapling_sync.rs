/// Sapling shield sync — fetches compact data from the bridge and updates wallet state.
use std::io::Read;

use kerrigan_sdk::params;
use kerrigan_sdk::sapling::keys;
use kerrigan_sdk::sapling::sync;
use kerrigan_sdk::wallet::{WalletData, WalletError};

/// Result of a shielded sync operation.
pub struct SaplingSyncResult {
    pub new_notes: usize,
    pub spent: usize,
}

/// Fetch the compact shield stream from the bridge HTTP endpoint.
/// This is the network-bound part — safe to run on a background thread.
pub fn fetch_shield_stream(start_block: u32) -> Result<Vec<u8>, WalletError> {
    let url = format!("{}/getshielddata?startBlock={start_block}", params::BRIDGE_URL);

    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(60))
        .build();

    let resp = agent
        .get(&url)
        .call()
        .map_err(|e| WalletError::Other(format!("bridge request failed: {e}")))?;

    let mut bytes = Vec::new();
    resp.into_reader()
        .read_to_end(&mut bytes)
        .map_err(|e| WalletError::Other(format!("reading bridge response: {e}")))?;

    Ok(bytes)
}

/// Apply fetched shield data to the wallet state.
/// This is the CPU-bound part — parses stream, decrypts notes, updates tree.
pub fn apply_shield_data(
    wallet: &mut WalletData,
    stream_bytes: &[u8],
) -> Result<SaplingSyncResult, WalletError> {
    let extfvk_encoded = wallet.sapling_extfvk.as_ref()
        .ok_or(WalletError::Other("no shielded viewing key".into()))?;

    let extfvk = keys::decode_extfvk(extfvk_encoded)
        .map_err(|e| WalletError::Other(format!("decode extfvk: {e}")))?;

    if stream_bytes.is_empty() {
        return Ok(SaplingSyncResult { new_notes: 0, spent: 0 });
    }

    let blocks = sync::parse_shield_stream(stream_bytes)
        .map_err(|e| WalletError::Other(format!("parse shield stream: {e}")))?;

    if blocks.is_empty() {
        return Ok(SaplingSyncResult { new_notes: 0, spent: 0 });
    }

    let max_height = blocks.iter().map(|b| b.height).max().unwrap_or(0);

    let tree_hex = wallet.commitment_tree.as_deref().unwrap_or("");
    let result = sync::process_shield_blocks(
        tree_hex,
        &blocks,
        &extfvk,
        &wallet.unspent_notes,
    )
    .map_err(|e| WalletError::Other(format!("process shield blocks: {e}")))?;

    let spent_count = wallet.unspent_notes.iter()
        .filter(|n| result.spent_nullifiers.contains(&n.nullifier))
        .count();

    // Update wallet state
    wallet.commitment_tree = Some(result.commitment_tree);

    let mut all_notes = result.updated_notes;
    all_notes.extend(result.new_notes.iter().cloned());
    all_notes.retain(|n| !result.spent_nullifiers.contains(&n.nullifier));

    wallet.unspent_notes = all_notes;
    wallet.sapling_last_block = max_height;

    Ok(SaplingSyncResult { new_notes: result.new_notes.len(), spent: spent_count })
}

