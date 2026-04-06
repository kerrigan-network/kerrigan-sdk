/// Sapling shield sync — fetches compact data from the bridge and updates wallet state.
use kerrigan_sdk::params;
use kerrigan_sdk::sapling::keys;
use kerrigan_sdk::sapling::sync;
use kerrigan_sdk::wallet::{WalletData, WalletError};


/// Sync the wallet's shielded state from the bridge.
///
/// 1. Fetches compact shield stream from the bridge endpoint.
/// 2. Parses the binary stream into blocks.
/// 3. Processes blocks against the wallet's viewing key.
/// 4. Updates commitment tree, discovers notes, tracks nullifiers.
pub fn sync_shielded(
    wallet: &mut WalletData,
    on_progress: impl Fn(&str),
) -> Result<SaplingSyncResult, WalletError> {
    // Need the extended full viewing key to decrypt notes
    let extfvk_encoded = wallet.sapling_extfvk.as_ref()
        .ok_or(WalletError::Other("no shielded viewing key — recreate wallet".into()))?;

    let extfvk = keys::decode_extfvk(extfvk_encoded)
        .map_err(|e| WalletError::Other(format!("decode extfvk: {e}")))?;

    // Fetch compact stream from the bridge
    on_progress("Fetching shield data...");
    let start_block = if wallet.sapling_last_block > 0 {
        wallet.sapling_last_block + 1
    } else {
        kerrigan_sdk::sapling::network::SAPLING_ACTIVATION_HEIGHT
    };

    let stream_bytes = fetch_shield_stream(start_block)?;

    if stream_bytes.is_empty() {
        return Ok(SaplingSyncResult { new_notes: 0, spent: 0 });
    }

    // Parse binary stream
    on_progress("Processing shield blocks...");
    let blocks = sync::parse_shield_stream(&stream_bytes)
        .map_err(|e| WalletError::Other(format!("parse shield stream: {e}")))?;

    if blocks.is_empty() {
        return Ok(SaplingSyncResult { new_notes: 0, spent: 0 });
    }

    // Get the highest block height from the stream
    let max_height = blocks.iter().map(|b| b.height).max().unwrap_or(0);

    // Process against viewing key
    let tree_hex = wallet.commitment_tree.as_deref().unwrap_or("");
    let result = sync::process_shield_blocks(
        tree_hex,
        &blocks,
        &extfvk,
        &wallet.unspent_notes,
    )
    .map_err(|e| WalletError::Other(format!("process shield blocks: {e}")))?;

    // Count spent notes (nullifiers that match our existing notes)
    let spent_count = count_spent_notes(&wallet.unspent_notes, &result.spent_nullifiers);

    // Update wallet state
    wallet.commitment_tree = Some(result.commitment_tree);

    // Merge updated notes (existing with updated witnesses)
    // and remove any that were spent (nullifier in spent list)
    let mut all_notes = result.updated_notes;
    all_notes.extend(result.new_notes.iter().cloned());

    // Filter out spent notes
    all_notes.retain(|n| !result.spent_nullifiers.contains(&n.nullifier));

    wallet.unspent_notes = all_notes;
    wallet.sapling_last_block = max_height;

    let new_notes = result.new_notes.len();

    Ok(SaplingSyncResult { new_notes, spent: spent_count })
}

/// Result of a shielded sync operation.
pub struct SaplingSyncResult {
    pub new_notes: usize,
    pub spent: usize,
}

/// Count how many of our notes were spent by the given nullifiers.
fn count_spent_notes(
    notes: &[kerrigan_sdk::sapling::notes::SerializedNote],
    spent_nullifiers: &[String],
) -> usize {
    notes.iter().filter(|n| spent_nullifiers.contains(&n.nullifier)).count()
}

/// Fetch the compact shield stream from the bridge HTTP endpoint.
fn fetch_shield_stream(start_block: u32) -> Result<Vec<u8>, WalletError> {
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
