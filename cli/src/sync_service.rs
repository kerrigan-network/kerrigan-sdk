/// Sync orchestration for the CLI — bridges network I/O to the SDK sync engine.

use kerrigan_sdk::sync::{self, TxData, TxInput, TxOutput, SyncResult};
use kerrigan_sdk::wallet::{WalletData, WalletError};

use crate::network::{ExplorerClient, NetworkError, TransactionInfo};
use crate::storage;

// ---------------------------------------------------------------------------
// Convert explorer types → SDK types
// ---------------------------------------------------------------------------

/// Convert an explorer TransactionInfo to the SDK's TxData.
fn to_tx_data(tx: &TransactionInfo) -> TxData {
    let inputs = tx.vin.iter().map(|v| TxInput {
        prev_txid: v.txid.clone(),
        prev_vout: v.vout,
        address: v.addr.clone(),
        value_sat: v.value_sat
            .or_else(|| v.value.map(|f| (f * kerrigan_sdk::params::COIN as f64) as u64)),
        is_coinbase: v.coinbase.is_some(),
    }).collect();

    let outputs = tx.vout.iter().map(|v| TxOutput {
        n: v.n,
        value_sat: v.value_satoshis(),
        addresses: v.script_pub_key.as_ref()
            .and_then(|spk| spk.addresses.clone())
            .unwrap_or_default(),
        script_hex: v.script_pub_key.as_ref()
            .and_then(|spk| spk.hex.clone())
            .unwrap_or_default(),
    }).collect();

    TxData {
        txid: tx.txid.clone(),
        inputs,
        outputs,
        timestamp: tx.time,
        block_height: tx.blockheight,
        confirmations: tx.confirmations,
    }
}

// ---------------------------------------------------------------------------
// Sync orchestration
// ---------------------------------------------------------------------------

/// Sync the wallet with a progress callback.
///
/// Two-layer cache:
/// 1. Fast path: if block height unchanged, return cached.
/// 2. Incremental: fetch only new txids, merge into persisted state.
pub fn sync_wallet(
    wallet: &mut WalletData,
    on_progress: impl Fn(usize, usize),
) -> Result<SyncResult, WalletError> {
    let client = ExplorerClient::new();

    // Fast path: check block height
    let current_height = client.get_block_height()
        .map_err(|e| WalletError::Other(format!("Sync error: {e}")))?;

    if wallet.last_sync_height > 0 && current_height == wallet.last_sync_height {
        if let Some(state) = &wallet.sync_state {
            let utxos = state.derive_utxos();
            let balance = utxos.iter().fold(0u64, |a, u| a.saturating_add(u.amount));
            return Ok(SyncResult {
                utxos,
                balance,
                new_tx_count: 0,
                processed_txids: state.processed_txids.clone(),
                history: wallet.history.clone(),
                state: state.clone(),
            });
        }
    }

    // Fetch address txids
    on_progress(0, 0);
    let all_txids = client.get_address_txids(&wallet.address)
        .map_err(|e| WalletError::Other(format!("Sync error: {e}")))?;

    // Filter new txids
    let known = wallet.sync_state.as_ref()
        .map(|s| &s.processed_txids)
        .cloned()
        .unwrap_or_default();

    let new_txids: Vec<&String> = all_txids.iter()
        .filter(|txid| !known.contains(*txid))
        .collect();

    let new_count = new_txids.len();

    // If nothing new, return cached
    if new_count == 0 {
        if let Some(state) = &wallet.sync_state {
            let utxos = state.derive_utxos();
            let balance = utxos.iter().fold(0u64, |a, u| a.saturating_add(u.amount));
            wallet.last_sync_height = current_height;
            return Ok(SyncResult {
                utxos,
                balance,
                new_tx_count: 0,
                processed_txids: state.processed_txids.clone(),
                history: wallet.history.clone(),
                state: state.clone(),
            });
        }
    }

    on_progress(0, new_count);

    // Fetch new transactions
    let mut new_tx_data = Vec::new();
    for (i, txid) in new_txids.iter().rev().enumerate() {
        let tx_info = client.get_transaction(txid)
            .map_err(|e| WalletError::Other(format!("Sync error: {e}")))?;
        new_tx_data.push(to_tx_data(&tx_info));
        on_progress(i + 1, new_count);
    }

    // Feed to SDK sync engine
    let result = sync::process_transactions(
        wallet.sync_state.take(),
        &new_tx_data,
        &wallet.address,
        &wallet.history,
    );

    // Persist
    wallet.utxos = result.utxos.clone();
    wallet.processed_txids = result.processed_txids.clone();
    wallet.sync_state = Some(result.state.clone());
    wallet.history = result.history.clone();
    wallet.last_sync_height = current_height;

    Ok(result)
}
