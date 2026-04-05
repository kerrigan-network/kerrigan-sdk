/// UTXO derivation from transaction history — pure logic, no I/O.
///
/// The caller provides decoded transaction data; this module derives the UTXO
/// set, balance, and history entries. No network, no filesystem.
///
/// # Usage
///
/// ```rust,ignore
/// let mut state = SyncState::new();
/// for tx in transactions {
///     state.process_transaction(&tx, my_address);
/// }
/// let utxos = state.derive_utxos();
/// ```

use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::transaction::Utxo;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum SyncError {
    InvalidData(String),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidData(s) => write!(f, "Invalid data: {s}"),
        }
    }
}

impl std::error::Error for SyncError {}

// ---------------------------------------------------------------------------
// Transaction data types (caller-provided, I/O-agnostic)
// ---------------------------------------------------------------------------

/// A decoded transaction input, as provided by the caller.
///
/// This is the SDK's view of a vin entry — it doesn't care whether it came
/// from an Insight API, a Bitcoin RPC, or a test fixture.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TxInput {
    /// Previous transaction ID (None for coinbase).
    pub prev_txid: Option<String>,
    /// Previous output index (None for coinbase).
    pub prev_vout: Option<u32>,
    /// Address that owned the spent output (populated by explorer).
    pub address: Option<String>,
    /// Value of the spent output in satoshis.
    pub value_sat: Option<u64>,
    /// True if this is a coinbase input.
    pub is_coinbase: bool,
}

/// A decoded transaction output, as provided by the caller.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TxOutput {
    /// Output index within the transaction.
    pub n: u32,
    /// Value in satoshis.
    pub value_sat: u64,
    /// Address(es) this output pays to.
    pub addresses: Vec<String>,
    /// Hex-encoded scriptPubKey.
    pub script_hex: String,
}

/// A decoded transaction, as provided by the caller.
///
/// This is the SDK's I/O-agnostic representation. The CLI's network module
/// converts explorer JSON into this format before passing it to the sync engine.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TxData {
    /// Transaction ID.
    pub txid: String,
    /// Inputs.
    pub inputs: Vec<TxInput>,
    /// Outputs.
    pub outputs: Vec<TxOutput>,
    /// Timestamp (unix seconds), if known.
    pub timestamp: Option<u64>,
    /// Block height, if confirmed.
    pub block_height: Option<u64>,
    /// Confirmations at the time of fetch.
    pub confirmations: Option<u64>,
}

// ---------------------------------------------------------------------------
// Outpoint
// ---------------------------------------------------------------------------

/// A reference to a specific transaction output (txid:vout).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Outpoint {
    pub txid: String,
    pub vout: u32,
}

// ---------------------------------------------------------------------------
// History entry
// ---------------------------------------------------------------------------

/// A summary of a single transaction for history display.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TxHistoryEntry {
    /// Transaction ID.
    pub txid: String,
    /// Net change to our balance in satoshis (positive = received, negative = sent).
    pub net_amount: i64,
    /// Timestamp (unix epoch seconds), if available.
    pub timestamp: Option<u64>,
    /// Block height, if confirmed.
    pub block_height: Option<u64>,
    /// Number of confirmations at sync time.
    pub confirmations: Option<u64>,
}

// ---------------------------------------------------------------------------
// Serde helper for HashMap<Outpoint, Utxo>
// ---------------------------------------------------------------------------

mod outpoint_map_serde {
    use super::*;
    use serde::{Serializer, Deserializer};

    pub fn serialize<S>(map: &HashMap<Outpoint, Utxo>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(map.len()))?;
        for (k, v) in map {
            seq.serialize_element(&(k, v))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<Outpoint, Utxo>, D::Error>
    where D: Deserializer<'de> {
        let pairs: Vec<(Outpoint, Utxo)> = serde::Deserialize::deserialize(deserializer)?;
        Ok(pairs.into_iter().collect())
    }
}

// ---------------------------------------------------------------------------
// Sync state
// ---------------------------------------------------------------------------

/// Accumulated state from processing transaction history.
///
/// This struct is the core of the sync algorithm. Call [`process_transaction`]
/// for each tx in the address's history, then [`derive_utxos`] to get the
/// final UTXO set.
///
/// The state is serializable so it can persist across sessions,
/// enabling incremental sync.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SyncState {
    /// Outputs to our address: (outpoint → Utxo).
    #[serde(with = "outpoint_map_serde")]
    pub potential_utxos: HashMap<Outpoint, Utxo>,

    /// Outpoints that have been spent.
    pub spent_outpoints: HashSet<Outpoint>,

    /// Transaction IDs that have already been processed.
    pub processed_txids: HashSet<String>,
}

impl SyncState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Restore from persisted data (for incremental sync).
    pub fn from_persisted(
        potential_utxos: HashMap<Outpoint, Utxo>,
        spent_outpoints: HashSet<Outpoint>,
        processed_txids: HashSet<String>,
    ) -> Self {
        Self { potential_utxos, spent_outpoints, processed_txids }
    }

    /// Process a single transaction.
    ///
    /// Scans outputs for payments **to** `our_address` (potential UTXOs)
    /// and inputs for spends **from** `our_address` (spent outpoints).
    pub fn process_transaction(&mut self, tx: &TxData, our_address: &str) {
        self.processed_txids.insert(tx.txid.clone());

        // Scan outputs → potential UTXOs
        for out in &tx.outputs {
            let is_ours = out.addresses.iter().any(|a| a == our_address);
            if is_ours && out.value_sat > 0 {
                let outpoint = Outpoint {
                    txid: tx.txid.clone(),
                    vout: out.n,
                };
                self.potential_utxos.insert(outpoint, Utxo {
                    txid: tx.txid.clone(),
                    vout: out.n,
                    amount: out.value_sat,
                    script_pubkey: out.script_hex.clone(),
                });
            }
        }

        // Scan inputs → spent outpoints
        for inp in &tx.inputs {
            if inp.is_coinbase { continue; }
            let is_ours = inp.address.as_deref() == Some(our_address);
            if is_ours {
                if let (Some(prev_txid), Some(prev_vout)) = (&inp.prev_txid, inp.prev_vout) {
                    self.spent_outpoints.insert(Outpoint {
                        txid: prev_txid.clone(),
                        vout: prev_vout,
                    });
                }
            }
        }
    }

    /// Build a history entry for a transaction.
    pub fn history_entry(tx: &TxData, our_address: &str) -> TxHistoryEntry {
        let received: i64 = tx.outputs.iter()
            .filter(|o| o.addresses.iter().any(|a| a == our_address))
            .map(|o| o.value_sat as i64)
            .sum();

        let spent: i64 = tx.inputs.iter()
            .filter(|i| !i.is_coinbase && i.address.as_deref() == Some(our_address))
            .map(|i| i.value_sat.unwrap_or(0) as i64)
            .sum();

        TxHistoryEntry {
            txid: tx.txid.clone(),
            net_amount: received - spent,
            timestamp: tx.timestamp,
            block_height: tx.block_height,
            confirmations: tx.confirmations,
        }
    }

    /// Derive the final UTXO set: potential UTXOs minus spent outpoints.
    pub fn derive_utxos(&self) -> Vec<Utxo> {
        self.potential_utxos.iter()
            .filter(|(outpoint, _)| !self.spent_outpoints.contains(outpoint))
            .map(|(_, utxo)| utxo.clone())
            .collect()
    }

    /// Get the total confirmed balance in satoshis.
    pub fn balance(&self) -> u64 {
        self.derive_utxos().iter().fold(0u64, |a, u| a.saturating_add(u.amount))
    }

    /// Number of transactions processed so far.
    pub fn tx_count(&self) -> usize {
        self.processed_txids.len()
    }
}

/// Process a batch of transactions and return the sync result.
///
/// This is the SDK's main sync entry point. The caller provides all transaction
/// data; the SDK processes it and returns UTXOs, balance, and history.
///
/// For incremental sync, pass a prior `SyncState` and only the new transactions.
pub fn process_transactions(
    prior_state: Option<SyncState>,
    transactions: &[TxData],
    our_address: &str,
    prior_history: &[TxHistoryEntry],
) -> SyncResult {
    let mut state = prior_state.unwrap_or_default();
    let mut new_history = Vec::new();
    let new_tx_count = transactions.len();

    for tx in transactions {
        new_history.push(SyncState::history_entry(tx, our_address));
        state.process_transaction(tx, our_address);
    }

    let utxos = state.derive_utxos();
    let balance = utxos.iter().fold(0u64, |a, u| a.saturating_add(u.amount));

    // Merge history: new entries prepended to prior, deduplicated
    new_history.reverse();
    let seen: HashSet<String> = new_history.iter().map(|e| e.txid.clone()).collect();
    let mut history = new_history;
    for entry in prior_history {
        if !seen.contains(&entry.txid) {
            history.push(entry.clone());
        }
    }

    SyncResult {
        utxos,
        balance,
        new_tx_count,
        processed_txids: state.processed_txids.clone(),
        history,
        state,
    }
}

/// Result of a sync operation.
#[derive(Debug)]
pub struct SyncResult {
    pub utxos: Vec<Utxo>,
    pub balance: u64,
    pub new_tx_count: usize,
    pub processed_txids: HashSet<String>,
    pub history: Vec<TxHistoryEntry>,
    pub state: SyncState,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tx(txid: &str, inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> TxData {
        TxData {
            txid: txid.into(),
            inputs,
            outputs,
            timestamp: Some(1000),
            block_height: Some(100),
            confirmations: Some(10),
        }
    }

    fn coinbase_input() -> TxInput {
        TxInput { prev_txid: None, prev_vout: None, address: None, value_sat: None, is_coinbase: true }
    }

    fn spend_input(prev_txid: &str, prev_vout: u32, addr: &str, value: u64) -> TxInput {
        TxInput {
            prev_txid: Some(prev_txid.into()),
            prev_vout: Some(prev_vout),
            address: Some(addr.into()),
            value_sat: Some(value),
            is_coinbase: false,
        }
    }

    fn output(addr: &str, n: u32, value: u64) -> TxOutput {
        TxOutput { n, value_sat: value, addresses: vec![addr.into()], script_hex: "76a914ab88ac".into() }
    }

    const ADDR: &str = "KTest";
    const OTHER: &str = "KOther";

    #[test]
    fn single_receive() {
        let mut state = SyncState::new();
        let tx = make_tx("tx1", vec![coinbase_input()], vec![output(ADDR, 0, 1_0000_0000)]);
        state.process_transaction(&tx, ADDR);
        assert_eq!(state.derive_utxos().len(), 1);
        assert_eq!(state.balance(), 1_0000_0000);
    }

    #[test]
    fn receive_then_spend() {
        let mut state = SyncState::new();
        let tx1 = make_tx("tx1", vec![coinbase_input()], vec![output(ADDR, 0, 1_0000_0000)]);
        let tx2 = make_tx("tx2",
            vec![spend_input("tx1", 0, ADDR, 1_0000_0000)],
            vec![output(OTHER, 0, 9000_0000)],
        );
        state.process_transaction(&tx1, ADDR);
        state.process_transaction(&tx2, ADDR);
        assert_eq!(state.derive_utxos().len(), 0);
    }

    #[test]
    fn change_output() {
        let mut state = SyncState::new();
        let tx1 = make_tx("tx1", vec![coinbase_input()], vec![output(ADDR, 0, 1_0000_0000)]);
        let tx2 = make_tx("tx2",
            vec![spend_input("tx1", 0, ADDR, 1_0000_0000)],
            vec![output(OTHER, 0, 5000_0000), output(ADDR, 1, 4999_0000)],
        );
        state.process_transaction(&tx1, ADDR);
        state.process_transaction(&tx2, ADDR);
        assert_eq!(state.derive_utxos().len(), 1);
        assert_eq!(state.balance(), 4999_0000);
    }

    #[test]
    fn process_transactions_batch() {
        let txs = vec![
            make_tx("tx1", vec![coinbase_input()], vec![output(ADDR, 0, 5_0000_0000)]),
            make_tx("tx2", vec![coinbase_input()], vec![output(ADDR, 0, 3_0000_0000)]),
        ];
        let result = process_transactions(None, &txs, ADDR, &[]);
        assert_eq!(result.utxos.len(), 2);
        assert_eq!(result.balance, 8_0000_0000);
        assert_eq!(result.new_tx_count, 2);
        assert_eq!(result.history.len(), 2);
    }

    #[test]
    fn incremental_sync() {
        let tx1 = make_tx("tx1", vec![coinbase_input()], vec![output(ADDR, 0, 5_0000_0000)]);
        let result1 = process_transactions(None, &[tx1], ADDR, &[]);

        let tx2 = make_tx("tx2", vec![coinbase_input()], vec![output(ADDR, 0, 3_0000_0000)]);
        let result2 = process_transactions(Some(result1.state), &[tx2], ADDR, &result1.history);

        assert_eq!(result2.utxos.len(), 2);
        assert_eq!(result2.balance, 8_0000_0000);
        assert_eq!(result2.history.len(), 2);
    }

    #[test]
    fn history_dedup() {
        let tx1 = make_tx("tx1", vec![coinbase_input()], vec![output(ADDR, 0, 1_0000_0000)]);
        let prior = vec![SyncState::history_entry(&tx1, ADDR)];

        // Process same tx again
        let result = process_transactions(None, &[tx1], ADDR, &prior);
        assert_eq!(result.history.len(), 1, "Duplicate should be deduped");
    }
}
