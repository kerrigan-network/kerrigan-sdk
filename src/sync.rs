/// UTXO derivation from transaction history.
///
/// The Kerrigan explorer has **no dedicated UTXO endpoint**. Instead, we derive
/// the UTXO set client-side by scanning the full transaction history for an address:
///
/// 1. Fetch all txids via [`ExplorerClient::get_address_txids`].
/// 2. Fetch each transaction via [`ExplorerClient::get_transaction`].
/// 3. **Outputs to our address** → potential UTXOs.
/// 4. **Inputs from our address** → spent outpoints.
/// 5. **UTXOs = potential − spent**.
///
/// Incremental sync is supported by tracking `processed_txids` — only new
/// transactions are fetched on subsequent syncs.
///
/// # Data flow
///
/// ```text
/// Explorer ──txids──→ SyncState ──fetch──→ process_transaction()
///                         │                        │
///                         │      ┌─────────────────┘
///                         ▼      ▼
///                    derive_utxos() → Vec<Utxo>
/// ```

use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::network::{ExplorerClient, TransactionInfo, NetworkError};
use crate::transaction::Utxo;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum SyncError {
    Network(NetworkError),
    InvalidData(String),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(e) => write!(f, "Network error: {e}"),
            Self::InvalidData(s) => write!(f, "Invalid data: {s}"),
        }
    }
}

impl std::error::Error for SyncError {}

impl From<NetworkError> for SyncError {
    fn from(e: NetworkError) -> Self { Self::Network(e) }
}

// ---------------------------------------------------------------------------
// Outpoint (txid + vout) as a unique key for spent tracking
// ---------------------------------------------------------------------------

/// A reference to a specific transaction output (txid:vout).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Outpoint {
    pub txid: String,
    pub vout: u32,
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
/// The state is designed to be serializable so it can persist across sessions
/// (via the wallet file), enabling incremental sync.
/// Serde helper: serialize HashMap<Outpoint, Utxo> as Vec<(Outpoint, Utxo)>
/// because JSON map keys must be strings.
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

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SyncState {
    /// Outputs to our address: (outpoint → Utxo).
    /// Includes both spent and unspent until [`derive_utxos`] is called.
    #[serde(with = "outpoint_map_serde")]
    pub potential_utxos: HashMap<Outpoint, Utxo>,

    /// Outpoints that have been spent (referenced as inputs in later txs).
    pub spent_outpoints: HashSet<Outpoint>,

    /// Transaction IDs that have already been processed.
    /// Used for incremental sync — skip these on the next sync.
    pub processed_txids: HashSet<String>,
}

impl SyncState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Restore a SyncState from persisted data (for incremental sync).
    pub fn from_persisted(
        potential_utxos: HashMap<Outpoint, Utxo>,
        spent_outpoints: HashSet<Outpoint>,
        processed_txids: HashSet<String>,
    ) -> Self {
        Self { potential_utxos, spent_outpoints, processed_txids }
    }

    /// Process a single transaction from the address's history.
    ///
    /// Scans outputs for payments **to** `our_address` (potential UTXOs)
    /// and inputs for spends **from** `our_address` (spent outpoints).
    pub fn process_transaction(&mut self, tx: &TransactionInfo, our_address: &str) {
        // Mark as processed
        self.processed_txids.insert(tx.txid.clone());

        // Scan outputs → potential UTXOs
        for vout in &tx.vout {
            let addresses = vout.script_pub_key.as_ref()
                .and_then(|spk| spk.addresses.as_ref());

            let is_ours = addresses
                .map(|addrs| addrs.iter().any(|a| a == our_address))
                .unwrap_or(false);

            if is_ours {
                let value = vout.value_satoshis();
                if value == 0 {
                    continue;
                }

                let script_hex = vout.script_pub_key.as_ref()
                    .and_then(|spk| spk.hex.clone())
                    .unwrap_or_default();

                let outpoint = Outpoint {
                    txid: tx.txid.clone(),
                    vout: vout.n,
                };

                self.potential_utxos.insert(outpoint, Utxo {
                    txid: tx.txid.clone(),
                    vout: vout.n,
                    amount: value,
                    script_pubkey: script_hex,
                });
            }
        }

        // Scan inputs → spent outpoints
        for vin in &tx.vin {
            // Skip coinbase inputs
            if vin.coinbase.is_some() {
                continue;
            }

            let is_ours = vin.addr.as_ref()
                .map(|a| a == our_address)
                .unwrap_or(false);

            if is_ours {
                if let (Some(prev_txid), Some(prev_vout)) = (&vin.txid, vin.vout) {
                    self.spent_outpoints.insert(Outpoint {
                        txid: prev_txid.clone(),
                        vout: prev_vout,
                    });
                }
            }
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
        self.derive_utxos().iter().map(|u| u.amount).sum()
    }

    /// Number of transactions processed so far.
    pub fn tx_count(&self) -> usize {
        self.processed_txids.len()
    }
}

// ---------------------------------------------------------------------------
// High-level sync orchestrator
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

/// Result of a sync operation.
#[derive(Debug)]
pub struct SyncResult {
    /// The derived UTXO set after sync.
    pub utxos: Vec<Utxo>,
    /// Total confirmed balance in satoshis.
    pub balance: u64,
    /// Number of new transactions processed in this sync.
    pub new_tx_count: usize,
    /// Complete set of processed txids (for persisting in the wallet file).
    pub processed_txids: HashSet<String>,
    /// Transaction history entries (newest first).
    pub history: Vec<TxHistoryEntry>,
    /// The full sync state (for persisting — enables incremental sync next time).
    pub state: SyncState,
    /// True if nothing changed (fast path — no new blocks or no new txids).
    pub was_cached: bool,
}

/// Perform a full sync (no prior state). Convenience wrapper.
pub fn sync_address(
    client: &ExplorerClient,
    address: &str,
    _known_txids: &HashSet<String>,
) -> Result<SyncResult, SyncError> {
    sync_incremental(client, address, None, &[], |_, _| {})
}

/// Incremental sync with progress callback and persisted state.
///
/// # Parameters
/// - `client`: the explorer API client.
/// - `address`: the Kerrigan address to sync.
/// - `prior_state`: the persisted `SyncState` from a previous sync (None for full sync).
/// - `prior_history`: the persisted history entries from a previous sync.
/// - `on_progress`: callback `(completed, total)` after each tx fetch.
///
/// # Progress phases
/// - `(0, 0)` — fetching address info
/// - `(0, N)` — N new transactions to fetch (0 = nothing new)
/// - `(i, N)` — fetched i of N new transactions
pub fn sync_incremental(
    client: &ExplorerClient,
    address: &str,
    prior_state: Option<SyncState>,
    prior_history: &[TxHistoryEntry],
    on_progress: impl Fn(usize, usize),
) -> Result<SyncResult, SyncError> {
    // Signal: fetching address info
    on_progress(0, 0);

    // 1. Get all txids for this address
    let all_txids = client.get_address_txids(address)?;

    // 2. Determine which txids are new
    let known_txids = prior_state.as_ref()
        .map(|s| &s.processed_txids)
        .cloned()
        .unwrap_or_default();

    let new_txids: Vec<&String> = all_txids.iter()
        .filter(|txid| !known_txids.contains(*txid))
        .collect();

    let new_tx_count = new_txids.len();

    // 3. If nothing new, return cached state immediately
    if new_tx_count == 0 {
        if let Some(state) = prior_state {
            let utxos = state.derive_utxos();
            let balance = utxos.iter().map(|u| u.amount).sum();
            on_progress(0, 0);
            return Ok(SyncResult {
                utxos,
                balance,
                new_tx_count: 0,
                processed_txids: state.processed_txids.clone(),
                history: prior_history.to_vec(),
                state,
                was_cached: true,
            });
        }
    }

    // Signal: N new txs to fetch
    on_progress(0, new_tx_count);

    // 4. Start from prior state or fresh
    let mut state = prior_state.unwrap_or_default();
    let mut new_history = Vec::new();

    // Only fetch NEW txids (oldest first)
    for (i, txid) in new_txids.iter().rev().enumerate() {
        let tx = client.get_transaction(txid)?;

        // Compute net amount for history
        let received: i64 = tx.vout.iter()
            .filter(|v| {
                v.script_pub_key.as_ref()
                    .and_then(|spk| spk.addresses.as_ref())
                    .map(|addrs| addrs.iter().any(|a| a == address))
                    .unwrap_or(false)
            })
            .map(|v| v.value_satoshis() as i64)
            .sum();

        let spent: i64 = tx.vin.iter()
            .filter(|v| v.coinbase.is_none() && v.addr.as_deref() == Some(address))
            .map(|v| v.value_sat.map(|s| s as i64)
                .or_else(|| v.value.map(|f| (f * crate::params::COIN as f64) as i64))
                .unwrap_or(0))
            .sum();

        new_history.push(TxHistoryEntry {
            txid: tx.txid.clone(),
            net_amount: received - spent,
            timestamp: tx.time,
            block_height: tx.blockheight,
            confirmations: tx.confirmations,
        });

        state.process_transaction(&tx, address);
        on_progress(i + 1, new_tx_count);
    }

    let utxos = state.derive_utxos();
    let balance = utxos.iter().map(|u| u.amount).sum();

    // Merge history: new entries (newest first) prepended to prior
    new_history.reverse();
    let mut history = new_history;
    history.extend_from_slice(prior_history);

    Ok(SyncResult {
        utxos,
        balance,
        new_tx_count,
        processed_txids: state.processed_txids.clone(),
        history,
        state,
        was_cached: false,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{TransactionInfo, TxVin, TxVout, ScriptPubKeyInfo};

    // Helper: build a TransactionInfo for testing
    fn make_tx(
        txid: &str,
        vins: Vec<(Option<&str>, Option<u32>, Option<&str>)>, // (prev_txid, prev_vout, addr)
        vouts: Vec<(&str, u32, u64, &str)>, // (addr, n, satoshis, script_hex)
    ) -> TransactionInfo {
        let vin = vins.into_iter().map(|(prev_txid, vout, addr)| TxVin {
            txid: prev_txid.map(|s| s.to_string()),
            vout,
            addr: addr.map(|s| s.to_string()),
            value: None,
            value_sat: None,
            coinbase: if prev_txid.is_none() && addr.is_none() { Some("coinbase".into()) } else { None },
        }).collect();

        let vout = vouts.into_iter().map(|(addr, n, satoshis, script_hex)| {
            let value_krgn = satoshis as f64 / 100_000_000.0;
            TxVout {
                value: Some(serde_json::json!(format!("{:.8}", value_krgn))),
                n,
                script_pub_key: Some(ScriptPubKeyInfo {
                    hex: Some(script_hex.to_string()),
                    addresses: Some(vec![addr.to_string()]),
                    script_type: Some("pubkeyhash".to_string()),
                }),
            }
        }).collect();

        TransactionInfo {
            txid: txid.to_string(),
            vin,
            vout,
            confirmations: Some(10),
            blockheight: Some(1000),
            time: None,
        }
    }

    const ADDR: &str = "KTestAddress";
    const OTHER: &str = "KOtherAddress";

    // -- Basic UTXO derivation --

    #[test]
    fn single_receive() {
        let mut state = SyncState::new();
        let tx = make_tx("tx1", vec![(None, None, None)], vec![
            (ADDR, 0, 100_000_000, "76a914abcd88ac"),
        ]);
        state.process_transaction(&tx, ADDR);

        let utxos = state.derive_utxos();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].txid, "tx1");
        assert_eq!(utxos[0].vout, 0);
        assert_eq!(utxos[0].amount, 100_000_000);
    }

    #[test]
    fn receive_then_spend() {
        let mut state = SyncState::new();

        // Receive 1 KRGN
        let tx1 = make_tx("tx1", vec![(None, None, None)], vec![
            (ADDR, 0, 100_000_000, "76a914abcd88ac"),
        ]);
        state.process_transaction(&tx1, ADDR);

        // Spend it (input references tx1:0)
        let tx2 = make_tx("tx2",
            vec![(Some("tx1"), Some(0), Some(ADDR))],
            vec![(OTHER, 0, 90_000_000, "76a914efgh88ac")],
        );
        state.process_transaction(&tx2, ADDR);

        let utxos = state.derive_utxos();
        assert_eq!(utxos.len(), 0, "Spent UTXO should be removed");
    }

    #[test]
    fn receive_spend_with_change() {
        let mut state = SyncState::new();

        // Receive 1 KRGN
        let tx1 = make_tx("tx1", vec![(None, None, None)], vec![
            (ADDR, 0, 100_000_000, "76a914abcd88ac"),
        ]);
        state.process_transaction(&tx1, ADDR);

        // Spend with change back to ourselves
        let tx2 = make_tx("tx2",
            vec![(Some("tx1"), Some(0), Some(ADDR))],
            vec![
                (OTHER, 0, 50_000_000, "76a914efgh88ac"),
                (ADDR, 1, 49_990_000, "76a914abcd88ac"),
            ],
        );
        state.process_transaction(&tx2, ADDR);

        let utxos = state.derive_utxos();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].txid, "tx2");
        assert_eq!(utxos[0].vout, 1);
        assert_eq!(utxos[0].amount, 49_990_000);
    }

    #[test]
    fn multiple_receives() {
        let mut state = SyncState::new();

        let tx1 = make_tx("tx1", vec![(None, None, None)], vec![
            (ADDR, 0, 50_000_000, "script1"),
        ]);
        let tx2 = make_tx("tx2", vec![(None, None, None)], vec![
            (ADDR, 0, 30_000_000, "script2"),
        ]);
        let tx3 = make_tx("tx3", vec![(None, None, None)], vec![
            (ADDR, 0, 20_000_000, "script3"),
        ]);

        state.process_transaction(&tx1, ADDR);
        state.process_transaction(&tx2, ADDR);
        state.process_transaction(&tx3, ADDR);

        let utxos = state.derive_utxos();
        assert_eq!(utxos.len(), 3);
        assert_eq!(state.balance(), 100_000_000);
    }

    #[test]
    fn spend_one_of_many() {
        let mut state = SyncState::new();

        let tx1 = make_tx("tx1", vec![(None, None, None)], vec![
            (ADDR, 0, 50_000_000, "s1"),
        ]);
        let tx2 = make_tx("tx2", vec![(None, None, None)], vec![
            (ADDR, 0, 30_000_000, "s2"),
        ]);
        state.process_transaction(&tx1, ADDR);
        state.process_transaction(&tx2, ADDR);

        // Spend only tx1:0
        let tx3 = make_tx("tx3",
            vec![(Some("tx1"), Some(0), Some(ADDR))],
            vec![(OTHER, 0, 49_000_000, "s3")],
        );
        state.process_transaction(&tx3, ADDR);

        let utxos = state.derive_utxos();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].txid, "tx2");
        assert_eq!(state.balance(), 30_000_000);
    }

    // -- Multiple outputs in one tx --

    #[test]
    fn multiple_outputs_to_us_in_one_tx() {
        let mut state = SyncState::new();

        let tx = make_tx("tx1", vec![(None, None, None)], vec![
            (ADDR, 0, 10_000_000, "s1"),
            (OTHER, 1, 20_000_000, "s2"),
            (ADDR, 2, 30_000_000, "s3"),
        ]);
        state.process_transaction(&tx, ADDR);

        let utxos = state.derive_utxos();
        assert_eq!(utxos.len(), 2);
        assert_eq!(state.balance(), 40_000_000);
    }

    // -- Outputs not to us are ignored --

    #[test]
    fn ignores_other_address_outputs() {
        let mut state = SyncState::new();

        let tx = make_tx("tx1", vec![(None, None, None)], vec![
            (OTHER, 0, 100_000_000, "script"),
        ]);
        state.process_transaction(&tx, ADDR);

        assert_eq!(state.derive_utxos().len(), 0);
        assert_eq!(state.balance(), 0);
    }

    // -- Coinbase inputs are not treated as spends --

    #[test]
    fn coinbase_input_not_spend() {
        let mut state = SyncState::new();

        // Coinbase tx pays to us
        let tx = make_tx("coinbase_tx", vec![(None, None, None)], vec![
            (ADDR, 0, 50_000_000, "script"),
        ]);
        state.process_transaction(&tx, ADDR);

        assert_eq!(state.derive_utxos().len(), 1);
    }

    // -- Zero-value outputs are skipped --

    #[test]
    fn zero_value_output_ignored() {
        let mut state = SyncState::new();

        let tx = make_tx("tx1", vec![(None, None, None)], vec![
            (ADDR, 0, 0, "script"),
            (ADDR, 1, 50_000_000, "script2"),
        ]);
        state.process_transaction(&tx, ADDR);

        let utxos = state.derive_utxos();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].vout, 1);
    }

    // -- Incremental sync: processed_txids --

    #[test]
    fn tracks_processed_txids() {
        let mut state = SyncState::new();

        let tx1 = make_tx("tx1", vec![(None, None, None)], vec![
            (ADDR, 0, 100_000_000, "s"),
        ]);
        let tx2 = make_tx("tx2", vec![(None, None, None)], vec![
            (ADDR, 0, 200_000_000, "s"),
        ]);

        state.process_transaction(&tx1, ADDR);
        state.process_transaction(&tx2, ADDR);

        assert!(state.processed_txids.contains("tx1"));
        assert!(state.processed_txids.contains("tx2"));
        assert_eq!(state.tx_count(), 2);
    }

    #[test]
    fn from_persisted_resumes() {
        let mut known = HashSet::new();
        known.insert("old_tx".to_string());

        let state = SyncState::from_persisted(HashMap::new(), HashSet::new(), known);
        assert!(state.processed_txids.contains("old_tx"));
        assert_eq!(state.derive_utxos().len(), 0);
    }

    // -- Double-spend: same output spent twice (shouldn't happen, but test robustness) --

    #[test]
    fn double_spend_still_removes() {
        let mut state = SyncState::new();

        let tx1 = make_tx("tx1", vec![(None, None, None)], vec![
            (ADDR, 0, 100_000_000, "s"),
        ]);
        state.process_transaction(&tx1, ADDR);

        // Two txs both spending tx1:0
        let tx2 = make_tx("tx2",
            vec![(Some("tx1"), Some(0), Some(ADDR))],
            vec![(OTHER, 0, 50_000_000, "s")],
        );
        let tx3 = make_tx("tx3",
            vec![(Some("tx1"), Some(0), Some(ADDR))],
            vec![(OTHER, 0, 50_000_000, "s")],
        );
        state.process_transaction(&tx2, ADDR);
        state.process_transaction(&tx3, ADDR);

        assert_eq!(state.derive_utxos().len(), 0);
    }

    // -- Complex scenario: chain of transactions --

    #[test]
    fn chain_of_transactions() {
        let mut state = SyncState::new();

        // Receive 10 KRGN
        let tx1 = make_tx("tx1", vec![(None, None, None)], vec![
            (ADDR, 0, 1_000_000_000, "s1"),
        ]);

        // Send 3 KRGN, get 6.999 change
        let tx2 = make_tx("tx2",
            vec![(Some("tx1"), Some(0), Some(ADDR))],
            vec![
                (OTHER, 0, 300_000_000, "s2"),
                (ADDR, 1, 699_900_000, "s3"),
            ],
        );

        // Send 2 KRGN from change, get 4.998 change
        let tx3 = make_tx("tx3",
            vec![(Some("tx2"), Some(1), Some(ADDR))],
            vec![
                (OTHER, 0, 200_000_000, "s4"),
                (ADDR, 1, 499_800_000, "s5"),
            ],
        );

        // Receive another 1 KRGN from someone else
        let tx4 = make_tx("tx4", vec![(None, None, None)], vec![
            (ADDR, 0, 100_000_000, "s6"),
        ]);

        state.process_transaction(&tx1, ADDR);
        state.process_transaction(&tx2, ADDR);
        state.process_transaction(&tx3, ADDR);
        state.process_transaction(&tx4, ADDR);

        let utxos = state.derive_utxos();
        assert_eq!(utxos.len(), 2); // tx3:1 change + tx4:0 receive

        let balance = state.balance();
        assert_eq!(balance, 499_800_000 + 100_000_000);
        assert_eq!(state.tx_count(), 4);
    }

    // -- Balance calculation --

    #[test]
    fn balance_empty() {
        let state = SyncState::new();
        assert_eq!(state.balance(), 0);
    }

    #[test]
    fn balance_accumulates() {
        let mut state = SyncState::new();

        for i in 0..5u32 {
            let tx = make_tx(&format!("tx{i}"), vec![(None, None, None)], vec![
                (ADDR, 0, (i as u64 + 1) * 10_000_000, "s"),
            ]);
            state.process_transaction(&tx, ADDR);
        }

        // 10 + 20 + 30 + 40 + 50 = 150M sat = 1.5 KRGN
        assert_eq!(state.balance(), 150_000_000);
    }

    // -- Idempotency: processing same tx twice --

    #[test]
    fn idempotent_processing() {
        let mut state = SyncState::new();

        let tx = make_tx("tx1", vec![(None, None, None)], vec![
            (ADDR, 0, 100_000_000, "s"),
        ]);

        state.process_transaction(&tx, ADDR);
        state.process_transaction(&tx, ADDR); // duplicate

        let utxos = state.derive_utxos();
        assert_eq!(utxos.len(), 1, "Duplicate processing should not create extra UTXOs");
        assert_eq!(state.balance(), 100_000_000);
    }

    // -- Outpoint equality --

    #[test]
    fn outpoint_eq_and_hash() {
        let a = Outpoint { txid: "abc".into(), vout: 0 };
        let b = Outpoint { txid: "abc".into(), vout: 0 };
        let c = Outpoint { txid: "abc".into(), vout: 1 };

        assert_eq!(a, b);
        assert_ne!(a, c);

        let mut set = HashSet::new();
        set.insert(a.clone());
        assert!(set.contains(&b));
        assert!(!set.contains(&c));
    }
}
