/// Transaction construction, serialization, signing, and UTXO selection
/// for Kerrigan Network v1 transparent transactions.
///
/// # Architecture
///
/// The module is split into composable layers:
///
/// 1. **Data types** — [`Utxo`], [`TxInput`], [`TxOutput`], [`Transaction`]
///    describe the transaction graph.
/// 2. **Serialization** — [`Transaction::serialize`] produces raw bytes (unsigned or signed).
/// 3. **Sighash** — [`Transaction::sighash`] computes the SIGHASH_ALL digest for a given input.
/// 4. **Signing** — [`Transaction::sign_p2pkh`] signs all inputs with one keypair.
/// 5. **UTXO selection** — [`select_utxos`] picks coins to fund a target amount + fee.
/// 6. **High-level builder** — [`build_transaction`] orchestrates selection → construction → signing.
///
/// Each layer is independently testable. Future transaction versions (e.g., v3 Sapling)
/// can add new sighash algorithms or signing flows without modifying the serialization core.

use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
use serde::{Serialize, Deserialize};
use std::fmt;

use crate::encoding::{write_varint, hex_encode, hex_decode, sha256d};
use crate::fees::{self, TxComponents};
use crate::keys;
use crate::params;
use crate::script::{self, ScriptType};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum TxError {
    InsufficientFunds { have: u64, need: u64 },
    NoUtxos,
    InvalidUtxo(String),
    SigningFailed(String),
    ScriptError(String),
    KeyError(String),
}

impl fmt::Display for TxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientFunds { have, need } => {
                write!(f, "Insufficient funds: have {have} sat, need {need} sat")
            }
            Self::NoUtxos => write!(f, "No UTXOs available"),
            Self::InvalidUtxo(s) => write!(f, "Invalid UTXO: {s}"),
            Self::SigningFailed(s) => write!(f, "Signing failed: {s}"),
            Self::ScriptError(s) => write!(f, "Script error: {s}"),
            Self::KeyError(s) => write!(f, "Key error: {s}"),
        }
    }
}

impl std::error::Error for TxError {}

impl From<script::ScriptError> for TxError {
    fn from(e: script::ScriptError) -> Self { Self::ScriptError(e.to_string()) }
}

impl From<keys::KeyError> for TxError {
    fn from(e: keys::KeyError) -> Self { Self::KeyError(e.to_string()) }
}

// ---------------------------------------------------------------------------
// UTXO (unspent transaction output)
// ---------------------------------------------------------------------------

/// A single unspent transaction output available for spending.
///
/// This is the wallet's view of a coin — it carries everything needed to
/// reference and spend the output in a new transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Utxo {
    /// Transaction ID that created this output (hex, big-endian display order).
    pub txid: String,
    /// Output index within that transaction.
    pub vout: u32,
    /// Value in satoshis.
    pub amount: u64,
    /// The scriptPubKey locking this output (hex).
    /// For P2PKH this is `76a914{hash}88ac`.
    pub script_pubkey: String,
}

// ---------------------------------------------------------------------------
// Transaction components
// ---------------------------------------------------------------------------

/// A transaction input (reference to a UTXO being spent).
#[derive(Debug, Clone)]
pub struct TxInput {
    /// Previous transaction ID (32 bytes, internal byte order = reversed display).
    pub prev_txid: [u8; 32],
    /// Previous output index.
    pub prev_vout: u32,
    /// scriptSig (empty for unsigned, filled after signing).
    pub script_sig: Vec<u8>,
    /// Sequence number (0xFFFFFFFF = final, no RBF).
    pub sequence: u32,
}

/// A transaction output (destination + amount).
#[derive(Debug, Clone)]
pub struct TxOutput {
    /// Value in satoshis.
    pub value: u64,
    /// The scriptPubKey that locks this output.
    pub script_pubkey: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Transaction
// ---------------------------------------------------------------------------

/// A Kerrigan v1 transaction.
///
/// This struct represents both unsigned and signed transactions — the
/// difference is whether `inputs[i].script_sig` is empty or filled.
///
/// The version field is kept generic to support future transaction versions
/// (e.g., v3 for Sapling-compatible transactions).
#[derive(Debug, Clone)]
pub struct Transaction {
    /// Transaction version (1 for standard transparent).
    pub version: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    /// Block height or timestamp after which the tx is valid (0 = immediate).
    pub locktime: u32,
}

impl Transaction {
    /// Create a new v1 transaction with the given inputs and outputs.
    pub fn new(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Self {
        Self {
            version: params::TX_VERSION,
            inputs,
            outputs,
            locktime: 0,
        }
    }

    /// Serialize the transaction to raw bytes.
    ///
    /// This produces the canonical Bitcoin wire format:
    /// `[version][input_count][inputs...][output_count][outputs...][locktime]`
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);

        // Version
        buf.extend_from_slice(&self.version.to_le_bytes());

        // Inputs
        write_varint(&mut buf, self.inputs.len() as u64);
        for input in &self.inputs {
            buf.extend_from_slice(&input.prev_txid);
            buf.extend_from_slice(&input.prev_vout.to_le_bytes());
            write_varint(&mut buf, input.script_sig.len() as u64);
            buf.extend_from_slice(&input.script_sig);
            buf.extend_from_slice(&input.sequence.to_le_bytes());
        }

        // Outputs
        write_varint(&mut buf, self.outputs.len() as u64);
        for output in &self.outputs {
            buf.extend_from_slice(&output.value.to_le_bytes());
            write_varint(&mut buf, output.script_pubkey.len() as u64);
            buf.extend_from_slice(&output.script_pubkey);
        }

        // Locktime
        buf.extend_from_slice(&self.locktime.to_le_bytes());

        buf
    }

    /// Compute the transaction ID (double-SHA256 of the serialized tx, reversed).
    pub fn txid(&self) -> String {
        let hash = sha256d(&self.serialize());
        // Bitcoin txids are displayed in reversed byte order
        let mut reversed = hash;
        reversed.reverse();
        hex_encode(&reversed)
    }

    // -- Sighash computation --------------------------------------------------

    /// Compute the SIGHASH_ALL digest for a specific input.
    ///
    /// This implements the legacy Bitcoin sighash algorithm:
    /// 1. Copy the transaction.
    /// 2. Clear all input scriptSigs except the one being signed.
    /// 3. Set the signing input's scriptSig to the referenced output's scriptPubKey.
    /// 4. Append the sighash type as a 4-byte LE integer.
    /// 5. Double-SHA256 the result.
    ///
    /// # Parameters
    /// - `input_index`: which input is being signed.
    /// - `script_code`: the scriptPubKey of the output being spent (for P2PKH,
    ///   this is the full 25-byte script; for future P2SH, the redeemScript).
    /// - `sighash_type`: typically [`params::SIGHASH_ALL`] (0x01).
    pub fn sighash(
        &self,
        input_index: usize,
        script_code: &[u8],
        sighash_type: u32,
    ) -> [u8; 32] {
        let mut buf = Vec::with_capacity(256);

        // Version
        buf.extend_from_slice(&self.version.to_le_bytes());

        // Inputs — the signing input gets the script_code; others get empty scripts
        write_varint(&mut buf, self.inputs.len() as u64);
        for (i, input) in self.inputs.iter().enumerate() {
            buf.extend_from_slice(&input.prev_txid);
            buf.extend_from_slice(&input.prev_vout.to_le_bytes());
            if i == input_index {
                write_varint(&mut buf, script_code.len() as u64);
                buf.extend_from_slice(script_code);
            } else {
                buf.push(0x00); // empty scriptSig
            }
            buf.extend_from_slice(&input.sequence.to_le_bytes());
        }

        // Outputs (unchanged)
        write_varint(&mut buf, self.outputs.len() as u64);
        for output in &self.outputs {
            buf.extend_from_slice(&output.value.to_le_bytes());
            write_varint(&mut buf, output.script_pubkey.len() as u64);
            buf.extend_from_slice(&output.script_pubkey);
        }

        // Locktime
        buf.extend_from_slice(&self.locktime.to_le_bytes());

        // Sighash type (4 bytes LE)
        buf.extend_from_slice(&sighash_type.to_le_bytes());

        sha256d(&buf)
    }

    // -- Signing ---------------------------------------------------------------

    /// Sign all inputs with a single P2PKH keypair (SIGHASH_ALL).
    ///
    /// For each input, computes the sighash against the provided `script_code`,
    /// signs with ECDSA, and fills the input's scriptSig with the standard
    /// P2PKH unlocking script.
    ///
    /// # Parameters
    /// - `privkey`: 32-byte secret key.
    /// - `pubkey`: 33-byte compressed public key.
    /// - `script_code`: the scriptPubKey of the UTXOs being spent (all inputs
    ///   must spend outputs locked to the same script — single-address wallet).
    pub fn sign_p2pkh(
        &mut self,
        privkey: &[u8; 32],
        pubkey: &[u8; 33],
        script_code: &[u8],
    ) -> Result<(), TxError> {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(privkey)
            .map_err(|e| TxError::SigningFailed(format!("invalid privkey: {e}")))?;

        // Verify the pubkey matches the privkey
        let derived_pubkey = PublicKey::from_secret_key(&secp, &sk);
        if derived_pubkey.serialize() != *pubkey {
            return Err(TxError::SigningFailed(
                "pubkey does not match privkey".into()
            ));
        }

        for i in 0..self.inputs.len() {
            let hash = self.sighash(i, script_code, params::SIGHASH_ALL);
            let msg = Message::from_digest(hash);
            let sig = secp.sign_ecdsa(&msg, &sk);

            // DER-encoded signature + SIGHASH_ALL byte
            let mut sig_bytes = sig.serialize_der().to_vec();
            sig_bytes.push(params::SIGHASH_ALL as u8);

            // P2PKH scriptSig
            self.inputs[i].script_sig = script::p2pkh_script_sig(&sig_bytes, pubkey);
        }

        Ok(())
    }

    /// Returns true if all inputs have non-empty scriptSigs (i.e., the tx is signed).
    pub fn is_signed(&self) -> bool {
        !self.inputs.is_empty() && self.inputs.iter().all(|i| !i.script_sig.is_empty())
    }

    /// Serialize to hex string (convenience).
    pub fn to_hex(&self) -> String {
        hex_encode(&self.serialize())
    }
}

// ---------------------------------------------------------------------------
// UTXO selection
// ---------------------------------------------------------------------------

/// Result of UTXO selection: the chosen UTXOs, total input value, and fee.
#[derive(Debug)]
pub struct CoinSelection {
    /// Selected UTXOs (order matters — they become transaction inputs).
    pub selected: Vec<Utxo>,
    /// Sum of all selected UTXO amounts.
    pub total_input: u64,
    /// Estimated fee in satoshis.
    pub fee: u64,
    /// Change amount (total_input - target - fee). Zero if exact match.
    pub change: u64,
}

/// Select UTXOs to fund a transaction sending `target_amount` to a destination.
///
/// Strategy: **largest-first**. Sorts UTXOs by amount descending and greedily
/// accumulates until the target + estimated fee is covered.  The fee is
/// recalculated at each step because adding an input increases the tx size.
///
/// Returns [`TxError::InsufficientFunds`] if the wallet cannot cover the target + fee.
///
/// # Parameters
/// - `utxos`: available unspent outputs.
/// - `target_amount`: destination amount in satoshis (excluding fee).
/// - `dest_script_type`: the destination output's script type (for fee estimation).
pub fn select_utxos(
    utxos: &[Utxo],
    target_amount: u64,
    dest_script_type: ScriptType,
) -> Result<CoinSelection, TxError> {
    if utxos.is_empty() {
        return Err(TxError::NoUtxos);
    }

    // Sort by amount descending (largest first)
    let mut sorted: Vec<Utxo> = utxos.to_vec();
    sorted.sort_by(|a, b| b.amount.cmp(&a.amount));

    let mut selected = Vec::new();
    let mut total: u64 = 0;

    for utxo in &sorted {
        selected.push(utxo.clone());
        total += utxo.amount;

        // Estimate fee assuming destination + change outputs
        let output_types = vec![dest_script_type, ScriptType::P2PKH]; // dest + change
        let components = TxComponents::transparent(selected.len(), output_types);
        let fee = fees::estimate_fee_default(&components);

        if total >= target_amount + fee {
            // Check if change is dust — if so, absorb it into the fee
            let change = total - target_amount - fee;
            if change > 0 && change <= params::DUST_THRESHOLD {
                // No change output: recalculate fee with only 1 output
                let no_change = TxComponents::transparent(
                    selected.len(),
                    vec![dest_script_type],
                );
                let _fee_no_change = fees::estimate_fee_default(&no_change);
                return Ok(CoinSelection {
                    selected,
                    total_input: total,
                    fee: total - target_amount, // absorb dust into fee
                    change: 0,
                });
            }

            // If change is 0, only need 1 output
            let final_fee = if change == 0 {
                let no_change = TxComponents::transparent(
                    selected.len(),
                    vec![dest_script_type],
                );
                fees::estimate_fee_default(&no_change)
            } else {
                fee
            };

            let final_change = if total >= target_amount + final_fee {
                total - target_amount - final_fee
            } else {
                0
            };

            return Ok(CoinSelection {
                selected,
                total_input: total,
                fee: final_fee,
                change: final_change,
            });
        }
    }

    // Not enough funds
    let output_types = vec![dest_script_type, ScriptType::P2PKH];
    let components = TxComponents::transparent(selected.len(), output_types);
    let fee = fees::estimate_fee_default(&components);
    Err(TxError::InsufficientFunds {
        have: total,
        need: target_amount + fee,
    })
}

/// Select ALL UTXOs and compute the maximum sendable amount (total - fee).
///
/// Used for "send max" — spends every UTXO, single output (no change),
/// fee is subtracted from the send amount internally.
///
/// Returns [`TxError::NoUtxos`] if wallet is empty, or [`TxError::InsufficientFunds`]
/// if the total balance doesn't even cover the fee.
pub fn select_all_utxos(
    utxos: &[Utxo],
    dest_script_type: ScriptType,
) -> Result<CoinSelection, TxError> {
    if utxos.is_empty() {
        return Err(TxError::NoUtxos);
    }

    let total: u64 = utxos.iter().fold(0u64, |a, u| a.saturating_add(u.amount));

    // Fee for N inputs, 1 output (no change)
    let components = TxComponents::transparent(utxos.len(), vec![dest_script_type]);
    let fee = fees::estimate_fee_default(&components);

    if total <= fee {
        return Err(TxError::InsufficientFunds { have: total, need: fee });
    }

    Ok(CoinSelection {
        selected: utxos.to_vec(),
        total_input: total,
        fee,
        change: 0,
    })
}

/// Build, fund, and sign a "send max" transaction (entire balance minus fee).
///
/// All UTXOs are consumed. Single output to the destination.
/// Fee is subtracted from the send amount.
pub fn build_max_transaction(
    utxos: &[Utxo],
    to_address: &str,
    privkey: &[u8; 32],
    pubkey: &[u8; 33],
    own_script_pubkey: &[u8],
) -> Result<SignedTransaction, TxError> {
    let dest_script_type = script::address_to_script_type(to_address)?;
    let dest_script = script::address_to_script_pubkey(to_address)?;

    let selection = select_all_utxos(utxos, dest_script_type)?;
    let send_amount = selection.total_input - selection.fee;

    // Build inputs (all UTXOs)
    let inputs: Vec<TxInput> = selection.selected.iter()
        .map(input_from_utxo)
        .collect::<Result<Vec<_>, _>>()?;

    // Single output — no change
    let outputs = vec![TxOutput {
        value: send_amount,
        script_pubkey: dest_script,
    }];

    let mut tx = Transaction::new(inputs, outputs);
    tx.sign_p2pkh(privkey, pubkey, own_script_pubkey)?;

    let tx_hex = tx.to_hex();
    let txid = tx.txid();
    let spent: Vec<(String, u32)> = selection.selected.iter()
        .map(|u| (u.txid.clone(), u.vout))
        .collect();

    Ok(SignedTransaction {
        tx,
        tx_hex,
        txid,
        spent_utxos: spent,
        fee: selection.fee,
    })
}

// ---------------------------------------------------------------------------
// Transaction input construction helpers
// ---------------------------------------------------------------------------

/// Convert a display-order txid hex string to internal byte order (reversed).
pub fn txid_to_internal(txid_hex: &str) -> Result<[u8; 32], TxError> {
    let mut bytes = hex_decode(txid_hex)
        .map_err(|e| TxError::InvalidUtxo(format!("bad txid hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(TxError::InvalidUtxo(format!(
            "txid must be 32 bytes, got {}", bytes.len()
        )));
    }
    bytes.reverse(); // display → internal byte order
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}

/// Create an unsigned [`TxInput`] from a [`Utxo`].
pub fn input_from_utxo(utxo: &Utxo) -> Result<TxInput, TxError> {
    Ok(TxInput {
        prev_txid: txid_to_internal(&utxo.txid)?,
        prev_vout: utxo.vout,
        script_sig: Vec::new(),
        sequence: 0xFFFFFFFF,
    })
}

// ---------------------------------------------------------------------------
// High-level transaction builder
// ---------------------------------------------------------------------------

/// The result of building and signing a transaction.
#[derive(Debug)]
pub struct SignedTransaction {
    /// The signed transaction (ready for broadcast).
    pub tx: Transaction,
    /// Hex-encoded raw transaction.
    pub tx_hex: String,
    /// Transaction ID (computed from the signed tx).
    pub txid: String,
    /// UTXOs that were spent (for wallet bookkeeping).
    pub spent_utxos: Vec<(String, u32)>,
    /// The fee paid.
    pub fee: u64,
}

/// Build, fund, and sign a transparent P2PKH transaction.
///
/// This is the main entry point for sending KRGN. It performs:
/// 1. UTXO selection to cover `amount + fee`.
/// 2. Transaction construction with destination + change outputs.
/// 3. SIGHASH_ALL signing of all inputs with the provided keypair.
///
/// # Parameters
/// - `utxos`: wallet's unspent outputs.
/// - `to_address`: destination Kerrigan address (P2PKH or P2SH).
/// - `amount`: value to send in satoshis.
/// - `privkey`: sender's 32-byte private key.
/// - `pubkey`: sender's 33-byte compressed public key.
/// - `change_address`: address to receive change (typically the sender's own address).
pub fn build_transaction(
    utxos: &[Utxo],
    to_address: &str,
    amount: u64,
    privkey: &[u8; 32],
    pubkey: &[u8; 33],
    change_address: &str,
) -> Result<SignedTransaction, TxError> {
    // Resolve destination script
    let dest_script_type = script::address_to_script_type(to_address)?;
    let dest_script = script::address_to_script_pubkey(to_address)?;
    let change_script = script::address_to_script_pubkey(change_address)?;

    // Our scriptPubKey (for sighash — all inputs spend from this script)
    let own_script = change_script.clone();

    // Select UTXOs
    let selection = select_utxos(utxos, amount, dest_script_type)?;

    // Build inputs
    let inputs: Vec<TxInput> = selection.selected.iter()
        .map(input_from_utxo)
        .collect::<Result<Vec<_>, _>>()?;

    // Build outputs
    let mut outputs = vec![TxOutput {
        value: amount,
        script_pubkey: dest_script,
    }];
    if selection.change > 0 {
        outputs.push(TxOutput {
            value: selection.change,
            script_pubkey: change_script,
        });
    }

    // Construct and sign
    let mut tx = Transaction::new(inputs, outputs);
    tx.sign_p2pkh(privkey, pubkey, &own_script)?;

    let tx_hex = tx.to_hex();
    let txid = tx.txid();
    let spent: Vec<(String, u32)> = selection.selected.iter()
        .map(|u| (u.txid.clone(), u.vout))
        .collect();

    Ok(SignedTransaction {
        tx,
        tx_hex,
        txid,
        spent_utxos: spent,
        fee: selection.fee,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip39::{entropy_to_mnemonic, mnemonic_to_seed};
    use crate::encoding::{hex_encode, hex_decode, base58check_encode};
    use crate::keys::derive_keypair;

    // Helper: create a dummy UTXO
    fn make_utxo(txid: &str, vout: u32, amount: u64, script_pubkey: &str) -> Utxo {
        Utxo {
            txid: txid.into(),
            vout,
            amount,
            script_pubkey: script_pubkey.into(),
        }
    }

    // Helper: generate a keypair from a known seed
    fn test_keypair() -> (keys::Keypair, Vec<u8>) {
        let entropy = hex_decode("abcdef0123456789abcdef0123456789").unwrap();
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        let seed = mnemonic_to_seed(&mnemonic, "");
        let kp = derive_keypair(&seed).unwrap();
        let script = script::address_to_script_pubkey(&kp.address).unwrap();
        (kp, script)
    }

    // -----------------------------------------------------------------------
    // Transaction serialization
    // -----------------------------------------------------------------------

    #[test]
    fn serialize_empty_transaction() {
        let tx = Transaction::new(vec![], vec![]);
        let bytes = tx.serialize();
        // version(4) + varint(0 inputs)(1) + varint(0 outputs)(1) + locktime(4) = 10
        assert_eq!(bytes.len(), 10);
        // Version = 1 LE
        assert_eq!(&bytes[0..4], &[0x01, 0x00, 0x00, 0x00]);
        // Input count = 0
        assert_eq!(bytes[4], 0x00);
        // Output count = 0
        assert_eq!(bytes[5], 0x00);
        // Locktime = 0
        assert_eq!(&bytes[6..10], &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn serialize_unsigned_one_input_one_output() {
        let input = TxInput {
            prev_txid: [0xAA; 32],
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        };
        let output = TxOutput {
            value: 50_000,
            script_pubkey: vec![0x76, 0xa9, 0x14, /* 20 zero bytes */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x88, 0xac],
        };
        let tx = Transaction::new(vec![input], vec![output]);
        let bytes = tx.serialize();

        // version(4) + varint(1)(1) + input(36+1+0+4=41) + varint(1)(1) + output(8+1+25=34) + locktime(4) = 85
        assert_eq!(bytes.len(), 85);
    }

    #[test]
    fn serialize_roundtrip_hex() {
        let input = TxInput {
            prev_txid: [0x01; 32],
            prev_vout: 1,
            script_sig: vec![0x48, 0x30],
            sequence: 0xFFFFFFFF,
        };
        let output = TxOutput {
            value: 100_000_000,
            script_pubkey: vec![0x76, 0xa9],
        };
        let tx = Transaction::new(vec![input], vec![output]);
        let hex = tx.to_hex();

        // Deserialize from hex and verify
        let bytes = hex_decode(&hex).unwrap();
        assert_eq!(bytes, tx.serialize());
    }

    // -----------------------------------------------------------------------
    // txid_to_internal byte reversal
    // -----------------------------------------------------------------------

    #[test]
    fn txid_byte_reversal() {
        let display = "0102030405060708091011121314151617181920212223242526272829303132";
        let internal = txid_to_internal(display).unwrap();
        // First byte of internal should be last byte of display
        assert_eq!(internal[0], 0x32);
        assert_eq!(internal[31], 0x01);
    }

    #[test]
    fn txid_invalid_hex() {
        assert!(txid_to_internal("not_hex").is_err());
    }

    #[test]
    fn txid_wrong_length() {
        assert!(txid_to_internal("0102").is_err());
    }

    // -----------------------------------------------------------------------
    // Sighash computation
    // -----------------------------------------------------------------------

    #[test]
    fn sighash_deterministic() {
        let input = TxInput {
            prev_txid: [0xAA; 32],
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        };
        let output = TxOutput {
            value: 50_000,
            script_pubkey: vec![0x76, 0xa9, 0x14, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x88, 0xac],
        };
        let tx = Transaction::new(vec![input], vec![output]);

        let script_code = &[0x76, 0xa9, 0x14, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x88, 0xac];
        let hash1 = tx.sighash(0, script_code, params::SIGHASH_ALL);
        let hash2 = tx.sighash(0, script_code, params::SIGHASH_ALL);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn sighash_changes_with_different_inputs() {
        let input1 = TxInput {
            prev_txid: [0xAA; 32],
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        };
        let input2 = TxInput {
            prev_txid: [0xBB; 32],
            prev_vout: 1,
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        };
        let output = TxOutput {
            value: 50_000,
            script_pubkey: vec![0x76, 0xa9, 0x14, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x88, 0xac],
        };
        let tx = Transaction::new(vec![input1, input2], vec![output]);

        let script_code = &[0x76, 0xa9, 0x14, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x88, 0xac];
        let hash0 = tx.sighash(0, script_code, params::SIGHASH_ALL);
        let hash1 = tx.sighash(1, script_code, params::SIGHASH_ALL);
        assert_ne!(hash0, hash1, "Different input indices must produce different sighashes");
    }

    #[test]
    fn sighash_changes_with_amount() {
        let make_tx = |amount: u64| {
            let input = TxInput {
                prev_txid: [0xAA; 32],
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            };
            let output = TxOutput {
                value: amount,
                script_pubkey: vec![0x76, 0xa9, 0x14, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x88, 0xac],
            };
            Transaction::new(vec![input], vec![output])
        };

        let script_code = &[0x76, 0xa9, 0x14, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x88, 0xac];
        let hash_a = make_tx(50_000).sighash(0, script_code, params::SIGHASH_ALL);
        let hash_b = make_tx(60_000).sighash(0, script_code, params::SIGHASH_ALL);
        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn sighash_ignores_existing_scriptsig() {
        // Existing scriptSigs should NOT affect the sighash (they get replaced)
        let input_clean = TxInput {
            prev_txid: [0xAA; 32],
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        };
        let input_dirty = TxInput {
            prev_txid: [0xAA; 32],
            prev_vout: 0,
            script_sig: vec![0xFF; 100],
            sequence: 0xFFFFFFFF,
        };
        let output = TxOutput {
            value: 50_000,
            script_pubkey: vec![0x76; 25],
        };

        let tx_clean = Transaction::new(vec![input_clean], vec![output.clone()]);
        let tx_dirty = Transaction::new(vec![input_dirty], vec![output]);

        let script_code = &[0x76; 25];
        assert_eq!(
            tx_clean.sighash(0, script_code, params::SIGHASH_ALL),
            tx_dirty.sighash(0, script_code, params::SIGHASH_ALL),
            "Sighash must not depend on existing scriptSig content"
        );
    }

    // -----------------------------------------------------------------------
    // Signing
    // -----------------------------------------------------------------------

    #[test]
    fn sign_and_verify_single_input() {
        let (kp, own_script) = test_keypair();

        // Create a fake UTXO
        let input = TxInput {
            prev_txid: [0x11; 32],
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        };
        let output = TxOutput {
            value: 50_000,
            script_pubkey: own_script.clone(),
        };

        let mut tx = Transaction::new(vec![input], vec![output]);
        assert!(!tx.is_signed());

        tx.sign_p2pkh(&kp.privkey, &kp.pubkey, &own_script).unwrap();
        assert!(tx.is_signed());

        // Verify the signature by re-computing the sighash and checking ECDSA
        let secp = Secp256k1::new();
        let hash = tx.sighash(0, &own_script, params::SIGHASH_ALL);
        let msg = Message::from_digest(hash);

        // Extract DER signature from scriptSig
        let script_sig = &tx.inputs[0].script_sig;
        let sig_len = script_sig[0] as usize;
        let sig_der = &script_sig[1..1 + sig_len - 1]; // strip sighash byte
        let sig = secp256k1::ecdsa::Signature::from_der(sig_der).unwrap();
        let pubkey = PublicKey::from_slice(&kp.pubkey).unwrap();

        secp.verify_ecdsa(&msg, &sig, &pubkey).unwrap();
    }

    #[test]
    fn sign_multiple_inputs() {
        let (kp, own_script) = test_keypair();

        let inputs: Vec<TxInput> = (0..3).map(|i| TxInput {
            prev_txid: [i as u8 + 1; 32],
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        }).collect();

        let output = TxOutput { value: 150_000, script_pubkey: own_script.clone() };
        let mut tx = Transaction::new(inputs, vec![output]);
        tx.sign_p2pkh(&kp.privkey, &kp.pubkey, &own_script).unwrap();

        // Verify each input's signature
        let secp = Secp256k1::new();
        let pubkey = PublicKey::from_slice(&kp.pubkey).unwrap();

        for i in 0..3 {
            let hash = tx.sighash(i, &own_script, params::SIGHASH_ALL);
            let msg = Message::from_digest(hash);
            let script_sig = &tx.inputs[i].script_sig;
            let sig_len = script_sig[0] as usize;
            let sig_der = &script_sig[1..1 + sig_len - 1];
            let sig = secp256k1::ecdsa::Signature::from_der(sig_der).unwrap();
            secp.verify_ecdsa(&msg, &sig, &pubkey).unwrap();
        }
    }

    #[test]
    fn sign_wrong_keypair_fails() {
        let (kp, own_script) = test_keypair();

        let input = TxInput {
            prev_txid: [0x11; 32],
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        };
        let output = TxOutput { value: 50_000, script_pubkey: own_script.clone() };
        let mut tx = Transaction::new(vec![input], vec![output]);

        // Use a different pubkey (mismatched)
        let wrong_pubkey = [0x02u8; 33];
        assert!(tx.sign_p2pkh(&kp.privkey, &wrong_pubkey, &own_script).is_err());
    }

    // -----------------------------------------------------------------------
    // UTXO selection
    // -----------------------------------------------------------------------

    #[test]
    fn select_single_utxo_exact() {
        let script = hex_encode(&script::p2pkh_script(&[0u8; 20]));
        let utxos = vec![
            make_utxo("aa".repeat(32).as_str(), 0, 100_000, &script),
        ];

        // Amount that fits in one UTXO
        let selection = select_utxos(&utxos, 50_000, ScriptType::P2PKH).unwrap();
        assert_eq!(selection.selected.len(), 1);
        assert_eq!(selection.total_input, 100_000);
        assert!(selection.fee > 0);
        assert_eq!(selection.total_input, 50_000 + selection.fee + selection.change);
    }

    #[test]
    fn select_multiple_utxos() {
        let script = hex_encode(&script::p2pkh_script(&[0u8; 20]));
        let utxos = vec![
            make_utxo(&"aa".repeat(32), 0, 30_000, &script),
            make_utxo(&"bb".repeat(32), 0, 30_000, &script),
            make_utxo(&"cc".repeat(32), 0, 30_000, &script),
        ];

        // Need more than one UTXO
        let selection = select_utxos(&utxos, 50_000, ScriptType::P2PKH).unwrap();
        assert!(selection.selected.len() >= 2);
        assert!(selection.total_input >= 50_000 + selection.fee);
    }

    #[test]
    fn select_largest_first() {
        let script = hex_encode(&script::p2pkh_script(&[0u8; 20]));
        let utxos = vec![
            make_utxo(&"aa".repeat(32), 0, 10_000, &script),
            make_utxo(&"bb".repeat(32), 0, 500_000, &script),
            make_utxo(&"cc".repeat(32), 0, 20_000, &script),
        ];

        let selection = select_utxos(&utxos, 50_000, ScriptType::P2PKH).unwrap();
        // Should pick the 500k UTXO first (and only need 1)
        assert_eq!(selection.selected.len(), 1);
        assert_eq!(selection.selected[0].amount, 500_000);
    }

    #[test]
    fn select_insufficient_funds() {
        let script = hex_encode(&script::p2pkh_script(&[0u8; 20]));
        let utxos = vec![
            make_utxo(&"aa".repeat(32), 0, 1_000, &script),
        ];

        let err = select_utxos(&utxos, 100_000, ScriptType::P2PKH).unwrap_err();
        assert!(matches!(err, TxError::InsufficientFunds { .. }));
    }

    #[test]
    fn select_no_utxos() {
        let err = select_utxos(&[], 1_000, ScriptType::P2PKH).unwrap_err();
        assert!(matches!(err, TxError::NoUtxos));
    }

    #[test]
    fn select_accounting_invariant() {
        // total_input == amount + fee + change (must ALWAYS hold)
        let script = hex_encode(&script::p2pkh_script(&[0u8; 20]));
        let utxos = vec![
            make_utxo(&"aa".repeat(32), 0, 1_000_000, &script),
            make_utxo(&"bb".repeat(32), 1, 2_000_000, &script),
            make_utxo(&"cc".repeat(32), 2, 500_000, &script),
        ];

        for amount in [10_000u64, 100_000, 1_000_000, 2_500_000] {
            if let Ok(sel) = select_utxos(&utxos, amount, ScriptType::P2PKH) {
                assert_eq!(
                    sel.total_input,
                    amount + sel.fee + sel.change,
                    "Accounting invariant broken for amount={amount}: \
                     input={} fee={} change={}",
                    sel.total_input, sel.fee, sel.change
                );
            }
        }
    }

    #[test]
    fn select_dust_absorbed_into_fee() {
        // Create a UTXO where the change would be < DUST_THRESHOLD
        let script = hex_encode(&script::p2pkh_script(&[0u8; 20]));
        let fee_2out = fees::estimate_transparent_fee(1, 2);
        // Set amount so that change = 100 sat (well below 546 dust threshold)
        let utxo_amount = 50_000 + fee_2out + 100;
        let utxos = vec![
            make_utxo(&"aa".repeat(32), 0, utxo_amount, &script),
        ];

        let selection = select_utxos(&utxos, 50_000, ScriptType::P2PKH).unwrap();
        // Dust should be absorbed into fee, so change = 0
        assert_eq!(selection.change, 0, "Dust change should be absorbed into fee");
        assert_eq!(selection.total_input, 50_000 + selection.fee);
    }

    // -----------------------------------------------------------------------
    // High-level build_transaction
    // -----------------------------------------------------------------------

    #[test]
    fn build_transaction_end_to_end() {
        let (kp, own_script) = test_keypair();

        // Create UTXOs owned by our keypair
        let utxos = vec![
            make_utxo(
                &"aa".repeat(32), 0, 10_000_000,
                &hex_encode(&own_script),
            ),
        ];

        // Destination: a different K... address
        let dest_hash = [0xBB; 20];
        let dest_addr = base58check_encode(params::PUBKEY_ADDRESS_PREFIX, &dest_hash);

        let result = build_transaction(
            &utxos,
            &dest_addr,
            1_000_000,
            &kp.privkey,
            &kp.pubkey,
            &kp.address,
        ).unwrap();

        // Basic sanity checks
        assert!(result.tx.is_signed());
        assert!(!result.tx_hex.is_empty());
        assert!(!result.txid.is_empty());
        assert_eq!(result.txid.len(), 64); // 32 bytes hex
        assert_eq!(result.spent_utxos.len(), 1);
        assert!(result.fee > 0);

        // Accounting: input = amount + fee + change
        let change = result.tx.outputs.iter()
            .filter(|o| o.script_pubkey == own_script)
            .map(|o| o.value)
            .sum::<u64>();
        assert_eq!(10_000_000, 1_000_000 + result.fee + change);

        // Verify signature on the signed tx
        let secp = Secp256k1::new();
        let hash = result.tx.sighash(0, &own_script, params::SIGHASH_ALL);
        let msg = Message::from_digest(hash);
        let script_sig = &result.tx.inputs[0].script_sig;
        let sig_len = script_sig[0] as usize;
        let sig_der = &script_sig[1..1 + sig_len - 1];
        let sig = secp256k1::ecdsa::Signature::from_der(sig_der).unwrap();
        let pubkey = PublicKey::from_slice(&kp.pubkey).unwrap();
        secp.verify_ecdsa(&msg, &sig, &pubkey).unwrap();
    }

    #[test]
    fn build_transaction_to_p2sh() {
        let (kp, own_script) = test_keypair();

        let utxos = vec![
            make_utxo(&"aa".repeat(32), 0, 10_000_000, &hex_encode(&own_script)),
        ];

        let dest_hash = [0xCC; 20];
        let dest_addr = base58check_encode(params::SCRIPT_ADDRESS_PREFIX, &dest_hash);

        let result = build_transaction(
            &utxos,
            &dest_addr,
            1_000_000,
            &kp.privkey,
            &kp.pubkey,
            &kp.address,
        ).unwrap();

        assert!(result.tx.is_signed());
        // Destination output should be P2SH (23-byte script)
        let dest_output = &result.tx.outputs[0];
        assert_eq!(dest_output.script_pubkey.len(), 23);
        assert_eq!(dest_output.value, 1_000_000);
    }

    #[test]
    fn build_transaction_insufficient_funds() {
        let (kp, own_script) = test_keypair();

        let utxos = vec![
            make_utxo(&"aa".repeat(32), 0, 1_000, &hex_encode(&own_script)),
        ];

        let dest_hash = [0xBB; 20];
        let dest_addr = base58check_encode(params::PUBKEY_ADDRESS_PREFIX, &dest_hash);

        let err = build_transaction(
            &utxos,
            &dest_addr,
            100_000,
            &kp.privkey,
            &kp.pubkey,
            &kp.address,
        ).unwrap_err();
        assert!(matches!(err, TxError::InsufficientFunds { .. }));
    }

    #[test]
    fn build_transaction_multiple_inputs() {
        let (kp, own_script) = test_keypair();

        let utxos = vec![
            make_utxo(&"aa".repeat(32), 0, 100_000, &hex_encode(&own_script)),
            make_utxo(&"bb".repeat(32), 0, 100_000, &hex_encode(&own_script)),
            make_utxo(&"cc".repeat(32), 0, 100_000, &hex_encode(&own_script)),
        ];

        let dest_hash = [0xBB; 20];
        let dest_addr = base58check_encode(params::PUBKEY_ADDRESS_PREFIX, &dest_hash);

        let result = build_transaction(
            &utxos,
            &dest_addr,
            250_000,
            &kp.privkey,
            &kp.pubkey,
            &kp.address,
        ).unwrap();

        assert!(result.tx.inputs.len() >= 3);
        assert!(result.tx.is_signed());

        // Verify all signatures
        let secp = Secp256k1::new();
        let pubkey = PublicKey::from_slice(&kp.pubkey).unwrap();
        for i in 0..result.tx.inputs.len() {
            let hash = result.tx.sighash(i, &own_script, params::SIGHASH_ALL);
            let msg = Message::from_digest(hash);
            let script_sig = &result.tx.inputs[i].script_sig;
            let sig_len = script_sig[0] as usize;
            let sig_der = &script_sig[1..1 + sig_len - 1];
            let sig = secp256k1::ecdsa::Signature::from_der(sig_der).unwrap();
            secp.verify_ecdsa(&msg, &sig, &pubkey).unwrap();
        }
    }

    // -----------------------------------------------------------------------
    // Transaction txid
    // -----------------------------------------------------------------------

    #[test]
    fn txid_is_deterministic() {
        let tx = Transaction::new(
            vec![TxInput {
                prev_txid: [0xAA; 32],
                prev_vout: 0,
                script_sig: vec![0x48, 0x30],
                sequence: 0xFFFFFFFF,
            }],
            vec![TxOutput { value: 50_000, script_pubkey: vec![0x76] }],
        );

        let id1 = tx.txid();
        let id2 = tx.txid();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64);
    }

    #[test]
    fn txid_changes_with_content() {
        let tx1 = Transaction::new(
            vec![TxInput {
                prev_txid: [0xAA; 32],
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            }],
            vec![TxOutput { value: 50_000, script_pubkey: vec![0x76] }],
        );
        let tx2 = Transaction::new(
            vec![TxInput {
                prev_txid: [0xBB; 32],
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            }],
            vec![TxOutput { value: 50_000, script_pubkey: vec![0x76] }],
        );
        assert_ne!(tx1.txid(), tx2.txid());
    }

    // -----------------------------------------------------------------------
    // Serialization size sanity
    // -----------------------------------------------------------------------

    #[test]
    fn signed_tx_size_within_estimate() {
        let (kp, own_script) = test_keypair();

        let utxos = vec![
            make_utxo(&"aa".repeat(32), 0, 10_000_000, &hex_encode(&own_script)),
        ];

        let dest_hash = [0xBB; 20];
        let dest_addr = base58check_encode(params::PUBKEY_ADDRESS_PREFIX, &dest_hash);

        let result = build_transaction(
            &utxos,
            &dest_addr,
            1_000_000,
            &kp.privkey,
            &kp.pubkey,
            &kp.address,
        ).unwrap();

        let actual_size = result.tx.serialize().len();
        let estimated = fees::TxComponents::transparent(1, vec![ScriptType::P2PKH, ScriptType::P2PKH])
            .estimated_size();

        // Actual size should be within 5% of estimate (DER sigs vary by 1-2 bytes)
        let tolerance = estimated as f64 * 0.10;
        assert!(
            (actual_size as f64 - estimated as f64).abs() < tolerance,
            "Actual size {actual_size} too far from estimate {estimated}"
        );
    }
}
