/// Sapling note types, decryption, and transaction processing.
///
/// Processes raw Sapling transaction bytes: parses the bundle, attempts to
/// decrypt outputs with a viewing key, updates the commitment tree and
/// witnesses, and derives nullifiers for spent notes.

use std::io::Cursor;

use sapling::note::Rseed;
use sapling::note_encryption::PreparedIncomingViewingKey;
use sapling::value::NoteValue;
use sapling::zip32::ExtendedFullViewingKey;
use sapling::{Node, Note, NullifierDerivingKey};
use serde::{Deserialize, Serialize};
use zcash_note_encryption::try_note_decryption;
use pivx_primitives::consensus::BranchId;
use pivx_primitives::transaction::Transaction;

use crate::encoding;
use super::keys;
use super::tree::{
    self, SaplingTree, SaplingWitness, advance_witness, append_node, witness_from_tree,
};

// ---------------------------------------------------------------------------
// Note types
// ---------------------------------------------------------------------------

/// A Sapling note we can spend — in-memory representation with live witness.
pub struct SpendableNote {
    /// The decrypted Sapling note (value, recipient, rcm).
    pub note: Note,
    /// Incremental Merkle witness tracking this note's path to the root.
    pub witness: SaplingWitness,
    /// Hex-encoded nullifier (marks this note as spent when broadcast).
    pub nullifier: String,
    /// Decoded memo field, if any.
    pub memo: Option<String>,
    /// Block height at which this note was received.
    pub height: u32,
}

/// Serializable note for persistent storage (JSON/hex-friendly).
///
/// The sapling-crypto `Note` type doesn't implement serde, so we store
/// its components as primitives: value (u64), recipient (bech32 address),
/// and rseed (hex bytes + ZIP 212 flag).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedNote {
    /// Note value in satoshis.
    pub value: u64,
    /// Bech32-encoded recipient payment address (`ks1...`).
    pub recipient: String,
    /// Hex-encoded note randomness seed (32 bytes).
    pub rseed: String,
    /// `true` = Rseed::AfterZip212 (Kerrigan default), `false` = BeforeZip212.
    pub rseed_after_zip212: bool,
    /// Hex-encoded incremental witness.
    pub witness: String,
    /// Hex-encoded nullifier.
    pub nullifier: String,
    /// Decoded memo text, if present.
    pub memo: Option<String>,
    /// Block height at which this note was received.
    #[serde(default)]
    pub height: u32,
}

// ---------------------------------------------------------------------------
// Conversion: SpendableNote ↔ SerializedNote
// ---------------------------------------------------------------------------

impl SpendableNote {
    /// Deserialize from storage format.
    pub fn from_serialized(n: &SerializedNote) -> Result<Self, SaplingNoteError> {
        // Reconstruct PaymentAddress from bech32
        let recipient = keys::decode_payment_address(&n.recipient)
            .map_err(|e| SaplingNoteError::Serialization(format!("recipient: {e}")))?;

        // Reconstruct rseed
        let rseed_bytes = encoding::hex_decode(&n.rseed)
            .map_err(|e| SaplingNoteError::Serialization(format!("rseed hex: {e}")))?;
        let rseed_array: [u8; 32] = rseed_bytes
            .try_into()
            .map_err(|_| SaplingNoteError::Serialization("rseed must be 32 bytes".into()))?;

        let rseed = if n.rseed_after_zip212 {
            Rseed::AfterZip212(rseed_array)
        } else {
            Rseed::BeforeZip212(
                jubjub::Fr::from_bytes(&rseed_array)
                    .into_option()
                    .ok_or(SaplingNoteError::Serialization(
                        "invalid BeforeZip212 rseed scalar".into(),
                    ))?,
            )
        };

        // Reconstruct note
        let note = Note::from_parts(recipient, NoteValue::from_raw(n.value), rseed);

        // Reconstruct witness
        let witness = tree::read_witness_hex(&n.witness)
            .map_err(|e| SaplingNoteError::Serialization(format!("witness: {e}")))?;

        Ok(Self {
            note,
            witness,
            nullifier: n.nullifier.clone(),
            memo: n.memo.clone(),
            height: n.height,
        })
    }

    /// Serialize to storage format.
    pub fn to_serialized(&self) -> Result<SerializedNote, SaplingNoteError> {
        let recipient = keys::encode_payment_address(&self.note.recipient());

        let (rseed_bytes, rseed_after_zip212) = match self.note.rseed() {
            Rseed::BeforeZip212(fr) => (fr.to_bytes(), false),
            Rseed::AfterZip212(bytes) => (*bytes, true),
        };

        let witness_hex = tree::write_witness_hex(&self.witness)
            .map_err(|e| SaplingNoteError::Serialization(format!("witness: {e}")))?;

        Ok(SerializedNote {
            value: self.note.value().inner(),
            recipient,
            rseed: encoding::hex_encode(&rseed_bytes),
            rseed_after_zip212,
            witness: witness_hex,
            nullifier: self.nullifier.clone(),
            memo: self.memo.clone(),
            height: self.height,
        })
    }
}

// ---------------------------------------------------------------------------
// Nullifier derivation
// ---------------------------------------------------------------------------

/// Derive a nullifier for a note at its current witness position.
pub fn get_nullifier(
    nk: &NullifierDerivingKey,
    note: &Note,
    witness: &SaplingWitness,
) -> Result<String, SaplingNoteError> {
    let path = witness.path().ok_or(SaplingNoteError::WitnessPathMissing)?;
    let nf = note.nf(nk, path.position().into());
    Ok(encoding::hex_encode(&nf.0))
}

// ---------------------------------------------------------------------------
// Transaction processing
// ---------------------------------------------------------------------------

/// Result of processing a single Sapling transaction.
pub struct TxProcessResult {
    /// Nullifiers found in the transaction's Sapling spends (marks notes as spent).
    pub spent_nullifiers: Vec<String>,
    /// Newly decrypted notes belonging to our viewing key.
    pub new_notes: Vec<SpendableNote>,
}

/// Process a single Sapling transaction against the commitment tree.
///
/// 1. Parses the transaction from raw bytes.
/// 2. Extracts spent nullifiers from Sapling spends.
/// 3. For each Sapling output:
///    a. Appends the CMU to the commitment tree.
///    b. Advances all existing witness Merkle paths.
///    c. Attempts decryption with the incoming viewing key.
///    d. On success: creates a witness snapshot and derives the nullifier.
///
/// The caller is responsible for persisting the updated tree and witnesses.
pub fn process_sapling_transaction(
    tree: &mut SaplingTree,
    tx_bytes: &[u8],
    extfvk: &ExtendedFullViewingKey,
    nk: &NullifierDerivingKey,
    existing_witnesses: &mut Vec<SpendableNote>,
    block_height: u32,
) -> Result<TxProcessResult, SaplingNoteError> {
    // Parse the transaction
    let tx = Transaction::read(Cursor::new(tx_bytes), BranchId::Sapling)
        .map_err(|e| SaplingNoteError::TxParse(format!("{e}")))?;

    let mut spent_nullifiers = Vec::new();
    let mut new_notes = Vec::new();

    let bundle = match tx.sapling_bundle() {
        Some(b) => b,
        None => return Ok(TxProcessResult { spent_nullifiers, new_notes }),
    };

    // Collect spent nullifiers
    for spend in bundle.shielded_spends() {
        spent_nullifiers.push(encoding::hex_encode(&spend.nullifier().0));
    }

    // Prepare incoming viewing key for decryption
    let ivk = PreparedIncomingViewingKey::new(&extfvk.fvk.vk.ivk());

    // Process each shielded output
    for output in bundle.shielded_outputs() {
        let cmu_node = Node::from_cmu(output.cmu());

        // 1. Append CMU to the commitment tree
        append_node(tree, cmu_node)
            .map_err(|e| SaplingNoteError::Tree(e.to_string()))?;

        // 2. Advance all existing witnesses (ours and newly found in this tx)
        for existing in existing_witnesses.iter_mut() {
            advance_witness(&mut existing.witness, cmu_node)
                .map_err(|e| SaplingNoteError::Tree(e.to_string()))?;
        }
        for new in new_notes.iter_mut() {
            advance_witness(&mut new.witness, cmu_node)
                .map_err(|e| SaplingNoteError::Tree(e.to_string()))?;
        }

        // 3. Try to decrypt this output
        let domain = sapling::note_encryption::SaplingDomain::new(
            sapling::note_encryption::Zip212Enforcement::On,
        );

        if let Some((note, _recipient, memo_bytes)) =
            try_note_decryption(&domain, &ivk, output)
        {
            // Create witness at current tree state
            let witness = witness_from_tree(tree)
                .ok_or(SaplingNoteError::Tree("empty tree after append".into()))?;

            // Derive nullifier
            let nullifier = get_nullifier(nk, &note, &witness)?;

            // Decode memo
            let memo = decode_memo(&memo_bytes);

            new_notes.push(SpendableNote {
                note,
                witness,
                nullifier,
                memo,
                height: block_height,
            });
        }
    }

    Ok(TxProcessResult { spent_nullifiers, new_notes })
}

// ---------------------------------------------------------------------------
// Block-level batch processing
// ---------------------------------------------------------------------------

/// A block containing raw Sapling transactions.
pub struct ShieldBlock {
    /// Block height.
    pub height: u32,
    /// Raw serialized Sapling transactions.
    pub txs: Vec<Vec<u8>>,
}

/// Result of processing a batch of shield blocks.
pub struct HandleBlocksResult {
    /// Updated commitment tree (hex).
    pub commitment_tree: String,
    /// Newly decrypted notes from this batch.
    pub new_notes: Vec<SerializedNote>,
    /// Previously known notes with updated witness paths.
    pub updated_notes: Vec<SerializedNote>,
    /// Nullifiers found in transaction spends (spent notes).
    pub spent_nullifiers: Vec<String>,
}

/// Process a batch of shield blocks against the wallet state.
///
/// This is the main entry point for Sapling sync. The caller provides:
/// - The current commitment tree (hex, or empty string for genesis)
/// - The blocks with raw Sapling transactions
/// - The viewing key and nullifier key
/// - Previously found notes (will have their witnesses updated)
///
/// Returns the updated state ready for persistence.
pub fn handle_blocks(
    tree_hex: &str,
    blocks: &[ShieldBlock],
    extfvk: &ExtendedFullViewingKey,
    nk: &NullifierDerivingKey,
    existing_notes: &[SerializedNote],
) -> Result<HandleBlocksResult, SaplingNoteError> {
    // Load tree
    let mut tree = if tree_hex.is_empty() {
        tree::empty_tree()
    } else {
        tree::read_tree_hex(tree_hex)
            .map_err(|e| SaplingNoteError::Tree(e.to_string()))?
    };

    // Load existing notes into in-memory form
    let mut existing: Vec<SpendableNote> = existing_notes
        .iter()
        .map(SpendableNote::from_serialized)
        .collect::<Result<Vec<_>, _>>()?;

    let mut all_new: Vec<SpendableNote> = Vec::new();
    let mut all_nullifiers: Vec<String> = Vec::new();

    // Process each block
    for block in blocks {
        for tx_bytes in &block.txs {
            let result = process_sapling_transaction(
                &mut tree,
                tx_bytes,
                extfvk,
                nk,
                &mut existing,
                block.height,
            )?;

            all_nullifiers.extend(result.spent_nullifiers);
            all_new.extend(result.new_notes);
        }
    }

    // Serialize back to storage
    let commitment_tree = tree::write_tree_hex(&tree)
        .map_err(|e| SaplingNoteError::Tree(e.to_string()))?;

    let updated_notes: Vec<SerializedNote> = existing
        .into_iter()
        .map(|n| n.to_serialized())
        .collect::<Result<Vec<_>, _>>()?;

    let new_notes: Vec<SerializedNote> = all_new
        .into_iter()
        .map(|n| n.to_serialized())
        .collect::<Result<Vec<_>, _>>()?;

    Ok(HandleBlocksResult {
        commitment_tree,
        new_notes,
        updated_notes,
        spent_nullifiers: all_nullifiers,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decode a Sapling memo field to an optional string.
fn decode_memo(memo_bytes: &[u8; 512]) -> Option<String> {
    // Skip if memo is all zeros (empty).
    if memo_bytes.iter().all(|&b| b == 0) {
        return None;
    }
    // First byte 0xF6 = empty memo marker per ZIP 302.
    if memo_bytes[0] == 0xF6 {
        return None;
    }
    // Try to interpret as UTF-8 text (strip trailing zeros).
    let end = memo_bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    String::from_utf8(memo_bytes[..end].to_vec()).ok()
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum SaplingNoteError {
    TxParse(String),
    Tree(String),
    WitnessPathMissing,
    Serialization(String),
}

impl std::fmt::Display for SaplingNoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TxParse(e) => write!(f, "Sapling transaction parse error: {e}"),
            Self::Tree(e) => write!(f, "Sapling tree error: {e}"),
            Self::WitnessPathMissing => write!(f, "witness has no Merkle path"),
            Self::Serialization(e) => write!(f, "serialization error: {e}"),
        }
    }
}

impl std::error::Error for SaplingNoteError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seed() -> [u8; 64] {
        [0u8; 64]
    }

    fn test_keys() -> (ExtendedFullViewingKey, NullifierDerivingKey) {
        let extsk = keys::default_spending_key(&test_seed()).unwrap();
        let extfvk = keys::full_viewing_key(&extsk);
        let nk = keys::nullifier_deriving_key(&extfvk);
        (extfvk, nk)
    }

    #[test]
    fn serialized_note_roundtrip_json() {
        let note = SerializedNote {
            value: 100_000,
            recipient: "ks1test".to_string(),
            rseed: "ab".repeat(32),
            rseed_after_zip212: true,
            witness: "deadbeef".to_string(),
            nullifier: "0123456789abcdef".to_string(),
            memo: Some("For the Swarm!".to_string()),
            height: 1000,
        };

        let json = serde_json::to_string(&note).unwrap();
        let restored: SerializedNote = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.value, note.value);
        assert_eq!(restored.recipient, note.recipient);
        assert_eq!(restored.nullifier, note.nullifier);
        assert_eq!(restored.memo, note.memo);
        assert_eq!(restored.height, note.height);
        assert_eq!(restored.rseed_after_zip212, true);
    }

    #[test]
    fn serialized_note_default_height() {
        let json = r#"{"value":0,"recipient":"","rseed":"","rseed_after_zip212":true,"witness":"","nullifier":"","memo":null}"#;
        let note: SerializedNote = serde_json::from_str(json).unwrap();
        assert_eq!(note.height, 0);
    }

    #[test]
    fn decode_memo_empty_zeros() {
        let memo = [0u8; 512];
        assert!(decode_memo(&memo).is_none());
    }

    #[test]
    fn decode_memo_f6_marker() {
        let mut memo = [0u8; 512];
        memo[0] = 0xF6;
        assert!(decode_memo(&memo).is_none());
    }

    #[test]
    fn decode_memo_text() {
        let mut memo = [0u8; 512];
        let text = b"For the Swarm!";
        memo[..text.len()].copy_from_slice(text);
        assert_eq!(decode_memo(&memo), Some("For the Swarm!".to_string()));
    }

    #[test]
    fn decode_memo_invalid_utf8_returns_none() {
        let mut memo = [0u8; 512];
        memo[0] = 0xFF;
        memo[1] = 0xFE;
        assert!(decode_memo(&memo).is_none());
    }

    #[test]
    fn handle_blocks_empty() {
        let (extfvk, nk) = test_keys();
        let result = handle_blocks("", &[], &extfvk, &nk, &[]).unwrap();
        assert!(result.new_notes.is_empty());
        assert!(result.updated_notes.is_empty());
        assert!(result.spent_nullifiers.is_empty());
        assert!(!result.commitment_tree.is_empty());
    }

    #[test]
    fn handle_blocks_no_txs() {
        let (extfvk, nk) = test_keys();
        let blocks = vec![ShieldBlock { height: 500, txs: vec![] }];
        let result = handle_blocks("", &blocks, &extfvk, &nk, &[]).unwrap();
        assert!(result.new_notes.is_empty());
        assert!(!result.commitment_tree.is_empty());
    }

    #[test]
    fn handle_blocks_preserves_tree_state() {
        let (extfvk, nk) = test_keys();

        // First call — get initial tree state.
        let r1 = handle_blocks("", &[], &extfvk, &nk, &[]).unwrap();
        let tree1 = &r1.commitment_tree;

        // Second call with same tree — should produce identical state.
        let r2 = handle_blocks(tree1, &[], &extfvk, &nk, &[]).unwrap();
        assert_eq!(r1.commitment_tree, r2.commitment_tree);
    }
}
