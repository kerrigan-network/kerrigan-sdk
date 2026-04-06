/// Sapling transaction builder for the Kerrigan Network.
///
/// Constructs signed Sapling transactions for three scenarios:
/// - **Shield-to-shield**: spend sapling notes → sapling output(s)
/// - **Shielding**: transparent UTXOs → sapling output
/// - **Unshielding**: sapling notes → transparent output
///
/// The SDK builds the transaction; the caller broadcasts it.

use rand_core::OsRng;
use sapling::zip32::ExtendedSpendingKey;
use sapling::{Anchor, PaymentAddress};
use pivx_primitives::consensus::BlockHeight;
use pivx_primitives::memo::MemoBytes;
use pivx_primitives::transaction::builder::{BuildConfig, Builder};
use pivx_primitives::transaction::components::transparent::builder::TransparentSigningSet;
use pivx_primitives::transaction::fees::fixed::FeeRule;
use pivx_primitives::zip32::Scope;
use pivx_protocol::memo::Memo;
use pivx_protocol::value::Zatoshis;
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::bundle::{OutPoint, TxOut};

use crate::encoding;
use crate::transaction::Utxo;
use super::fees;
use super::network::KerriganMainNetwork;
use super::notes::SpendableNote;
use super::prover::SaplingProver;

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// Result of building a Sapling transaction.
#[derive(Debug)]
pub struct SaplingTxResult {
    /// Hex-encoded signed transaction, ready to broadcast.
    pub tx_hex: String,
    /// Hex-encoded nullifiers of spent notes (mark as spent locally).
    pub nullifiers: Vec<String>,
    /// Amount sent (excluding fee) in satoshis.
    pub amount: u64,
    /// Fee paid in satoshis.
    pub fee: u64,
}

// ---------------------------------------------------------------------------
// Shield-to-shield send
// ---------------------------------------------------------------------------

/// Build a Sapling shield-to-shield transaction.
///
/// Spends one or more shielded notes and creates a shielded output to the
/// recipient, plus a change output back to the sender.
///
/// Notes are selected in order. The fee is recalculated as each note
/// is added (since more spends = higher fee).
pub fn build_sapling_send(
    notes: &[SpendableNote],
    extsk: &ExtendedSpendingKey,
    to: &PaymentAddress,
    amount: u64,
    memo: &str,
    block_height: u32,
    prover: &SaplingProver,
) -> Result<SaplingTxResult, SaplingBuilderError> {
    if notes.is_empty() {
        return Err(SaplingBuilderError::NoNotes);
    }

    // Derive keys
    #[allow(deprecated)]
    let dfvk = extsk.to_diversifiable_full_viewing_key();
    let fvk = dfvk.fvk().clone();
    let nk = dfvk.to_nk(Scope::External);

    // Get anchor from first note's witness
    let anchor = anchor_from_witness(&notes[0])?;

    // Initialize builder
    let mut builder = Builder::new(
        KerriganMainNetwork,
        BlockHeight::from_u32(block_height),
        BuildConfig::Standard {
            sapling_anchor: Some(anchor),
            orchard_anchor: None,
        },
    );

    // Select notes and add spends
    let mut total = 0u64;
    let mut nullifiers = Vec::new();
    let mut num_spends = 0usize;

    for note in notes {
        let path = note.witness.path()
            .ok_or(SaplingBuilderError::WitnessPathMissing)?;

        builder
            .add_sapling_spend::<FeeRule>(fvk.clone(), note.note.clone(), path)
            .map_err(|e| SaplingBuilderError::Build(format!("add spend: {e:?}")))?;

        // Extract nullifier
        let nf = note.note.nf(&nk, note.witness.path().unwrap().position().into());
        nullifiers.push(encoding::hex_encode(&nf.0));

        num_spends += 1;
        total += note.note.value().inner();

        let current_fee = fees::shield_send_fee(num_spends);
        if total >= amount + current_fee {
            break;
        }
    }

    let fee = fees::shield_send_fee(num_spends);
    if total < amount + fee {
        return Err(SaplingBuilderError::InsufficientBalance {
            have: total,
            need: amount + fee,
        });
    }

    // Add payment output
    let memo_bytes = parse_memo(memo)?;
    let send_amount = zatoshis(amount)?;

    builder
        .add_sapling_output::<FeeRule>(None, *to, send_amount, memo_bytes)
        .map_err(|e| SaplingBuilderError::Build(format!("add output: {e:?}")))?;

    // Add change output (back to ourselves)
    let change = total - amount - fee;
    if change > 0 {
        let (_, change_addr) = dfvk.default_address();
        builder
            .add_sapling_output::<FeeRule>(None, change_addr, zatoshis(change)?, MemoBytes::empty())
            .map_err(|e| SaplingBuilderError::Build(format!("add change: {e:?}")))?;
    }

    // Build and sign
    finalize(builder, extsk, fee, amount, nullifiers, prover)
}

// ---------------------------------------------------------------------------
// Shielding (transparent → sapling)
// ---------------------------------------------------------------------------

/// Build a shielding transaction.
///
/// Spends transparent UTXOs and sends to a shielded `ks1...` address.
/// Transparent change goes back to the sender's transparent address.
pub fn build_shield(
    utxos: &[Utxo],
    privkey: &[u8],
    pubkey: &[u8],
    from_address: &str,
    to_shielded: &PaymentAddress,
    amount: u64,
    block_height: u32,
    prover: &SaplingProver,
) -> Result<SaplingTxResult, SaplingBuilderError> {
    if utxos.is_empty() {
        return Err(SaplingBuilderError::NoNotes);
    }

    // Convert secp256k1 key for transparent signing
    let secp_pubkey = secp256k1::PublicKey::from_slice(pubkey)
        .map_err(|e| SaplingBuilderError::Build(format!("invalid pubkey: {e}")))?;

    // Initialize builder with empty anchor (enables Sapling outputs
    // even though we have no Sapling spends)
    let mut builder = Builder::new(
        KerriganMainNetwork,
        BlockHeight::from_u32(block_height),
        BuildConfig::Standard {
            sapling_anchor: Some(Anchor::empty_tree()),
            orchard_anchor: None,
        },
    );

    // Select UTXOs and add transparent inputs
    let mut total = 0u64;
    let fee = fees::shield_fee(1); // 1 sapling output

    for utxo in utxos {
        // Convert txid from display order (big-endian) to internal order (little-endian)
        let txid_decoded = encoding::hex_decode(&utxo.txid)
            .map_err(|e| SaplingBuilderError::Build(format!("txid hex: {e}")))?;
        if txid_decoded.len() != 32 {
            return Err(SaplingBuilderError::Build("txid must be 32 bytes".into()));
        }
        let mut txid_bytes = [0u8; 32];
        for (i, b) in txid_decoded.iter().enumerate() {
            txid_bytes[31 - i] = *b;
        }

        let outpoint = OutPoint::new(txid_bytes, utxo.vout);

        // Use the UTXO's scriptPubKey directly
        let script_bytes = encoding::hex_decode(&utxo.script_pubkey)
            .map_err(|e| SaplingBuilderError::Build(format!("script hex: {e}")))?;
        let script = zcash_transparent::address::Script(script_bytes);
        let coin = TxOut {
            value: zatoshis(utxo.amount)?,
            script_pubkey: script,
        };

        builder
            .add_transparent_input(secp_pubkey, outpoint, coin)
            .map_err(|e| SaplingBuilderError::Build(format!("add transparent input: {e:?}")))?;

        total += utxo.amount;

        if total >= amount + fee {
            break;
        }
    }

    if total < amount + fee {
        return Err(SaplingBuilderError::InsufficientBalance {
            have: total,
            need: amount + fee,
        });
    }

    // Add shielded output
    builder
        .add_sapling_output::<FeeRule>(None, *to_shielded, zatoshis(amount)?, MemoBytes::empty())
        .map_err(|e| SaplingBuilderError::Build(format!("add sapling output: {e:?}")))?;

    // Transparent change (if any)
    let change = total - amount - fee;
    if change > 0 {
        let change_pubkey_hash = crate::keys::address_to_pubkey_hash(from_address)
            .map_err(|e| SaplingBuilderError::Build(format!("change address: {e}")))?;
        let change_addr = TransparentAddress::PublicKeyHash(change_pubkey_hash);
        builder
            .add_transparent_output(&change_addr, zatoshis(change)?)
            .map_err(|e| SaplingBuilderError::Build(format!("add transparent change: {e:?}")))?;
    }

    // Build with transparent signing set containing our private key
    let secp_privkey = secp256k1::SecretKey::from_slice(privkey)
        .map_err(|e| SaplingBuilderError::Build(format!("invalid privkey: {e}")))?;

    let mut signing_set = TransparentSigningSet::new();
    signing_set.add_key(secp_privkey);

    // Dummy extsk — no sapling spends, only output proof needed
    let extsk = super::keys::default_spending_key(&[0u8; 64])
        .map_err(|e| SaplingBuilderError::Build(format!("dummy extsk: {e}")))?;

    let fee_rule = FeeRule::non_standard(zatoshis(fee)?);

    let result = builder
        .build(
            &signing_set,
            &[extsk],
            &[],
            OsRng,
            &prover.1,
            &prover.0,
            &fee_rule,
        )
        .map_err(|e| SaplingBuilderError::Build(format!("{e:?}")))?;

    // Re-serialize in Kerrigan's type 10 extra payload format
    let tx_bytes = super::kerrigan_tx::serialize_kerrigan_tx(result.transaction())
        .map_err(|e| SaplingBuilderError::Build(format!("kerrigan serialize: {e}")))?;

    Ok(SaplingTxResult {
        tx_hex: encoding::hex_encode(&tx_bytes),
        nullifiers: Vec::new(),
        amount,
        fee,
    })
}

// ---------------------------------------------------------------------------
// Unshielding (sapling → transparent)
// ---------------------------------------------------------------------------

/// Build a Sapling unshielding transaction.
///
/// Spends shielded notes and sends to a transparent `K...` address.
/// Change goes back as a shielded output.
pub fn build_unshield(
    notes: &[SpendableNote],
    extsk: &ExtendedSpendingKey,
    to_transparent: &str,
    amount: u64,
    block_height: u32,
    prover: &SaplingProver,
) -> Result<SaplingTxResult, SaplingBuilderError> {
    if notes.is_empty() {
        return Err(SaplingBuilderError::NoNotes);
    }

    // Validate and convert transparent address
    let pubkey_hash = crate::keys::address_to_pubkey_hash(to_transparent)
        .map_err(|e| SaplingBuilderError::InvalidAddress(format!("{e}")))?;
    let transparent_addr = TransparentAddress::PublicKeyHash(pubkey_hash);

    // Derive keys
    #[allow(deprecated)]
    let dfvk = extsk.to_diversifiable_full_viewing_key();
    let fvk = dfvk.fvk().clone();
    let nk = dfvk.to_nk(Scope::External);

    let anchor = anchor_from_witness(&notes[0])?;

    let mut builder = Builder::new(
        KerriganMainNetwork,
        BlockHeight::from_u32(block_height),
        BuildConfig::Standard {
            sapling_anchor: Some(anchor),
            orchard_anchor: None,
        },
    );

    // Select notes
    let mut total = 0u64;
    let mut nullifiers = Vec::new();
    let mut num_spends = 0usize;

    for note in notes {
        let path = note.witness.path()
            .ok_or(SaplingBuilderError::WitnessPathMissing)?;

        builder
            .add_sapling_spend::<FeeRule>(fvk.clone(), note.note.clone(), path)
            .map_err(|e| SaplingBuilderError::Build(format!("add spend: {e:?}")))?;

        let nf = note.note.nf(&nk, note.witness.path().unwrap().position().into());
        nullifiers.push(encoding::hex_encode(&nf.0));

        num_spends += 1;
        total += note.note.value().inner();

        let current_fee = fees::unshield_fee(num_spends);
        if total >= amount + current_fee {
            break;
        }
    }

    let fee = fees::unshield_fee(num_spends);
    if total < amount + fee {
        return Err(SaplingBuilderError::InsufficientBalance {
            have: total,
            need: amount + fee,
        });
    }

    // Add transparent output
    builder
        .add_transparent_output(&transparent_addr, zatoshis(amount)?)
        .map_err(|e| SaplingBuilderError::Build(format!("add transparent output: {e:?}")))?;

    // Add shielded change
    let change = total - amount - fee;
    if change > 0 {
        let (_, change_addr) = dfvk.default_address();
        builder
            .add_sapling_output::<FeeRule>(None, change_addr, zatoshis(change)?, MemoBytes::empty())
            .map_err(|e| SaplingBuilderError::Build(format!("add change: {e:?}")))?;
    }

    finalize(builder, extsk, fee, amount, nullifiers, prover)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the Sapling anchor from a note's witness root.
fn anchor_from_witness(note: &SpendableNote) -> Result<Anchor, SaplingBuilderError> {
    let root_bytes = note.witness.root().to_bytes();
    Anchor::from_bytes(root_bytes)
        .into_option()
        .ok_or(SaplingBuilderError::InvalidAnchor)
}

/// Build, sign, and serialize the transaction.
fn finalize(
    builder: Builder<'_, KerriganMainNetwork, ()>,
    extsk: &ExtendedSpendingKey,
    fee: u64,
    amount: u64,
    nullifiers: Vec<String>,
    prover: &SaplingProver,
) -> Result<SaplingTxResult, SaplingBuilderError> {
    let transparent_signing_set = TransparentSigningSet::new();
    let fee_rule = FeeRule::non_standard(zatoshis(fee)?);

    let result = builder
        .build(
            &transparent_signing_set,
            &[extsk.clone()],
            &[],
            OsRng,
            &prover.1, // SpendParameters
            &prover.0, // OutputParameters
            &fee_rule,
        )
        .map_err(|e| SaplingBuilderError::Build(format!("{e:?}")))?;

    // Re-serialize in Kerrigan's type 10 extra payload format
    let tx_bytes = super::kerrigan_tx::serialize_kerrigan_tx(result.transaction())
        .map_err(|e| SaplingBuilderError::Build(format!("kerrigan serialize: {e}")))?;

    Ok(SaplingTxResult {
        tx_hex: encoding::hex_encode(&tx_bytes),
        nullifiers,
        amount,
        fee,
    })
}

/// Parse a memo string into MemoBytes.
fn parse_memo(memo: &str) -> Result<MemoBytes, SaplingBuilderError> {
    if memo.is_empty() {
        return Ok(MemoBytes::empty());
    }
    let m: Memo = memo
        .parse()
        .map_err(|e| SaplingBuilderError::InvalidMemo(format!("{e}")))?;
    Ok(m.encode())
}

/// Convert u64 satoshis to Zatoshis.
fn zatoshis(sat: u64) -> Result<Zatoshis, SaplingBuilderError> {
    Zatoshis::from_u64(sat).map_err(|_| SaplingBuilderError::InvalidAmount(sat))
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum SaplingBuilderError {
    NoNotes,
    InsufficientBalance { have: u64, need: u64 },
    InvalidAddress(String),
    InvalidAnchor,
    InvalidMemo(String),
    InvalidAmount(u64),
    WitnessPathMissing,
    Build(String),
}

impl std::fmt::Display for SaplingBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoNotes => write!(f, "no spendable notes"),
            Self::InsufficientBalance { have, need } => {
                write!(f, "insufficient balance: have {have} sat, need {need} sat")
            }
            Self::InvalidAddress(a) => write!(f, "invalid address: {a}"),
            Self::InvalidAnchor => write!(f, "invalid Sapling anchor"),
            Self::InvalidMemo(e) => write!(f, "invalid memo: {e}"),
            Self::InvalidAmount(a) => write!(f, "invalid amount: {a}"),
            Self::WitnessPathMissing => write!(f, "witness has no Merkle path"),
            Self::Build(e) => write!(f, "transaction build error: {e}"),
        }
    }
}

impl std::error::Error for SaplingBuilderError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::keys;

    #[test]
    fn error_display_no_notes() {
        let err = SaplingBuilderError::NoNotes;
        assert_eq!(format!("{err}"), "no spendable notes");
    }

    #[test]
    fn error_display_insufficient_balance() {
        let err = SaplingBuilderError::InsufficientBalance { have: 50_000, need: 100_000 };
        assert!(format!("{err}").contains("50000"));
        assert!(format!("{err}").contains("100000"));
    }

    #[test]
    fn error_display_invalid_address() {
        let err = SaplingBuilderError::InvalidAddress("bad".into());
        assert!(format!("{err}").contains("bad"));
    }

    #[test]
    fn parse_memo_empty() {
        let memo = parse_memo("").unwrap();
        assert_eq!(memo, MemoBytes::empty());
    }

    #[test]
    fn parse_memo_text() {
        let memo = parse_memo("For the Swarm!").unwrap();
        assert_ne!(memo, MemoBytes::empty());
    }

    #[test]
    fn zatoshis_valid() {
        assert!(zatoshis(100_000).is_ok());
        assert!(zatoshis(0).is_ok());
    }

    #[test]
    fn anchor_extraction_requires_witness_path() {
        // A fresh witness from a tree with one node should have a path.
        let mut tree = super::super::tree::empty_tree();
        let node = sapling::Node::from_bytes([42u8; 32]).unwrap();
        super::super::tree::append_node(&mut tree, node).unwrap();
        let witness = super::super::tree::witness_from_tree(&tree).unwrap();

        let note = SpendableNote {
            note: sapling::Note::from_parts(
                keys::default_payment_address(
                    &keys::full_viewing_key(
                        &keys::default_spending_key(&[0u8; 64]).unwrap(),
                    ),
                ),
                sapling::value::NoteValue::from_raw(100_000),
                sapling::note::Rseed::AfterZip212([0u8; 32]),
            ),
            witness,
            nullifier: String::new(),
            memo: None,
            height: 500,
        };

        let anchor = anchor_from_witness(&note);
        assert!(anchor.is_ok());
    }
}
