/// Sapling transaction builder for the Kerrigan Network.
///
/// Uses the `sapling::Builder` three-step flow:
/// 1. Build unauthorized bundle (circuit descriptions, no proofs)
/// 2. Create Groth16 proofs
/// 3. Compute Kerrigan sighash and apply signatures
///
/// Then serializes in Kerrigan's type 10 extra payload format.

use rand_core::OsRng;
use sapling::builder::BundleType;
use sapling::note_encryption::Zip212Enforcement;
use sapling::prover::{OutputProver, SpendProver};
use sapling::value::NoteValue;
use sapling::zip32::ExtendedSpendingKey;
use sapling::{Anchor, PaymentAddress};

use crate::encoding;
use crate::transaction::Utxo;
use super::fees;
use super::keys;
use super::notes::SpendableNote;
use super::prover::SaplingProver;

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct SaplingTxResult {
    pub tx_hex: String,
    pub nullifiers: Vec<String>,
    pub amount: u64,
    pub fee: u64,
}

// ---------------------------------------------------------------------------
// Shielding (transparent → sapling)
// ---------------------------------------------------------------------------

/// Build a shielding transaction (transparent UTXOs → sapling output).
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

    let fee = fees::shield_fee(1);

    // Select UTXOs
    let mut selected = Vec::new();
    let mut total = 0u64;
    for utxo in utxos {
        selected.push(utxo.clone());
        total += utxo.amount;
        if total >= amount + fee {
            break;
        }
    }

    if total < amount + fee {
        return Err(SaplingBuilderError::InsufficientBalance { have: total, need: amount + fee });
    }

    let change = total - amount - fee;

    // Step 1: Build unauthorized sapling bundle (circuit descriptions)
    let mut sapling_builder = sapling::builder::Builder::new(
        Zip212Enforcement::On,
        BundleType::DEFAULT,
        Anchor::empty_tree(),
    );

    sapling_builder
        .add_output(None, *to_shielded, NoteValue::from_raw(amount), None)
        .map_err(|e| SaplingBuilderError::Build(format!("add output: {e:?}")))?;

    let dummy_extsk = keys::default_spending_key(&[0u8; 64])
        .map_err(|e| SaplingBuilderError::Build(format!("dummy extsk: {e}")))?;

    use sapling::circuit::{SpendParameters, OutputParameters};
    let (unauth_bundle, _metadata) = sapling_builder
        .build::<SpendParameters, OutputParameters, OsRng, i64>(&[dummy_extsk], OsRng)
        .map_err(|e| SaplingBuilderError::Build(format!("build: {e:?}")))?
        .ok_or(SaplingBuilderError::Build("empty bundle".into()))?;

    // Step 2: Create Groth16 proofs
    let proven_bundle = unauth_bundle.create_proofs(
        &prover.1, // SpendParameters
        &prover.0, // OutputParameters
        OsRng,
        (),        // no progress tracking
    );

    // Step 3: Compute Kerrigan sighash from the proven bundle
    let sighash = super::kerrigan_tx::compute_kerrigan_sighash_from_bundle(
        &selected,
        from_address,
        change,
        &proven_bundle,
    ).map_err(|e| SaplingBuilderError::Build(format!("sighash: {e}")))?;

    // Step 4: Apply binding signature with Kerrigan sighash
    let auth_bundle = proven_bundle
        .apply_signatures(OsRng, sighash, &[])
        .map_err(|e| SaplingBuilderError::Build(format!("apply signatures: {e:?}")))?;

    // Step 5: Serialize in Kerrigan type 10 format
    let tx_hex = super::kerrigan_tx::serialize_kerrigan_shield_tx(
        &selected,
        privkey,
        pubkey,
        from_address,
        change,
        &auth_bundle,
        &sighash,
    ).map_err(|e| SaplingBuilderError::Build(format!("serialize: {e}")))?;

    Ok(SaplingTxResult {
        tx_hex,
        nullifiers: Vec::new(),
        amount,
        fee,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_no_notes() {
        assert_eq!(format!("{}", SaplingBuilderError::NoNotes), "no spendable notes");
    }

    #[test]
    fn error_display_insufficient_balance() {
        let err = SaplingBuilderError::InsufficientBalance { have: 50_000, need: 100_000 };
        assert!(format!("{err}").contains("50000"));
    }
}
