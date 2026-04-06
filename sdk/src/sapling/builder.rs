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
use sapling::keys::SpendAuthorizingKey;
use sapling::note_encryption::Zip212Enforcement;
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
#[allow(clippy::too_many_arguments)]
pub fn build_shield(
    utxos: &[Utxo],
    privkey: &[u8],
    pubkey: &[u8],
    from_address: &str,
    to_shielded: &PaymentAddress,
    amount: u64,
    _block_height: u32,
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

    // Build sapling bundle with one output (no spends)
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

    // Create proofs
    let proven_bundle = unauth_bundle.create_proofs(&prover.1, &prover.0, OsRng, ());

    // Compute Kerrigan sighash
    let sighash = super::kerrigan_tx::compute_kerrigan_sighash_from_bundle(
        &selected, from_address, change, &proven_bundle,
    ).map_err(|e| SaplingBuilderError::Build(format!("sighash: {e}")))?;

    // Apply binding signature (no spend auth keys for shielding)
    let auth_bundle = proven_bundle
        .apply_signatures(OsRng, sighash, &[])
        .map_err(|e| SaplingBuilderError::Build(format!("apply signatures: {e:?}")))?;

    // Serialize in Kerrigan type 10 format
    let tx_hex = super::kerrigan_tx::serialize_kerrigan_shield_tx(
        &selected, privkey, pubkey, from_address, change, &auth_bundle, &sighash,
    ).map_err(|e| SaplingBuilderError::Build(format!("serialize: {e}")))?;

    Ok(SaplingTxResult { tx_hex, nullifiers: Vec::new(), amount, fee })
}

// ---------------------------------------------------------------------------
// Shield-to-shield send (private → private)
// ---------------------------------------------------------------------------

/// Build a shield-to-shield transaction (spend sapling notes → sapling output).
#[allow(clippy::too_many_arguments)]
pub fn build_sapling_send(
    notes: &[SpendableNote],
    extsk: &ExtendedSpendingKey,
    to: &PaymentAddress,
    amount: u64,
    memo: Option<[u8; 512]>,
    prover: &SaplingProver,
) -> Result<SaplingTxResult, SaplingBuilderError> {
    if notes.is_empty() {
        return Err(SaplingBuilderError::NoNotes);
    }

    // Derive keys
    #[allow(deprecated)]
    let dfvk = extsk.to_diversifiable_full_viewing_key();
    let fvk = dfvk.fvk().clone();
    let nk = dfvk.to_nk(pivx_primitives::zip32::Scope::External);

    // Get anchor from first note's witness
    let anchor = Anchor::from_bytes(notes[0].witness.root().to_bytes())
        .into_option()
        .ok_or(SaplingBuilderError::InvalidAnchor)?;

    let mut sapling_builder = sapling::builder::Builder::new(
        Zip212Enforcement::On,
        BundleType::DEFAULT,
        anchor,
    );

    // Select notes and add spends
    let mut total = 0u64;
    let mut nullifiers = Vec::new();
    let mut num_spends = 0usize;

    for note in notes {
        let path = note.witness.path()
            .ok_or(SaplingBuilderError::WitnessPathMissing)?;

        sapling_builder
            .add_spend(fvk.clone(), note.note.clone(), path)
            .map_err(|e| SaplingBuilderError::Build(format!("add spend: {e:?}")))?;

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
        return Err(SaplingBuilderError::InsufficientBalance { have: total, need: amount + fee });
    }

    // Add payment output
    sapling_builder
        .add_output(None, *to, NoteValue::from_raw(amount), memo)
        .map_err(|e| SaplingBuilderError::Build(format!("add output: {e:?}")))?;

    // Add change output (back to ourselves)
    let change = total - amount - fee;
    if change > 0 {
        let (_, change_addr) = dfvk.default_address();
        sapling_builder
            .add_output(None, change_addr, NoteValue::from_raw(change), None)
            .map_err(|e| SaplingBuilderError::Build(format!("add change: {e:?}")))?;
    }

    // Build proofs and sign
    build_and_sign_sapling_only(sapling_builder, extsk, prover, nullifiers, amount, fee)
}

// ---------------------------------------------------------------------------
// Unshielding (private → public)
// ---------------------------------------------------------------------------

/// Build an unshielding transaction (spend sapling notes → transparent output).
#[allow(clippy::too_many_arguments)]
pub fn build_unshield(
    notes: &[SpendableNote],
    extsk: &ExtendedSpendingKey,
    to_transparent: &str,
    amount: u64,
    prover: &SaplingProver,
) -> Result<SaplingTxResult, SaplingBuilderError> {
    if notes.is_empty() {
        return Err(SaplingBuilderError::NoNotes);
    }

    // Validate transparent destination
    crate::keys::validate_address(to_transparent)
        .map_err(|e| SaplingBuilderError::InvalidAddress(format!("{e}")))?;

    // Derive keys
    #[allow(deprecated)]
    let dfvk = extsk.to_diversifiable_full_viewing_key();
    let fvk = dfvk.fvk().clone();
    let nk = dfvk.to_nk(pivx_primitives::zip32::Scope::External);

    let anchor = Anchor::from_bytes(notes[0].witness.root().to_bytes())
        .into_option()
        .ok_or(SaplingBuilderError::InvalidAnchor)?;

    let mut sapling_builder = sapling::builder::Builder::new(
        Zip212Enforcement::On,
        BundleType::DEFAULT,
        anchor,
    );

    // Select notes
    let mut total = 0u64;
    let mut nullifiers = Vec::new();
    let mut num_spends = 0usize;

    for note in notes {
        let path = note.witness.path()
            .ok_or(SaplingBuilderError::WitnessPathMissing)?;

        sapling_builder
            .add_spend(fvk.clone(), note.note.clone(), path)
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
        return Err(SaplingBuilderError::InsufficientBalance { have: total, need: amount + fee });
    }

    // Shielded change (if any)
    let change = total - amount - fee;
    if change > 0 {
        let (_, change_addr) = dfvk.default_address();
        sapling_builder
            .add_output(None, change_addr, NoteValue::from_raw(change), None)
            .map_err(|e| SaplingBuilderError::Build(format!("add change: {e:?}")))?;
    }

    // Build the sapling bundle (proofs + signatures)
    let (auth_bundle, sighash, _, _) =
        build_sapling_bundle_with_sighash(
            sapling_builder, extsk, prover, &nullifiers,
            Some((to_transparent, amount)),
            fee,
        )?;

    // Serialize in Kerrigan type 10 format with transparent output
    let tx_hex = super::kerrigan_tx::serialize_kerrigan_unshield_tx(
        to_transparent, amount, &auth_bundle, &sighash,
    ).map_err(|e| SaplingBuilderError::Build(format!("serialize: {e}")))?;

    Ok(SaplingTxResult { tx_hex, nullifiers, amount, fee })
}

// ---------------------------------------------------------------------------
// Internal: build sapling bundle with Kerrigan sighash
// ---------------------------------------------------------------------------

/// Build, prove, and sign a sapling-only transaction (no transparent inputs).
fn build_and_sign_sapling_only(
    sapling_builder: sapling::builder::Builder,
    extsk: &ExtendedSpendingKey,
    prover: &SaplingProver,
    nullifiers: Vec<String>,
    amount: u64,
    fee: u64,
) -> Result<SaplingTxResult, SaplingBuilderError> {
    let (auth_bundle, sighash, _, _) = build_sapling_bundle_with_sighash(
        sapling_builder, extsk, prover, &nullifiers, None, fee,
    )?;

    // Serialize — no transparent inputs or outputs
    let tx_hex = super::kerrigan_tx::serialize_kerrigan_sapling_only_tx(
        &auth_bundle, &sighash,
    ).map_err(|e| SaplingBuilderError::Build(format!("serialize: {e}")))?;

    Ok(SaplingTxResult { tx_hex, nullifiers, amount, fee })
}

/// Core bundle builder: proofs → Kerrigan sighash → signatures.
#[allow(clippy::type_complexity)]
fn build_sapling_bundle_with_sighash(
    sapling_builder: sapling::builder::Builder,
    extsk: &ExtendedSpendingKey,
    prover: &SaplingProver,
    nullifiers: &[String],
    transparent_output: Option<(&str, u64)>, // (address, amount) for unshielding
    fee: u64,
) -> Result<(
    sapling::bundle::Bundle<sapling::bundle::Authorized, i64>,
    [u8; 32],
    Vec<String>,
    u64,
), SaplingBuilderError> {
    use sapling::circuit::{SpendParameters, OutputParameters};

    // Step 1: Build unauthorized bundle
    let (unauth_bundle, _metadata) = sapling_builder
        .build::<SpendParameters, OutputParameters, OsRng, i64>(std::slice::from_ref(extsk), OsRng)
        .map_err(|e| SaplingBuilderError::Build(format!("build: {e:?}")))?
        .ok_or(SaplingBuilderError::Build("empty bundle".into()))?;

    // Step 2: Create Groth16 proofs
    let proven_bundle = unauth_bundle.create_proofs(&prover.1, &prover.0, OsRng, ());

    // Step 3: Compute Kerrigan sighash
    let sighash = super::kerrigan_tx::compute_kerrigan_sighash_sapling(
        transparent_output, &proven_bundle,
    ).map_err(|e| SaplingBuilderError::Build(format!("sighash: {e}")))?;

    // Step 4: Apply signatures (binding sig + spend auth sigs)
    let ask = extsk.expsk.ask.clone();
    let num_spends = proven_bundle.shielded_spends().len();
    let signing_keys: Vec<SpendAuthorizingKey> = (0..num_spends).map(|_| ask.clone()).collect();

    let auth_bundle = proven_bundle
        .apply_signatures(OsRng, sighash, &signing_keys)
        .map_err(|e| SaplingBuilderError::Build(format!("apply signatures: {e:?}")))?;

    Ok((auth_bundle, sighash, nullifiers.to_vec(), fee))
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
