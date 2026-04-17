//! WASM bindings for the Kerrigan SDK.
//!
//! Exposes wallet primitives to JavaScript via wasm-bindgen.
//! Covers both transparent and shielded (Sapling) operations.

use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Multicore initialization (requires SharedArrayBuffer + COOP/COEP headers)
// ---------------------------------------------------------------------------

/// Initialize the rayon thread pool for parallel proof generation.
/// Call this once from the worker before building shield txs.
#[cfg(feature = "multicore")]
pub use wasm_bindgen_rayon::init_thread_pool;

// ---------------------------------------------------------------------------
// Wallet creation
// ---------------------------------------------------------------------------

/// Generate a new mnemonic phrase (24 words).
#[wasm_bindgen]
pub fn generate_mnemonic() -> Result<String, JsError> {
    crate::bip39::generate_mnemonic()
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Generate a 12-word mnemonic phrase (128 bits of entropy).
#[wasm_bindgen]
pub fn generate_mnemonic_12() -> Result<String, JsError> {
    let mut entropy = [0u8; 16];
    getrandom::getrandom(&mut entropy)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let mnemonic = crate::bip39::entropy_to_mnemonic(&entropy)
        .map_err(|e| JsError::new(&e.to_string()))?;
    entropy.iter_mut().for_each(|b| *b = 0);
    Ok(mnemonic)
}

/// Validate a mnemonic phrase.
#[wasm_bindgen]
pub fn validate_mnemonic(mnemonic: &str) -> bool {
    crate::bip39::validate_mnemonic(mnemonic).is_ok()
}

/// Derive seed from mnemonic + optional passphrase.
#[wasm_bindgen]
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Result<Vec<u8>, JsError> {
    Ok(crate::bip39::mnemonic_to_seed(mnemonic, passphrase).to_vec())
}

// ---------------------------------------------------------------------------
// Transparent keys + addresses
// ---------------------------------------------------------------------------

/// Derive a transparent address from seed at the given index.
#[wasm_bindgen]
pub fn derive_address(seed: &[u8], account: u32, index: u32) -> Result<String, JsError> {
    let kp = crate::keys::derive_keypair_at(seed, account, index)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(kp.address)
}

/// Derive a transparent private key (WIF) from seed.
#[wasm_bindgen]
pub fn derive_wif(seed: &[u8], account: u32, index: u32) -> Result<String, JsError> {
    let kp = crate::keys::derive_keypair_at(seed, account, index)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(crate::keys::privkey_to_wif(&kp.privkey))
}

// ---------------------------------------------------------------------------
// Shielded (Sapling) keys + addresses
// ---------------------------------------------------------------------------

/// Derive a shielded spending key from seed.
#[wasm_bindgen]
pub fn derive_sapling_spending_key(seed: &[u8]) -> Result<String, JsError> {
    let extsk = crate::sapling::keys::default_spending_key(seed)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(crate::sapling::keys::encode_extsk(&extsk))
}

/// Derive a shielded full viewing key from a spending key.
#[wasm_bindgen]
pub fn derive_sapling_viewing_key(extsk_encoded: &str) -> Result<String, JsError> {
    let extsk = crate::sapling::keys::decode_extsk(extsk_encoded)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let extfvk = crate::sapling::keys::full_viewing_key(&extsk);
    Ok(crate::sapling::keys::encode_extfvk(&extfvk))
}

/// Derive a shielded payment address (ks1...) from a viewing key.
#[wasm_bindgen]
pub fn derive_sapling_address(extfvk_encoded: &str) -> Result<String, JsError> {
    let extfvk = crate::sapling::keys::decode_extfvk(extfvk_encoded)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let addr = crate::sapling::keys::default_payment_address(&extfvk);
    Ok(crate::sapling::keys::encode_payment_address(&addr))
}

// ---------------------------------------------------------------------------
// Shield sync (compact stream processing)
// ---------------------------------------------------------------------------

/// Parse a binary shield stream into blocks.
/// Returns JSON: [{ height, entries: [...] }]
#[wasm_bindgen]
pub fn parse_shield_stream(data: &[u8]) -> Result<JsValue, JsError> {
    let blocks = crate::sapling::sync::parse_shield_stream(data)
        .map_err(|e| JsError::new(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&blocks)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Process shield blocks against wallet state.
/// Returns JSON with updated tree, new notes, spent nullifiers, sent notes.
#[wasm_bindgen]
pub fn process_shield_blocks(
    tree_hex: &str,
    blocks: JsValue,
    extfvk_encoded: &str,
    existing_notes: JsValue,
) -> Result<JsValue, JsError> {
    let blocks: Vec<crate::sapling::sync::RawShieldBlock> =
        serde_wasm_bindgen::from_value(blocks)
            .map_err(|e| JsError::new(&e.to_string()))?;
    let extfvk = crate::sapling::keys::decode_extfvk(extfvk_encoded)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let notes: Vec<crate::sapling::notes::SerializedNote> =
        serde_wasm_bindgen::from_value(existing_notes)
            .map_err(|e| JsError::new(&e.to_string()))?;

    let result = crate::sapling::sync::process_shield_blocks(
        tree_hex, &blocks, &extfvk, &notes,
    ).map_err(|e| JsError::new(&e.to_string()))?;

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&e.to_string()))
}

// ---------------------------------------------------------------------------
// Address validation
// ---------------------------------------------------------------------------

/// Validate a Kerrigan address (transparent K.../7... or shielded ks1...).
#[wasm_bindgen]
pub fn validate_address(address: &str) -> bool {
    // Transparent: try to decode script
    if address.starts_with('K') || address.starts_with('7') {
        return crate::script::address_to_script_pubkey(address).is_ok();
    }
    // Shielded
    if address.starts_with("ks1") {
        return crate::sapling::keys::decode_payment_address(address).is_ok();
    }
    false
}

// ---------------------------------------------------------------------------
// Transparent transaction building
// ---------------------------------------------------------------------------

/// Build and sign a transparent transaction.
///
/// The caller is responsible for computing the send amount and any change
/// expectations. Pass a literal amount in satoshis — this function does not
/// interpret any special sentinel values. To send the full balance, compute
/// `sum(utxos) - estimate_transparent_fee(utxos.len(), 1)` on the caller side
/// and pass the result.
///
/// - `utxos`: JsValue array of { txid, vout, amount, script_pubkey }
/// - `to_address`: destination address (K... or 7...)
/// - `amount`: amount in satoshis (literal, > 0)
/// - `seed`: wallet seed bytes
/// - `account`: BIP44 account index
/// - `index`: BIP44 address index
///
/// Returns JsValue: { tx_hex, txid, fee, spent_utxos: [[txid, vout], ...] }
#[wasm_bindgen]
pub fn build_transparent_tx(
    utxos: JsValue,
    to_address: &str,
    amount: u64,
    seed: &[u8],
    account: u32,
    index: u32,
) -> Result<String, JsError> {
    let utxos: Vec<crate::transaction::Utxo> =
        serde_wasm_bindgen::from_value(utxos)
            .map_err(|e| JsError::new(&e.to_string()))?;

    let kp = crate::keys::derive_keypair_at(seed, account, index)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let result = crate::transaction::build_transaction(
        &utxos, to_address, amount, &kp.privkey, &kp.pubkey, &kp.address,
    ).map_err(|e| JsError::new(&e.to_string()))?;

    let spent: Vec<(String, u32)> = result.spent_utxos;
    Ok(serde_json::json!({
        "tx_hex": result.tx_hex, "txid": result.txid,
        "fee": result.fee, "spent_utxos": spent,
    }).to_string())
}

/// Estimate the fee for a transparent transaction (in satoshis).
#[wasm_bindgen]
pub fn estimate_transparent_fee(input_count: usize, output_count: usize) -> u64 {
    crate::fees::estimate_transparent_fee(input_count, output_count)
}

// ---------------------------------------------------------------------------
// Shielding (transparent → sapling)
// ---------------------------------------------------------------------------

/// Estimate shield fee in satoshis (transparent → sapling, 1 output).
#[wasm_bindgen]
pub fn estimate_shield_fee() -> u64 {
    crate::sapling::fees::shield_fee(1)
}

/// Estimate shield-to-shield send fee.
#[wasm_bindgen]
pub fn estimate_shield_send_fee(num_spends: usize) -> u64 {
    crate::sapling::fees::shield_send_fee(num_spends)
}

/// Estimate unshield fee (sapling → transparent).
#[wasm_bindgen]
pub fn estimate_unshield_fee(num_spends: usize) -> u64 {
    crate::sapling::fees::unshield_fee(num_spends)
}

/// Estimate a Sapling transaction fee for an arbitrary (spends, outputs) shape.
///
/// Useful when building send-max transactions where the output count differs
/// from the typical helper functions above (e.g. sapling-send max has no
/// change output, so pass `num_outputs = 1`; unshield-max has no sapling
/// change, so pass `num_outputs = 0`).
#[wasm_bindgen]
pub fn estimate_sapling_fee(num_spends: usize, num_outputs: usize) -> u64 {
    crate::sapling::fees::sapling_fee(num_spends, num_outputs)
}

/// Load Sapling proving parameters into memory (with SHA-256 verification).
#[wasm_bindgen]
pub fn load_sapling_params(
    output_bytes: &[u8],
    spend_bytes: &[u8],
) -> Result<(), JsError> {
    let prover = crate::sapling::prover::verify_and_load_params(output_bytes, spend_bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;
    CACHED_PROVER.lock().unwrap().replace(Arc::new(prover));
    Ok(())
}

/// Load Sapling proving parameters without SHA-256 verification (faster).
/// Use when params were already verified on download.
#[wasm_bindgen]
pub fn load_sapling_params_unchecked(
    output_bytes: &[u8],
    spend_bytes: &[u8],
) -> Result<(), JsError> {
    use sapling::circuit::{OutputParameters, SpendParameters};
    let output = OutputParameters::read(output_bytes, false)
        .map_err(|e| JsError::new(&format!("output params: {e}")))?;
    let spend = SpendParameters::read(spend_bytes, false)
        .map_err(|e| JsError::new(&format!("spend params: {e}")))?;
    CACHED_PROVER.lock().unwrap().replace(Arc::new((output, spend)));
    Ok(())
}

use std::sync::Arc;
static CACHED_PROVER: std::sync::Mutex<Option<Arc<crate::sapling::prover::SaplingProver>>> =
    std::sync::Mutex::new(None);

fn get_prover() -> Result<Arc<crate::sapling::prover::SaplingProver>, JsError> {
    CACHED_PROVER.lock().unwrap().as_ref().cloned()
        .ok_or_else(|| JsError::new("Sapling params not loaded — call load_sapling_params first"))
}

/// Build a shielding transaction (transparent UTXOs → sapling output).
/// Requires load_sapling_params() called first.
/// Returns JSON string: { tx_hex, fee, amount }
#[wasm_bindgen]
pub fn build_shield_tx(
    utxos: JsValue,
    to_shielded_address: &str,
    amount: u64,
    memo: &str,
    seed: &[u8],
    account: u32,
    index: u32,
) -> Result<String, JsError> {
    let utxos: Vec<crate::transaction::Utxo> =
        serde_wasm_bindgen::from_value(utxos)
            .map_err(|e| JsError::new(&e.to_string()))?;
    let prover = get_prover()?;
    let kp = crate::keys::derive_keypair_at(seed, account, index)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let to_addr = crate::sapling::keys::decode_payment_address(to_shielded_address)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let memo_opt = make_memo(memo);

    let result = crate::sapling::builder::build_shield(
        &utxos, &kp.privkey, &kp.pubkey, &kp.address,
        &to_addr, amount, memo_opt, 0, &prover,
    ).map_err(|e| JsError::new(&e.to_string()))?;

    // Compute txid from raw tx hex (double SHA-256, reversed)
    let txid = compute_txid_from_hex(&result.tx_hex);
    let spent: Vec<(String, u32)> = result.spent_utxos;
    Ok(serde_json::json!({
        "tx_hex": result.tx_hex, "fee": result.fee, "amount": result.amount,
        "txid": txid, "spent_utxos": spent,
    }).to_string())
}

/// Compute a txid from a raw transaction hex string.
fn compute_txid_from_hex(hex: &str) -> String {
    use sha2::{Sha256, Digest};
    let bytes = crate::encoding::hex_decode(hex).unwrap_or_default();
    let first = Sha256::digest(&bytes);
    let second = Sha256::digest(first);
    let mut txid = second.to_vec();
    txid.reverse();
    crate::encoding::hex_encode(&txid)
}

/// Build a shield-to-shield send (sapling → sapling).
/// Requires load_sapling_params() called first.
/// Returns JSON string: { tx_hex, fee, amount, nullifiers }
#[wasm_bindgen]
pub fn build_sapling_send_tx(
    notes: JsValue,
    to_address: &str,
    amount: u64,
    memo: &str,
    seed: &[u8],
) -> Result<String, JsError> {
    let ser_notes: Vec<crate::sapling::notes::SerializedNote> =
        serde_wasm_bindgen::from_value(notes)
            .map_err(|e| JsError::new(&e.to_string()))?;
    let spendable: Vec<crate::sapling::notes::SpendableNote> = ser_notes.iter()
        .map(|n| crate::sapling::notes::SpendableNote::from_serialized(n))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsError::new(&e.to_string()))?;
    let prover = get_prover()?;
    let extsk = crate::sapling::keys::default_spending_key(seed)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let to_addr = crate::sapling::keys::decode_payment_address(to_address)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let memo_opt = make_memo(memo);

    let result = crate::sapling::builder::build_sapling_send(
        &spendable, &extsk, &to_addr, amount, memo_opt, &prover,
    ).map_err(|e| JsError::new(&e.to_string()))?;
    let txid = compute_txid_from_hex(&result.tx_hex);

    Ok(serde_json::json!({
        "tx_hex": result.tx_hex, "txid": txid, "fee": result.fee, "amount": result.amount,
        "nullifiers": result.nullifiers,
    }).to_string())
}

/// Build an unshield transaction (sapling → transparent).
/// Requires load_sapling_params() called first.
/// Returns JSON string: { tx_hex, fee, amount, nullifiers }
#[wasm_bindgen]
pub fn build_unshield_tx(
    notes: JsValue,
    to_transparent: &str,
    amount: u64,
    seed: &[u8],
) -> Result<String, JsError> {
    let ser_notes: Vec<crate::sapling::notes::SerializedNote> =
        serde_wasm_bindgen::from_value(notes)
            .map_err(|e| JsError::new(&e.to_string()))?;
    let spendable: Vec<crate::sapling::notes::SpendableNote> = ser_notes.iter()
        .map(|n| crate::sapling::notes::SpendableNote::from_serialized(n))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsError::new(&e.to_string()))?;
    let prover = get_prover()?;
    let extsk = crate::sapling::keys::default_spending_key(seed)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let result = crate::sapling::builder::build_unshield(
        &spendable, &extsk, to_transparent, amount, &prover,
    ).map_err(|e| JsError::new(&e.to_string()))?;
    let txid = compute_txid_from_hex(&result.tx_hex);

    Ok(serde_json::json!({
        "tx_hex": result.tx_hex, "txid": txid, "fee": result.fee, "amount": result.amount,
        "nullifiers": result.nullifiers,
    }).to_string())
}

/// Helper: build optional 512-byte memo from string.
fn make_memo(memo: &str) -> Option<[u8; 512]> {
    if memo.is_empty() { return None; }
    let mut padded = [0u8; 512];
    let len = memo.as_bytes().len().min(512);
    padded[..len].copy_from_slice(&memo.as_bytes()[..len]);
    Some(padded)
}

/// Debug: compute the Sapling anchor from a witness hex string.
/// Returns the anchor as a hex string (for comparing with node errors).
#[wasm_bindgen]
pub fn debug_witness_anchor(witness_hex: &str) -> Result<String, JsError> {
    let witness = crate::sapling::tree::read_witness_hex(witness_hex)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let root = witness.root();
    let root_bytes = root.to_bytes();
    // Return both normal and reversed for comparison
    let normal = crate::encoding::hex_encode(&root_bytes);
    let reversed: Vec<u8> = root_bytes.iter().rev().cloned().collect();
    let rev = crate::encoding::hex_encode(&reversed);
    Ok(format!("normal:{normal} reversed:{rev}"))
}

/// Debug: compute the Sapling tree root from a commitment tree hex string.
#[wasm_bindgen]
pub fn debug_tree_root(tree_hex: &str) -> Result<String, JsError> {
    let tree = crate::sapling::tree::read_tree_hex(tree_hex)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let root = tree.root();
    let root_bytes = root.to_bytes();
    let normal = crate::encoding::hex_encode(&root_bytes);
    let reversed: Vec<u8> = root_bytes.iter().rev().cloned().collect();
    let rev = crate::encoding::hex_encode(&reversed);
    Ok(format!("normal:{normal} reversed:{rev}"))
}

// ---------------------------------------------------------------------------
// Encoding utilities
// ---------------------------------------------------------------------------

/// Encode bytes to hex string.
#[wasm_bindgen]
pub fn hex_encode(bytes: &[u8]) -> String {
    crate::encoding::hex_encode(bytes)
}

/// Decode hex string to bytes.
#[wasm_bindgen]
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, JsError> {
    crate::encoding::hex_decode(hex)
        .map_err(|e| JsError::new(&e.to_string()))
}
