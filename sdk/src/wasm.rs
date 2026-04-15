//! WASM bindings for the Kerrigan SDK.
//!
//! Exposes wallet primitives to JavaScript via wasm-bindgen.
//! Covers both transparent and shielded (Sapling) operations.

use wasm_bindgen::prelude::*;

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
/// - `utxos`: JsValue array of { txid, vout, amount, script_pubkey }
/// - `to_address`: destination address (K... or 7...)
/// - `amount`: amount in satoshis (0 = send max)
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
) -> Result<JsValue, JsError> {
    let utxos: Vec<crate::transaction::Utxo> =
        serde_wasm_bindgen::from_value(utxos)
            .map_err(|e| JsError::new(&e.to_string()))?;

    let kp = crate::keys::derive_keypair_at(seed, account, index)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let result = if amount == 0 {
        // Send max
        let own_script = crate::script::address_to_script_pubkey(&kp.address)
            .map_err(|e| JsError::new(&e.to_string()))?;
        crate::transaction::build_max_transaction(
            &utxos, to_address, &kp.privkey, &kp.pubkey, &own_script,
        ).map_err(|e| JsError::new(&e.to_string()))?
    } else {
        crate::transaction::build_transaction(
            &utxos, to_address, amount, &kp.privkey, &kp.pubkey, &kp.address,
        ).map_err(|e| JsError::new(&e.to_string()))?
    };

    // Build a plain serializable result (avoid needing Serialize on Transaction)
    let spent: Vec<(String, u32)> = result.spent_utxos;
    let out = serde_json::json!({
        "tx_hex": result.tx_hex,
        "txid": result.txid,
        "fee": result.fee,
        "spent_utxos": spent,
    });
    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsError::new(&e.to_string()))
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

/// Build a shielding transaction (transparent UTXOs → sapling output).
///
/// Requires the Sapling proving parameter files (downloaded + cached by caller).
/// Returns JsValue: { tx_hex, fee, amount }
#[wasm_bindgen]
pub fn build_shield_tx(
    utxos: JsValue,
    to_shielded_address: &str,
    amount: u64,
    memo: &str,
    seed: &[u8],
    account: u32,
    index: u32,
    output_params: &[u8],
    spend_params: &[u8],
) -> Result<JsValue, JsError> {
    let utxos: Vec<crate::transaction::Utxo> =
        serde_wasm_bindgen::from_value(utxos)
            .map_err(|e| JsError::new(&e.to_string()))?;

    let prover = crate::sapling::prover::verify_and_load_params(output_params, spend_params)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let kp = crate::keys::derive_keypair_at(seed, account, index)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let to_addr = crate::sapling::keys::decode_payment_address(to_shielded_address)
        .map_err(|e| JsError::new(&e.to_string()))?;

    // Build memo (512-byte padded)
    let memo_opt = if memo.is_empty() {
        None
    } else {
        let memo_bytes = memo.as_bytes();
        let mut padded = [0u8; 512];
        let len = memo_bytes.len().min(512);
        padded[..len].copy_from_slice(&memo_bytes[..len]);
        Some(padded)
    };

    let result = crate::sapling::builder::build_shield(
        &utxos, &kp.privkey, &kp.pubkey, &kp.address,
        &to_addr, amount, memo_opt, 0, &prover,
    ).map_err(|e| JsError::new(&e.to_string()))?;

    let out = serde_json::json!({
        "tx_hex": result.tx_hex,
        "fee": result.fee,
        "amount": result.amount,
    });
    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsError::new(&e.to_string()))
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
