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
