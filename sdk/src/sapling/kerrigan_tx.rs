/// Kerrigan transaction format: sighash computation and serialization.
///
/// Kerrigan uses Dash-style type 10 transactions with Sapling data in
/// `vExtraPayload`. The sighash for the binding signature differs from
/// PIVX/Zcash — it includes `nType` and `payloadVersion` fields.
use sha2::{Sha256, Digest};

use sapling::bundle::{Authorized, Bundle};
use sapling::builder::{InProgress, Proven, Unsigned};

use crate::encoding;
use crate::transaction::Utxo;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const KERRIGAN_TX_VERSION: u16 = 3;
const KERRIGAN_SAPLING_TYPE: u16 = 10;
const SAPLING_PAYLOAD_VERSION: u16 = 1;

// ---------------------------------------------------------------------------
// Kerrigan Sighash (mirrors ComputeSaplingSighash in sapling_validation.cpp)
// ---------------------------------------------------------------------------

/// Compute the Kerrigan sighash from a proven (but unsigned) bundle.
pub fn compute_kerrigan_sighash_from_bundle(
    utxos: &[Utxo],
    change_address: &str,
    change_amount: u64,
    bundle: &Bundle<InProgress<Proven, Unsigned>, i64>,
) -> Result<[u8; 32], String> {
    let mut hw = Vec::new();

    // nVersion (i16 LE — matches C++ int16_t tx.nVersion)
    hw.extend_from_slice(&(KERRIGAN_TX_VERSION as i16).to_le_bytes());

    // hashPrevouts = SHA256d(all prevouts)
    let hash_prevouts = {
        let mut data = Vec::new();
        for utxo in utxos {
            let txid_bytes = encoding::hex_decode(&utxo.txid).map_err(|e| format!("txid: {e}"))?;
            // Reverse txid for internal byte order
            let mut reversed = [0u8; 32];
            for (i, b) in txid_bytes.iter().enumerate() {
                reversed[31 - i] = *b;
            }
            data.extend_from_slice(&reversed);
            data.extend_from_slice(&utxo.vout.to_le_bytes());
        }
        sha256d(&data)
    };
    hw.extend_from_slice(&hash_prevouts);

    // hashSequence = SHA256d(all sequences) — all 0xFFFFFFFF
    let hash_sequence = {
        let mut data = Vec::new();
        for _ in utxos {
            data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        }
        sha256d(&data)
    };
    hw.extend_from_slice(&hash_sequence);

    // hashOutputs = SHA256d(all transparent outputs)
    let hash_outputs = {
        let mut data = Vec::new();
        // Change output (if any)
        if change_amount > 0 {
            data.extend_from_slice(&(change_amount as i64).to_le_bytes());
            let pubkey_hash = crate::keys::address_to_pubkey_hash(change_address)
                .map_err(|e| format!("change addr: {e}"))?;
            let script = crate::script::p2pkh_script(&pubkey_hash);
            write_compact_size(&mut data, script.len());
            data.extend_from_slice(&script);
        }
        sha256d(&data)
    };
    hw.extend_from_slice(&hash_outputs);

    // nLockTime
    hw.extend_from_slice(&0u32.to_le_bytes());

    // nType (u16 LE — matches C++ uint16_t tx.nType)
    hw.extend_from_slice(&KERRIGAN_SAPLING_TYPE.to_le_bytes());

    // payloadVersion
    hw.extend_from_slice(&SAPLING_PAYLOAD_VERSION.to_le_bytes());

    // hashShieldedSpends = SHA256d(all spend descriptions without spendAuthSig)
    let hash_spends = {
        let mut data = Vec::new();
        for spend in bundle.shielded_spends() {
            data.extend_from_slice(&spend.cv().to_bytes());
            data.extend_from_slice(&spend.anchor().to_bytes());
            data.extend_from_slice(&spend.nullifier().0);
            data.extend_from_slice(&<[u8; 32]>::from(*spend.rk()));
            data.extend_from_slice(spend.zkproof());
        }
        sha256d(&data)
    };
    hw.extend_from_slice(&hash_spends);

    // hashShieldedOutputs = SHA256d(all output descriptions)
    let hash_outputs_shielded = {
        let mut data = Vec::new();
        for output in bundle.shielded_outputs() {
            data.extend_from_slice(&output.cv().to_bytes());
            data.extend_from_slice(&output.cmu().to_bytes());
            data.extend_from_slice(output.ephemeral_key().as_ref());
            data.extend_from_slice(output.enc_ciphertext());
            data.extend_from_slice(output.out_ciphertext());
            data.extend_from_slice(output.zkproof());
        }
        sha256d(&data)
    };
    hw.extend_from_slice(&hash_outputs_shielded);

    // valueBalance
    let vb: i64 = *bundle.value_balance();
    hw.extend_from_slice(&vb.to_le_bytes());

    Ok(sha256d(&hw))
}

// ---------------------------------------------------------------------------
// Full transaction serialization
// ---------------------------------------------------------------------------

/// Serialize a complete Kerrigan shielding transaction in type 10 format.
pub fn serialize_kerrigan_shield_tx(
    utxos: &[Utxo],
    privkey: &[u8],
    pubkey: &[u8],
    from_address: &str,
    change_amount: u64,
    bundle: &Bundle<Authorized, i64>,
    _sighash: &[u8; 32],
) -> Result<String, String> {
    let mut tx = Vec::new();

    // Header: (type << 16) | version
    let header: u32 = ((KERRIGAN_SAPLING_TYPE as u32) << 16) | (KERRIGAN_TX_VERSION as u32);
    tx.extend_from_slice(&header.to_le_bytes());

    // Build the Sapling payload first (needed for transparent signing)
    let payload = build_sapling_payload(bundle)?;

    // Transparent inputs (signed with legacy sighash including payload)
    write_compact_size(&mut tx, utxos.len());
    for (i, utxo) in utxos.iter().enumerate() {
        // prevout: txid (reversed) + vout
        let txid_bytes = encoding::hex_decode(&utxo.txid).map_err(|e| format!("txid: {e}"))?;
        let mut reversed = [0u8; 32];
        for (j, b) in txid_bytes.iter().enumerate() {
            reversed[31 - j] = *b;
        }
        tx.extend_from_slice(&reversed);
        tx.extend_from_slice(&utxo.vout.to_le_bytes());

        // scriptSig: sign with legacy sighash over full tx + payload
        let sig_script = sign_transparent_input(
            i, utxos, privkey, pubkey, from_address, change_amount, &payload,
        )?;
        write_compact_size(&mut tx, sig_script.len());
        tx.extend_from_slice(&sig_script);

        // sequence
        tx.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    }

    // Transparent outputs
    if change_amount > 0 {
        write_compact_size(&mut tx, 1);
        tx.extend_from_slice(&(change_amount as i64).to_le_bytes());
        let pubkey_hash = crate::keys::address_to_pubkey_hash(from_address)
            .map_err(|e| format!("change addr: {e}"))?;
        let script = crate::script::p2pkh_script(&pubkey_hash);
        write_compact_size(&mut tx, script.len());
        tx.extend_from_slice(&script);
    } else {
        write_compact_size(&mut tx, 0);
    }

    // nLockTime
    tx.extend_from_slice(&0u32.to_le_bytes());

    // Extra payload (Sapling) — already built above for signing
    write_compact_size(&mut tx, payload.len());
    tx.extend_from_slice(&payload);

    Ok(encoding::hex_encode(&tx))
}

/// Build the Sapling extra payload from an authorized bundle.
fn build_sapling_payload(bundle: &Bundle<Authorized, i64>) -> Result<Vec<u8>, String> {
    let mut payload = Vec::new();

    // Payload version
    payload.extend_from_slice(&SAPLING_PAYLOAD_VERSION.to_le_bytes());

    // Spend descriptions
    let spends = bundle.shielded_spends();
    write_compact_size(&mut payload, spends.len());
    for spend in spends {
        payload.extend_from_slice(&spend.cv().to_bytes());
        payload.extend_from_slice(&spend.anchor().to_bytes());
        payload.extend_from_slice(&spend.nullifier().0);
        payload.extend_from_slice(&<[u8; 32]>::from(*spend.rk()));
        payload.extend_from_slice(spend.zkproof());
        let sig_bytes: [u8; 64] = (*spend.spend_auth_sig()).into();
        payload.extend_from_slice(&sig_bytes);
    }

    // Output descriptions
    let outputs = bundle.shielded_outputs();
    write_compact_size(&mut payload, outputs.len());
    for output in outputs {
        payload.extend_from_slice(&output.cv().to_bytes());
        payload.extend_from_slice(&output.cmu().to_bytes());
        payload.extend_from_slice(output.ephemeral_key().as_ref());
        payload.extend_from_slice(output.enc_ciphertext());
        payload.extend_from_slice(output.out_ciphertext());
        payload.extend_from_slice(output.zkproof());
    }

    // Value balance
    payload.extend_from_slice(&bundle.value_balance().to_le_bytes());

    // Binding signature
    let binding_bytes: [u8; 64] = bundle.authorization().binding_sig.into();
    payload.extend_from_slice(&binding_bytes);

    Ok(payload)
}

// ---------------------------------------------------------------------------
// Transparent input signing (SIGHASH_ALL for type 10)
// ---------------------------------------------------------------------------

/// Sign a transparent input using legacy sighash over the full type 10 tx.
///
/// The sighash preimage is the entire serialized transaction with:
/// - All other inputs' scriptSig set to empty
/// - This input's scriptSig replaced with the UTXO's scriptPubKey
/// - The Sapling extra payload included
/// - SIGHASH_ALL (4 bytes) appended
fn sign_transparent_input(
    input_index: usize,
    all_utxos: &[Utxo],
    privkey: &[u8],
    pubkey: &[u8],
    change_address: &str,
    change_amount: u64,
    sapling_payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut preimage = Vec::new();

    // Header: (type << 16) | version
    let header: u32 = ((KERRIGAN_SAPLING_TYPE as u32) << 16) | (KERRIGAN_TX_VERSION as u32);
    preimage.extend_from_slice(&header.to_le_bytes());

    // vin
    write_compact_size(&mut preimage, all_utxos.len());
    for (i, utxo) in all_utxos.iter().enumerate() {
        // prevout
        let txid_bytes = encoding::hex_decode(&utxo.txid).map_err(|e| format!("txid: {e}"))?;
        let mut reversed = [0u8; 32];
        for (j, b) in txid_bytes.iter().enumerate() {
            reversed[31 - j] = *b;
        }
        preimage.extend_from_slice(&reversed);
        preimage.extend_from_slice(&utxo.vout.to_le_bytes());

        // scriptSig: empty for all except the one being signed
        if i == input_index {
            let script = encoding::hex_decode(&utxo.script_pubkey)
                .map_err(|e| format!("script: {e}"))?;
            write_compact_size(&mut preimage, script.len());
            preimage.extend_from_slice(&script);
        } else {
            write_compact_size(&mut preimage, 0);
        }

        // sequence
        preimage.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    }

    // vout
    if change_amount > 0 {
        write_compact_size(&mut preimage, 1);
        preimage.extend_from_slice(&(change_amount as i64).to_le_bytes());
        let pubkey_hash = crate::keys::address_to_pubkey_hash(change_address)
            .map_err(|e| format!("change addr: {e}"))?;
        let script = crate::script::p2pkh_script(&pubkey_hash);
        write_compact_size(&mut preimage, script.len());
        preimage.extend_from_slice(&script);
    } else {
        write_compact_size(&mut preimage, 0);
    }

    // nLockTime
    preimage.extend_from_slice(&0u32.to_le_bytes());

    // vExtraPayload (Sapling data — included in sighash!)
    write_compact_size(&mut preimage, sapling_payload.len());
    preimage.extend_from_slice(sapling_payload);

    // SIGHASH_ALL
    preimage.extend_from_slice(&1u32.to_le_bytes());

    // Double SHA-256
    let sighash = sha256d(&preimage);

    // Sign
    let secp = secp256k1::Secp256k1::new();
    let secret_key = secp256k1::SecretKey::from_slice(privkey)
        .map_err(|e| format!("privkey: {e}"))?;
    let message = secp256k1::Message::from_digest(sighash);
    let sig = secp.sign_ecdsa(&message, &secret_key);

    // Build scriptSig: <sig + hashtype> <pubkey>
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(0x01); // SIGHASH_ALL

    let mut script_sig = Vec::new();
    script_sig.push(sig_bytes.len() as u8);
    script_sig.extend_from_slice(&sig_bytes);
    script_sig.push(pubkey.len() as u8);
    script_sig.extend_from_slice(pubkey);

    Ok(script_sig)
}

// ---------------------------------------------------------------------------
// Sighash for sapling-only txs (shield-to-shield, unshield)
// ---------------------------------------------------------------------------

/// Compute Kerrigan sighash for a transaction with sapling spends.
/// Optionally includes a transparent output (for unshielding).
pub fn compute_kerrigan_sighash_sapling(
    transparent_output: Option<(&str, u64)>,
    bundle: &Bundle<InProgress<Proven, Unsigned>, i64>,
) -> Result<[u8; 32], String> {
    let mut hw = Vec::new();

    // nVersion (i16 LE)
    hw.extend_from_slice(&(KERRIGAN_TX_VERSION as i16).to_le_bytes());

    // hashPrevouts (empty — no transparent inputs)
    hw.extend_from_slice(&sha256d(&[]));

    // hashSequence (empty)
    hw.extend_from_slice(&sha256d(&[]));

    // hashOutputs
    let hash_outputs = if let Some((addr, amount)) = transparent_output {
        let mut data = Vec::new();
        data.extend_from_slice(&(amount as i64).to_le_bytes());
        let pubkey_hash = crate::keys::address_to_pubkey_hash(addr)
            .map_err(|e| format!("output addr: {e}"))?;
        let script = crate::script::p2pkh_script(&pubkey_hash);
        write_compact_size(&mut data, script.len());
        data.extend_from_slice(&script);
        sha256d(&data)
    } else {
        sha256d(&[])
    };
    hw.extend_from_slice(&hash_outputs);

    // nLockTime
    hw.extend_from_slice(&0u32.to_le_bytes());

    // nType (u16 LE)
    hw.extend_from_slice(&KERRIGAN_SAPLING_TYPE.to_le_bytes());

    // payloadVersion (u16 LE)
    hw.extend_from_slice(&SAPLING_PAYLOAD_VERSION.to_le_bytes());

    // hashShieldedSpends
    let hash_spends = {
        let mut data = Vec::new();
        for spend in bundle.shielded_spends() {
            data.extend_from_slice(&spend.cv().to_bytes());
            data.extend_from_slice(&spend.anchor().to_bytes());
            data.extend_from_slice(&spend.nullifier().0);
            data.extend_from_slice(&<[u8; 32]>::from(*spend.rk()));
            data.extend_from_slice(spend.zkproof());
        }
        sha256d(&data)
    };
    hw.extend_from_slice(&hash_spends);

    // hashShieldedOutputs
    let hash_outputs_shielded = {
        let mut data = Vec::new();
        for output in bundle.shielded_outputs() {
            data.extend_from_slice(&output.cv().to_bytes());
            data.extend_from_slice(&output.cmu().to_bytes());
            data.extend_from_slice(output.ephemeral_key().as_ref());
            data.extend_from_slice(output.enc_ciphertext());
            data.extend_from_slice(output.out_ciphertext());
            data.extend_from_slice(output.zkproof());
        }
        sha256d(&data)
    };
    hw.extend_from_slice(&hash_outputs_shielded);

    // valueBalance
    let vb: i64 = *bundle.value_balance();
    hw.extend_from_slice(&vb.to_le_bytes());

    Ok(sha256d(&hw))
}

// ---------------------------------------------------------------------------
// Serialize sapling-only tx (shield-to-shield, no transparent)
// ---------------------------------------------------------------------------

/// Serialize a Kerrigan type 10 tx with only sapling data (no transparent I/O).
pub fn serialize_kerrigan_sapling_only_tx(
    bundle: &Bundle<Authorized, i64>,
    _sighash: &[u8; 32],
) -> Result<String, String> {
    let mut tx = Vec::new();

    // Header
    let header: u32 = ((KERRIGAN_SAPLING_TYPE as u32) << 16) | (KERRIGAN_TX_VERSION as u32);
    tx.extend_from_slice(&header.to_le_bytes());

    // Empty vin/vout
    write_compact_size(&mut tx, 0);
    write_compact_size(&mut tx, 0);

    // nLockTime
    tx.extend_from_slice(&0u32.to_le_bytes());

    // Extra payload
    let payload = build_sapling_payload(bundle)?;
    write_compact_size(&mut tx, payload.len());
    tx.extend_from_slice(&payload);

    Ok(encoding::hex_encode(&tx))
}

// ---------------------------------------------------------------------------
// Serialize unshield tx (sapling spends → transparent output)
// ---------------------------------------------------------------------------

/// Serialize a Kerrigan type 10 unshield tx (sapling → transparent).
pub fn serialize_kerrigan_unshield_tx(
    to_address: &str,
    amount: u64,
    bundle: &Bundle<Authorized, i64>,
    _sighash: &[u8; 32],
) -> Result<String, String> {
    let mut tx = Vec::new();

    // Header
    let header: u32 = ((KERRIGAN_SAPLING_TYPE as u32) << 16) | (KERRIGAN_TX_VERSION as u32);
    tx.extend_from_slice(&header.to_le_bytes());

    // No transparent inputs
    write_compact_size(&mut tx, 0);

    // One transparent output
    write_compact_size(&mut tx, 1);
    tx.extend_from_slice(&(amount as i64).to_le_bytes());
    let pubkey_hash = crate::keys::address_to_pubkey_hash(to_address)
        .map_err(|e| format!("output addr: {e}"))?;
    let script = crate::script::p2pkh_script(&pubkey_hash);
    write_compact_size(&mut tx, script.len());
    tx.extend_from_slice(&script);

    // nLockTime
    tx.extend_from_slice(&0u32.to_le_bytes());

    // Extra payload
    let payload = build_sapling_payload(bundle)?;
    write_compact_size(&mut tx, payload.len());
    tx.extend_from_slice(&payload);

    Ok(encoding::hex_encode(&tx))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// SHA-256d (double SHA-256).
fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

/// Write a Bitcoin-style compact size (varint).
fn write_compact_size(buf: &mut Vec<u8>, n: usize) {
    if n < 253 {
        buf.push(n as u8);
    } else if n <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&(n as u64).to_le_bytes());
    }
}
