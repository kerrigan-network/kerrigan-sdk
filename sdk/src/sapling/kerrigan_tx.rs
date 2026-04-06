/// Kerrigan transaction format serializer.
///
/// Kerrigan uses Dash-style special transactions with type 10 for Sapling.
/// The Sapling data lives in `vExtraPayload`, not inline like Zcash/PIVX.
///
/// Format:
/// ```text
/// n32bitVersion: u32 LE = (nType << 16) | nVersion = (10 << 16) | 3
/// vin:           compact_size + inputs
/// vout:          compact_size + outputs
/// nLockTime:     u32 LE
/// vExtraPayload: compact_size + payload_bytes
/// ```
///
/// Extra payload (SaplingTxPayload):
/// ```text
/// nVersion:     u16 LE (payload version = 1)
/// nSpends:      compact_size
///   per spend:  cv(32) + anchor(32) + nullifier(32) + rk(32) + proof(192) + spendAuthSig(64)
/// nOutputs:     compact_size
///   per output: cv(32) + cmu(32) + epk(32) + enc(580) + out(80) + proof(192)
/// valueBalance: i64 LE
/// bindingSig:   64 bytes (if spends or outputs exist)
/// ```

use pivx_primitives::transaction::Transaction;

use crate::encoding;

/// Kerrigan transaction type for Sapling.
const KERRIGAN_SAPLING_TYPE: u16 = 10;

/// Kerrigan transaction version for Sapling.
const KERRIGAN_TX_VERSION: u16 = 3;

/// Sapling payload version.
const SAPLING_PAYLOAD_VERSION: u16 = 1;

/// Re-serialize a librustpivx Transaction into Kerrigan's type 10 format.
///
/// Takes the built transaction (PIVX v3 type 0 format) and rewrites it
/// with the Sapling data in the extra payload (Kerrigan type 10 format).
pub fn serialize_kerrigan_tx(tx: &Transaction) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();

    // Header: (type << 16) | version
    let header: u32 = ((KERRIGAN_SAPLING_TYPE as u32) << 16) | (KERRIGAN_TX_VERSION as u32);
    buf.extend_from_slice(&header.to_le_bytes());

    // Transparent inputs
    if let Some(transparent) = tx.transparent_bundle() {
        write_compact_size(&mut buf, transparent.vin.len());
        for input in &transparent.vin {
            // Write the raw input bytes
            let mut input_buf = Vec::new();
            input.write(&mut input_buf).map_err(|e| format!("write vin: {e}"))?;
            buf.extend_from_slice(&input_buf);
        }

        // Transparent outputs
        write_compact_size(&mut buf, transparent.vout.len());
        for output in &transparent.vout {
            let mut out_buf = Vec::new();
            output.write(&mut out_buf).map_err(|e| format!("write vout: {e}"))?;
            buf.extend_from_slice(&out_buf);
        }
    } else {
        // No transparent data
        write_compact_size(&mut buf, 0); // vin
        write_compact_size(&mut buf, 0); // vout
    }

    // nLockTime
    buf.extend_from_slice(&tx.lock_time().to_le_bytes());

    // Build the Sapling extra payload
    let payload = build_sapling_payload(tx)?;

    // Write payload as compact_size + bytes
    write_compact_size(&mut buf, payload.len());
    buf.extend_from_slice(&payload);

    Ok(buf)
}

/// Build the Sapling extra payload bytes.
fn build_sapling_payload(tx: &Transaction) -> Result<Vec<u8>, String> {
    let bundle = tx.sapling_bundle()
        .ok_or("no sapling bundle in transaction")?;

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
        payload.extend_from_slice(&<[u8; 32]>::from(spend.rk().clone()));
        // Groth16 proof (192 bytes) — already raw bytes in authorized bundle
        payload.extend_from_slice(spend.zkproof());
        // Spend auth signature (64 bytes)
        let sig_bytes: [u8; 64] = spend.spend_auth_sig().clone().into();
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
        // Groth16 proof (192 bytes) — already raw bytes
        payload.extend_from_slice(output.zkproof());
    }

    // Value balance (i64 LE)
    let vb = bundle.value_balance();
    payload.extend_from_slice(&vb.to_i64_le_bytes());

    // Binding signature (64 bytes) — always present if bundle exists
    let binding_bytes: [u8; 64] = bundle.authorization().binding_sig.clone().into();
    payload.extend_from_slice(&binding_bytes);

    Ok(payload)
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
