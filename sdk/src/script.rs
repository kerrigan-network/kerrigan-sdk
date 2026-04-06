/// Bitcoin script construction for Kerrigan Network.
///
/// Supports P2PKH and P2SH script types, with an extensible [`ScriptType`] enum
/// designed for future additions (e.g., P2SH-P2WPKH, Sapling-related scripts).
///
/// # Script types
///
/// | Type  | scriptPubKey pattern                                          | Address prefix |
/// |-------|---------------------------------------------------------------|----------------|
/// | P2PKH | `OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG`| `K...` (45)    |
/// | P2SH  | `OP_HASH160 <20-byte hash> OP_EQUAL`                         | `7...` (16)    |
use crate::encoding::{base58check_decode, EncodingError};
use crate::params;
use std::fmt;

// ---------------------------------------------------------------------------
// Opcodes (named constants for readability and future extension)
// ---------------------------------------------------------------------------

/// Standard Bitcoin opcodes used in Kerrigan script construction.
///
/// Only the opcodes needed for currently supported script types are defined.
/// Add new opcodes here as additional script types are implemented.
pub mod opcodes {
    /// Push the next N bytes onto the stack (N encoded as the opcode value itself for N < 76).
    /// Not an opcode per se — the byte 0x14 means "push the next 20 bytes."
    pub const OP_PUSH_20: u8 = 0x14;

    pub const OP_DUP: u8 = 0x76;
    pub const OP_HASH160: u8 = 0xa9;
    pub const OP_EQUAL: u8 = 0x87;
    pub const OP_EQUALVERIFY: u8 = 0x88;
    pub const OP_CHECKSIG: u8 = 0xac;

    // Future opcodes (SegWit, Taproot, etc.) go here:
    // pub const OP_0: u8 = 0x00;
    // pub const OP_CHECKMULTISIG: u8 = 0xae;
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum ScriptError {
    /// Address could not be decoded or has an unrecognized version byte.
    InvalidAddress(String),
    /// The pubkey hash is not the expected 20 bytes.
    InvalidPubkeyHash,
    /// Script type is not supported for the requested operation.
    UnsupportedScriptType(String),
    /// Base58 / encoding error from a lower layer.
    Encoding(String),
}

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAddress(s) => write!(f, "Invalid address: {s}"),
            Self::InvalidPubkeyHash => write!(f, "Invalid pubkey hash (expected 20 bytes)"),
            Self::UnsupportedScriptType(s) => write!(f, "Unsupported script type: {s}"),
            Self::Encoding(s) => write!(f, "Encoding error: {s}"),
        }
    }
}

impl std::error::Error for ScriptError {}

impl From<EncodingError> for ScriptError {
    fn from(e: EncodingError) -> Self {
        Self::Encoding(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Script types
// ---------------------------------------------------------------------------

/// Recognized script output types.
///
/// This enum is the primary extension point for future transaction types.
/// When adding a new variant, also update [`script_pubkey`] and
/// [`address_to_script_type`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptType {
    /// Pay-to-Public-Key-Hash (standard transparent output).
    P2PKH,
    /// Pay-to-Script-Hash (multi-sig, time-locked, or wrapped scripts).
    P2SH,
    // Future variants:
    // P2WPKH,        // native SegWit v0
    // P2WSH,         // native SegWit v0 script
    // SaplingOutput,  // Sapling shielded output
}

impl fmt::Display for ScriptType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::P2PKH => write!(f, "P2PKH"),
            Self::P2SH => write!(f, "P2SH"),
        }
    }
}

// ---------------------------------------------------------------------------
// scriptPubKey construction
// ---------------------------------------------------------------------------

/// Build a scriptPubKey from a script type and a 20-byte hash.
///
/// This is the low-level builder — callers provide the hash directly.
/// For building from an address string, use [`address_to_script_pubkey`].
///
/// # Script formats
///
/// **P2PKH** (25 bytes):
/// ```text
/// OP_DUP OP_HASH160 OP_PUSH_20 <20-byte pubkey hash> OP_EQUALVERIFY OP_CHECKSIG
/// ```
///
/// **P2SH** (23 bytes):
/// ```text
/// OP_HASH160 OP_PUSH_20 <20-byte script hash> OP_EQUAL
/// ```
pub fn script_pubkey(script_type: ScriptType, hash: &[u8; 20]) -> Vec<u8> {
    match script_type {
        ScriptType::P2PKH => {
            let mut s = Vec::with_capacity(25);
            s.push(opcodes::OP_DUP);
            s.push(opcodes::OP_HASH160);
            s.push(opcodes::OP_PUSH_20);
            s.extend_from_slice(hash);
            s.push(opcodes::OP_EQUALVERIFY);
            s.push(opcodes::OP_CHECKSIG);
            s
        }
        ScriptType::P2SH => {
            let mut s = Vec::with_capacity(23);
            s.push(opcodes::OP_HASH160);
            s.push(opcodes::OP_PUSH_20);
            s.extend_from_slice(hash);
            s.push(opcodes::OP_EQUAL);
            s
        }
    }
}

/// Build a P2PKH scriptPubKey from a 20-byte pubkey hash (convenience wrapper).
pub fn p2pkh_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    script_pubkey(ScriptType::P2PKH, pubkey_hash)
}

/// Build a P2SH scriptPubKey from a 20-byte script hash (convenience wrapper).
pub fn p2sh_script(script_hash: &[u8; 20]) -> Vec<u8> {
    script_pubkey(ScriptType::P2SH, script_hash)
}

// ---------------------------------------------------------------------------
// scriptSig construction
// ---------------------------------------------------------------------------

/// Build a P2PKH scriptSig (input unlocking script).
///
/// ```text
/// <sig_len> <DER signature || SIGHASH byte> <pubkey_len> <compressed pubkey>
/// ```
///
/// The signature must already include the trailing SIGHASH type byte.
pub fn p2pkh_script_sig(signature_with_hashtype: &[u8], pubkey: &[u8; 33]) -> Vec<u8> {
    let mut s = Vec::with_capacity(2 + signature_with_hashtype.len() + pubkey.len());
    s.push(signature_with_hashtype.len() as u8);
    s.extend_from_slice(signature_with_hashtype);
    s.push(pubkey.len() as u8);
    s.extend_from_slice(pubkey);
    s
}

// ---------------------------------------------------------------------------
// Address ↔ script conversion
// ---------------------------------------------------------------------------

/// Determine the [`ScriptType`] for a Kerrigan address based on its version byte.
pub fn address_to_script_type(address: &str) -> Result<ScriptType, ScriptError> {
    let (version, _) = base58check_decode(address)?;
    match version {
        params::PUBKEY_ADDRESS_PREFIX => Ok(ScriptType::P2PKH),
        params::SCRIPT_ADDRESS_PREFIX => Ok(ScriptType::P2SH),
        _ => Err(ScriptError::InvalidAddress(format!(
            "unrecognized version byte {version}"
        ))),
    }
}

/// Decode a Kerrigan address to its scriptPubKey.
///
/// Supports P2PKH (`K...`) and P2SH (`7...`) addresses.
/// Returns the raw script bytes suitable for embedding in a transaction output.
pub fn address_to_script_pubkey(address: &str) -> Result<Vec<u8>, ScriptError> {
    let (version, data) = base58check_decode(address)?;
    if data.len() != 20 {
        return Err(ScriptError::InvalidAddress(format!(
            "expected 20-byte hash, got {} bytes", data.len()
        )));
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&data);

    match version {
        params::PUBKEY_ADDRESS_PREFIX => Ok(p2pkh_script(&hash)),
        params::SCRIPT_ADDRESS_PREFIX => Ok(p2sh_script(&hash)),
        _ => Err(ScriptError::InvalidAddress(format!(
            "unrecognized version byte {version}"
        ))),
    }
}

/// Returns the script length for a given script type.
/// Useful for fee estimation without constructing the full script.
pub fn script_pubkey_size(script_type: ScriptType) -> usize {
    match script_type {
        ScriptType::P2PKH => 25,
        ScriptType::P2SH => 23,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip32::hash160;
    use crate::encoding::{hex_encode, hex_decode, base58check_encode};

    // -- Opcode sanity --

    #[test]
    fn opcode_values() {
        assert_eq!(opcodes::OP_DUP, 0x76);
        assert_eq!(opcodes::OP_HASH160, 0xa9);
        assert_eq!(opcodes::OP_PUSH_20, 0x14);
        assert_eq!(opcodes::OP_EQUAL, 0x87);
        assert_eq!(opcodes::OP_EQUALVERIFY, 0x88);
        assert_eq!(opcodes::OP_CHECKSIG, 0xac);
    }

    // -- P2PKH scriptPubKey --

    #[test]
    fn p2pkh_script_known_hash() {
        // Well-known hash160: 751e76e8199196d454941c45d1b3a323f1433bd6
        let hash = hex_decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let mut h = [0u8; 20];
        h.copy_from_slice(&hash);

        let script = p2pkh_script(&h);
        assert_eq!(
            hex_encode(&script),
            "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
        );
        assert_eq!(script.len(), 25);
    }

    #[test]
    fn p2pkh_script_zero_hash() {
        let h = [0u8; 20];
        let script = p2pkh_script(&h);
        assert_eq!(script.len(), 25);
        // OP_DUP OP_HASH160 OP_PUSH_20 [00*20] OP_EQUALVERIFY OP_CHECKSIG
        assert_eq!(script[0], 0x76);
        assert_eq!(script[1], 0xa9);
        assert_eq!(script[2], 0x14);
        assert_eq!(&script[3..23], &[0u8; 20]);
        assert_eq!(script[23], 0x88);
        assert_eq!(script[24], 0xac);
    }

    // -- P2SH scriptPubKey --

    #[test]
    fn p2sh_script_known_hash() {
        let hash = hex_decode("89abcdefabbaabbaabbaabbaabbaabbaabbaabba").unwrap();
        let mut h = [0u8; 20];
        h.copy_from_slice(&hash);

        let script = p2sh_script(&h);
        assert_eq!(
            hex_encode(&script),
            "a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87"
        );
        assert_eq!(script.len(), 23);
    }

    #[test]
    fn p2sh_script_structure() {
        let h = [0xffu8; 20];
        let script = p2sh_script(&h);
        assert_eq!(script[0], opcodes::OP_HASH160);
        assert_eq!(script[1], opcodes::OP_PUSH_20);
        assert_eq!(&script[2..22], &[0xff; 20]);
        assert_eq!(script[22], opcodes::OP_EQUAL);
    }

    // -- Script type enum --

    #[test]
    fn script_type_via_enum() {
        let h = [0u8; 20];
        let p2pkh = script_pubkey(ScriptType::P2PKH, &h);
        let p2sh = script_pubkey(ScriptType::P2SH, &h);

        assert_eq!(p2pkh.len(), 25);
        assert_eq!(p2sh.len(), 23);
        assert_ne!(p2pkh, p2sh);
    }

    #[test]
    fn script_pubkey_size_matches_actual() {
        let h = [0u8; 20];
        assert_eq!(script_pubkey_size(ScriptType::P2PKH), p2pkh_script(&h).len());
        assert_eq!(script_pubkey_size(ScriptType::P2SH), p2sh_script(&h).len());
    }

    // -- scriptSig --

    #[test]
    fn p2pkh_script_sig_structure() {
        // Fake DER signature (72 bytes) + SIGHASH_ALL byte
        let mut sig = vec![0x30u8; 72];
        sig.push(0x01); // SIGHASH_ALL
        let pubkey = [0x02u8; 33]; // Fake compressed pubkey

        let script_sig = p2pkh_script_sig(&sig, &pubkey);

        // [sig_len=73][sig(73 bytes)][pubkey_len=33][pubkey(33 bytes)]
        assert_eq!(script_sig.len(), 1 + 73 + 1 + 33);
        assert_eq!(script_sig[0], 73); // sig length
        assert_eq!(&script_sig[1..74], &sig);
        assert_eq!(script_sig[74], 33); // pubkey length
        assert_eq!(&script_sig[75..108], &pubkey);
    }

    #[test]
    fn p2pkh_script_sig_variable_sig_length() {
        // Shorter signature (70 bytes + sighash)
        let mut sig = vec![0x30u8; 70];
        sig.push(0x01);
        let pubkey = [0x03u8; 33];

        let script_sig = p2pkh_script_sig(&sig, &pubkey);
        assert_eq!(script_sig[0], 71); // sig length byte
        assert_eq!(script_sig.len(), 1 + 71 + 1 + 33);
    }

    // -- Address → scriptPubKey conversion --

    #[test]
    fn address_to_script_p2pkh() {
        let hash = [0u8; 20];
        let addr = base58check_encode(params::PUBKEY_ADDRESS_PREFIX, &hash);
        assert!(addr.starts_with('K'));

        let script = address_to_script_pubkey(&addr).unwrap();
        assert_eq!(script, p2pkh_script(&hash));
    }

    #[test]
    fn address_to_script_p2sh() {
        let hash = [0xABu8; 20];
        let addr = base58check_encode(params::SCRIPT_ADDRESS_PREFIX, &hash);
        assert!(addr.starts_with('7'));

        let script = address_to_script_pubkey(&addr).unwrap();
        assert_eq!(script, p2sh_script(&hash));
    }

    #[test]
    fn address_to_script_wrong_prefix() {
        // Bitcoin mainnet (version 0)
        let hash = [0u8; 20];
        let addr = base58check_encode(0, &hash);
        assert!(address_to_script_pubkey(&addr).is_err());
    }

    #[test]
    fn address_to_script_type_p2pkh() {
        let hash = [0u8; 20];
        let addr = base58check_encode(params::PUBKEY_ADDRESS_PREFIX, &hash);
        assert_eq!(address_to_script_type(&addr).unwrap(), ScriptType::P2PKH);
    }

    #[test]
    fn address_to_script_type_p2sh() {
        let hash = [0u8; 20];
        let addr = base58check_encode(params::SCRIPT_ADDRESS_PREFIX, &hash);
        assert_eq!(address_to_script_type(&addr).unwrap(), ScriptType::P2SH);
    }

    #[test]
    fn address_to_script_type_unknown() {
        let hash = [0u8; 20];
        let addr = base58check_encode(99, &hash);
        assert!(address_to_script_type(&addr).is_err());
    }

    // -- Round-trip: pubkey → hash → address → script → verify hash --

    #[test]
    fn pubkey_to_script_roundtrip() {
        // secp256k1 generator point compressed pubkey
        let pubkey = hex_decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        let pkh = hash160(&pubkey);

        let addr = base58check_encode(params::PUBKEY_ADDRESS_PREFIX, &pkh);
        let script = address_to_script_pubkey(&addr).unwrap();

        // The hash embedded in the script should match our original hash160
        assert_eq!(&script[3..23], &pkh);
    }

    // -- Script display --

    #[test]
    fn script_type_display() {
        assert_eq!(format!("{}", ScriptType::P2PKH), "P2PKH");
        assert_eq!(format!("{}", ScriptType::P2SH), "P2SH");
    }

    // -- Edge: garbage address --

    #[test]
    fn address_to_script_garbage() {
        assert!(address_to_script_pubkey("not_a_valid_address!!!").is_err());
        assert!(address_to_script_pubkey("").is_err());
    }
}
