/// Address generation, key management, and validation for Kerrigan Network.
use crate::bip32::{ExtendedPrivKey, hash160};
use crate::encoding::{base58check_encode, base58check_decode, EncodingError};
use crate::params;
use std::fmt;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum KeyError {
    InvalidAddress(String),
    InvalidWif(String),
    Bip32(String),
    Encoding(String),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAddress(s) => write!(f, "Invalid address: {s}"),
            Self::InvalidWif(s) => write!(f, "Invalid WIF: {s}"),
            Self::Bip32(s) => write!(f, "BIP32 error: {s}"),
            Self::Encoding(s) => write!(f, "Encoding error: {s}"),
        }
    }
}

impl std::error::Error for KeyError {}

impl From<crate::bip32::Bip32Error> for KeyError {
    fn from(e: crate::bip32::Bip32Error) -> Self {
        Self::Bip32(e.to_string())
    }
}

impl From<EncodingError> for KeyError {
    fn from(e: EncodingError) -> Self {
        Self::Encoding(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Keypair: address, compressed public key (33 bytes), private key (32 bytes).
pub struct Keypair {
    pub address: String,
    pub pubkey: [u8; 33],
    pub privkey: [u8; 32],
}

/// Derive the default keypair from a 64-byte BIP39 seed.
/// Path: m/44'/99888'/0'/0/0
pub fn derive_keypair(seed: &[u8]) -> Result<Keypair, KeyError> {
    derive_keypair_at(seed, 0, 0)
}

/// Derive a keypair at a specific change/index from a 64-byte BIP39 seed.
/// Path: m/44'/99888'/0'/{change}/{index}
pub fn derive_keypair_at(seed: &[u8], change: u32, index: u32) -> Result<Keypair, KeyError> {
    let master = ExtendedPrivKey::from_seed(seed)?;
    let path = format!("m/44'/{}'/{}'/{}/{}", params::BIP44_COIN_TYPE, 0, change, index);
    let child = master.derive_path(&path)?;

    let pubkey = child.public_key_bytes();
    let mut privkey = [0u8; 32];
    privkey.copy_from_slice(child.private_key_bytes());
    let address = pubkey_to_address(&pubkey);

    Ok(Keypair { address, pubkey, privkey })
}

// ---------------------------------------------------------------------------
// Address generation
// ---------------------------------------------------------------------------

/// Convert a compressed public key (33 bytes) to a Kerrigan P2PKH address.
/// SHA256 → RIPEMD160 → Base58Check with prefix 45 → "K..." address.
pub fn pubkey_to_address(pubkey: &[u8; 33]) -> String {
    let pkh = hash160(pubkey);
    base58check_encode(params::PUBKEY_ADDRESS_PREFIX, &pkh)
}

/// Decode a Kerrigan address to its 20-byte pubkey hash.
/// Validates the prefix is P2PKH (45) or P2SH (16).
pub fn address_to_pubkey_hash(address: &str) -> Result<[u8; 20], KeyError> {
    let (version, data) = base58check_decode(address)?;
    if version != params::PUBKEY_ADDRESS_PREFIX && version != params::SCRIPT_ADDRESS_PREFIX {
        return Err(KeyError::InvalidAddress(format!(
            "unexpected version byte {version} (expected {} or {})",
            params::PUBKEY_ADDRESS_PREFIX, params::SCRIPT_ADDRESS_PREFIX
        )));
    }
    if data.len() != 20 {
        return Err(KeyError::InvalidAddress(format!(
            "expected 20-byte hash, got {} bytes", data.len()
        )));
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&data);
    Ok(hash)
}

/// Validate a Kerrigan address (P2PKH or P2SH).
pub fn validate_address(address: &str) -> Result<(), KeyError> {
    address_to_pubkey_hash(address)?;
    Ok(())
}

/// Returns true if the address is a P2PKH address (prefix 45, starts with "K").
pub fn is_p2pkh(address: &str) -> bool {
    base58check_decode(address)
        .map(|(v, d)| v == params::PUBKEY_ADDRESS_PREFIX && d.len() == 20)
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// WIF (Wallet Import Format)
// ---------------------------------------------------------------------------

/// Encode a 32-byte private key to WIF (compressed).
/// Format: [204][32-byte key][0x01] → Base58Check
pub fn privkey_to_wif(privkey: &[u8; 32]) -> String {
    let mut data = Vec::with_capacity(33);
    data.extend_from_slice(privkey);
    data.push(0x01); // compressed flag
    base58check_encode(params::WIF_PREFIX, &data)
}

/// Decode a WIF string to a 32-byte private key.
pub fn wif_to_privkey(wif: &str) -> Result<[u8; 32], KeyError> {
    let (version, data) = base58check_decode(wif)?;
    if version != params::WIF_PREFIX {
        return Err(KeyError::InvalidWif(format!(
            "unexpected version byte {version} (expected {})", params::WIF_PREFIX
        )));
    }
    // Compressed WIF: 33 bytes (32-byte key + 0x01 flag)
    // Uncompressed WIF: 32 bytes (32-byte key, no flag)
    let key_bytes = if data.len() == 33 && data[32] == 0x01 {
        &data[..32]
    } else if data.len() == 32 {
        &data[..]
    } else {
        return Err(KeyError::InvalidWif(format!(
            "unexpected data length {} (expected 32 or 33)", data.len()
        )));
    };

    let mut privkey = [0u8; 32];
    privkey.copy_from_slice(key_bytes);

    // Validate it's a valid secp256k1 key
    secp256k1::SecretKey::from_slice(&privkey)
        .map_err(|_| KeyError::InvalidWif("invalid private key".into()))?;

    Ok(privkey)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip39::{entropy_to_mnemonic, mnemonic_to_seed};
    use crate::encoding::{hex_encode, hex_decode};

    // -- Address generation from known seed --

    #[test]
    fn derive_default_address() {
        // Known seed (from BIP32 test vector 1, extended to 64 bytes via BIP39)
        let entropy = hex_decode("00000000000000000000000000000000").unwrap();
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        let seed = mnemonic_to_seed(&mnemonic, "");

        let kp = derive_keypair(&seed).unwrap();

        // Address should start with 'K'
        assert!(kp.address.starts_with('K'), "Address should start with K: {}", kp.address);

        // Public key should be 33 bytes compressed
        assert_eq!(kp.pubkey.len(), 33);
        assert!(kp.pubkey[0] == 0x02 || kp.pubkey[0] == 0x03);

        // Private key should be 32 bytes
        assert_eq!(kp.privkey.len(), 32);

        // Validate the address
        validate_address(&kp.address).unwrap();
    }

    #[test]
    fn derive_deterministic() {
        // Same seed should always produce the same address
        let seed = hex_decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        ).unwrap();

        let kp1 = derive_keypair(&seed).unwrap();
        let kp2 = derive_keypair(&seed).unwrap();
        assert_eq!(kp1.address, kp2.address);
        assert_eq!(kp1.pubkey, kp2.pubkey);
        assert_eq!(kp1.privkey, kp2.privkey);
    }

    #[test]
    fn derive_different_indices() {
        let seed = hex_decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        ).unwrap();

        let kp0 = derive_keypair_at(&seed, 0, 0).unwrap();
        let kp1 = derive_keypair_at(&seed, 0, 1).unwrap();
        assert_ne!(kp0.address, kp1.address);
        assert_ne!(kp0.pubkey, kp1.pubkey);
    }

    // -- pubkey_to_address --

    #[test]
    fn pubkey_to_address_known() {
        // Use the secp256k1 generator point's public key
        let pubkey_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pubkey_bytes = hex_decode(pubkey_hex).unwrap();
        let mut pubkey = [0u8; 33];
        pubkey.copy_from_slice(&pubkey_bytes);

        let addr = pubkey_to_address(&pubkey);
        assert!(addr.starts_with('K'), "Expected K prefix: {addr}");

        // Verify roundtrip through address_to_pubkey_hash
        let hash = address_to_pubkey_hash(&addr).unwrap();
        // hash160 of this pubkey is well-known: 751e76e8199196d454941c45d1b3a323f1433bd6
        assert_eq!(hex_encode(&hash), "751e76e8199196d454941c45d1b3a323f1433bd6");
    }

    // -- Address validation --

    #[test]
    fn validate_good_address() {
        // Generate a valid address and validate it
        let pkh = [0u8; 20];
        let addr = base58check_encode(params::PUBKEY_ADDRESS_PREFIX, &pkh);
        assert!(addr.starts_with('K'));
        validate_address(&addr).unwrap();
    }

    #[test]
    fn validate_p2sh_address() {
        let hash = [0u8; 20];
        let addr = base58check_encode(params::SCRIPT_ADDRESS_PREFIX, &hash);
        assert!(addr.starts_with('7'));
        validate_address(&addr).unwrap();
    }

    #[test]
    fn validate_wrong_prefix() {
        // Bitcoin mainnet address (version 0)
        let hash = [0u8; 20];
        let addr = base58check_encode(0, &hash);
        assert!(validate_address(&addr).is_err());
    }

    #[test]
    fn validate_bad_checksum() {
        let addr = "K000000000000000000000000000000bad";
        assert!(validate_address(addr).is_err());
    }

    #[test]
    fn is_p2pkh_check() {
        let hash = [0u8; 20];
        let p2pkh = base58check_encode(params::PUBKEY_ADDRESS_PREFIX, &hash);
        let p2sh = base58check_encode(params::SCRIPT_ADDRESS_PREFIX, &hash);
        assert!(is_p2pkh(&p2pkh));
        assert!(!is_p2pkh(&p2sh));
        assert!(!is_p2pkh("garbage"));
    }

    // -- WIF --

    #[test]
    fn wif_roundtrip() {
        // Known private key
        let privkey_hex = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
        let privkey_bytes = hex_decode(privkey_hex).unwrap();
        let mut privkey = [0u8; 32];
        privkey.copy_from_slice(&privkey_bytes);

        let wif = privkey_to_wif(&privkey);
        let decoded = wif_to_privkey(&wif).unwrap();
        assert_eq!(decoded, privkey);
    }

    #[test]
    fn wif_format() {
        let privkey = [0x01u8; 32]; // Simple key
        let wif = privkey_to_wif(&privkey);
        // WIF should be a valid Base58Check string
        let (version, data) = base58check_decode(&wif).unwrap();
        assert_eq!(version, params::WIF_PREFIX);
        assert_eq!(data.len(), 33); // 32 bytes + compressed flag
        assert_eq!(data[32], 0x01); // compressed flag
    }

    #[test]
    fn wif_wrong_prefix() {
        // Create a WIF with wrong prefix (Bitcoin mainnet WIF prefix 128)
        let privkey = [0x01u8; 32];
        let mut data = Vec::with_capacity(33);
        data.extend_from_slice(&privkey);
        data.push(0x01);
        let bad_wif = base58check_encode(128, &data);
        assert!(matches!(wif_to_privkey(&bad_wif), Err(KeyError::InvalidWif(_))));
    }

    // -- Full pipeline: mnemonic → seed → keypair → address → validate --

    #[test]
    fn full_pipeline() {
        let entropy = hex_decode("abcdef0123456789abcdef0123456789").unwrap();
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        let seed = mnemonic_to_seed(&mnemonic, "");
        let kp = derive_keypair(&seed).unwrap();

        // Address is valid
        validate_address(&kp.address).unwrap();
        assert!(kp.address.starts_with('K'));

        // WIF roundtrip
        let wif = privkey_to_wif(&kp.privkey);
        let recovered = wif_to_privkey(&wif).unwrap();
        assert_eq!(recovered, kp.privkey);

        // Pubkey hash roundtrip
        let hash = address_to_pubkey_hash(&kp.address).unwrap();
        assert_eq!(hash, hash160(&kp.pubkey));
    }
}
