/// ZIP32 Sapling key derivation for the Kerrigan Network.
///
/// Derives shielded keys from BIP39 seeds using the standard ZIP32 path:
/// `m_sapling / purpose' / coin_type' / account'`
///
/// Kerrigan coin type: 99888

use sapling::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};
use sapling::PaymentAddress;
use zcash_keys::encoding;
use zcash_keys::keys::sapling as sapling_keys;
use pivx_primitives::zip32::AccountId;

use super::network;
use crate::params;

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derive a Sapling extended spending key from a seed.
///
/// Uses ZIP32 derivation: `m_sapling / purpose' / coin_type' / account'`
/// with Kerrigan's coin type (99888).
pub fn spending_key_from_seed(
    seed: &[u8],
    coin_type: u32,
    account: u32,
) -> Result<ExtendedSpendingKey, SaplingKeyError> {
    let account_id = AccountId::try_from(account)
        .map_err(|_| SaplingKeyError::InvalidAccount(account))?;
    Ok(sapling_keys::spending_key(seed, coin_type, account_id))
}

/// Derive a Sapling extended spending key using Kerrigan defaults.
///
/// Equivalent to `spending_key_from_seed(seed, 99888, 0)`.
pub fn default_spending_key(seed: &[u8]) -> Result<ExtendedSpendingKey, SaplingKeyError> {
    spending_key_from_seed(seed, params::BIP44_COIN_TYPE, 0)
}

/// Derive the extended full viewing key from an extended spending key.
#[allow(deprecated)]
pub fn full_viewing_key(extsk: &ExtendedSpendingKey) -> ExtendedFullViewingKey {
    extsk.to_extended_full_viewing_key()
}

/// Derive the default payment address from an extended full viewing key.
pub fn default_payment_address(extfvk: &ExtendedFullViewingKey) -> PaymentAddress {
    let (_, addr) = extfvk.default_address();
    addr
}

/// Derive the nullifier deriving key from an extended full viewing key.
pub fn nullifier_deriving_key(
    extfvk: &ExtendedFullViewingKey,
) -> sapling::NullifierDerivingKey {
    extfvk.fvk.vk.nk
}

// ---------------------------------------------------------------------------
// Encoding — bech32 with Kerrigan HRPs
// ---------------------------------------------------------------------------

/// Encode a Sapling payment address as a bech32 string: `ks1...`
pub fn encode_payment_address(addr: &PaymentAddress) -> String {
    encoding::encode_payment_address(network::HRP_SAPLING_PAYMENT_ADDRESS, addr)
}

/// Decode a `ks1...` bech32 string to a Sapling payment address.
pub fn decode_payment_address(encoded: &str) -> Result<PaymentAddress, SaplingKeyError> {
    encoding::decode_payment_address(network::HRP_SAPLING_PAYMENT_ADDRESS, encoded)
        .map_err(|e| SaplingKeyError::Encoding(format!("{e}")))
}

/// Encode an extended spending key as a bech32 string.
pub fn encode_extsk(extsk: &ExtendedSpendingKey) -> String {
    encoding::encode_extended_spending_key(network::HRP_SAPLING_EXTENDED_SPENDING_KEY, extsk)
}

/// Decode a bech32 extended spending key string.
pub fn decode_extsk(encoded: &str) -> Result<ExtendedSpendingKey, SaplingKeyError> {
    encoding::decode_extended_spending_key(network::HRP_SAPLING_EXTENDED_SPENDING_KEY, encoded)
        .map_err(|e| SaplingKeyError::Encoding(format!("{e}")))
}

/// Encode an extended full viewing key as a bech32 string.
pub fn encode_extfvk(extfvk: &ExtendedFullViewingKey) -> String {
    encoding::encode_extended_full_viewing_key(
        network::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
        extfvk,
    )
}

/// Decode a bech32 extended full viewing key string.
pub fn decode_extfvk(encoded: &str) -> Result<ExtendedFullViewingKey, SaplingKeyError> {
    encoding::decode_extended_full_viewing_key(
        network::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
        encoded,
    )
    .map_err(|e| SaplingKeyError::Encoding(format!("{e}")))
}

// ---------------------------------------------------------------------------
// Convenience — full pipeline from seed to encoded address
// ---------------------------------------------------------------------------

/// One-shot: seed → extended spending key → full viewing key → payment address → bech32.
pub fn derive_shielded_address(seed: &[u8]) -> Result<String, SaplingKeyError> {
    let extsk = default_spending_key(seed)?;
    let extfvk = full_viewing_key(&extsk);
    let addr = default_payment_address(&extfvk);
    Ok(encode_payment_address(&addr))
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum SaplingKeyError {
    InvalidAccount(u32),
    Encoding(String),
}

impl std::fmt::Display for SaplingKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAccount(n) => write!(f, "invalid Sapling account index: {n}"),
            Self::Encoding(e) => write!(f, "Sapling key encoding error: {e}"),
        }
    }
}

impl std::error::Error for SaplingKeyError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic 64-byte seed for testing (all zeros — NOT for production).
    fn test_seed() -> [u8; 64] {
        [0u8; 64]
    }

    /// A different seed to verify different keys are derived.
    fn alt_seed() -> [u8; 64] {
        let mut s = [0u8; 64];
        s[0] = 1;
        s
    }

    #[test]
    fn derive_spending_key_succeeds() {
        let extsk = spending_key_from_seed(&test_seed(), params::BIP44_COIN_TYPE, 0);
        assert!(extsk.is_ok());
    }

    #[test]
    fn derive_default_spending_key() {
        let extsk = default_spending_key(&test_seed());
        assert!(extsk.is_ok());
    }

    #[test]
    fn derive_full_viewing_key_from_spending_key() {
        let extsk = default_spending_key(&test_seed()).unwrap();
        let _extfvk = full_viewing_key(&extsk);
        // No panic = success — EFVK derivation is infallible.
    }

    #[test]
    fn derive_payment_address() {
        let extsk = default_spending_key(&test_seed()).unwrap();
        let extfvk = full_viewing_key(&extsk);
        let _addr = default_payment_address(&extfvk);
    }

    #[test]
    fn payment_address_starts_with_ks() {
        let encoded = derive_shielded_address(&test_seed()).unwrap();
        assert!(
            encoded.starts_with("ks"),
            "Expected address starting with 'ks', got: {encoded}"
        );
    }

    #[test]
    fn different_seeds_produce_different_addresses() {
        let addr1 = derive_shielded_address(&test_seed()).unwrap();
        let addr2 = derive_shielded_address(&alt_seed()).unwrap();
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn deterministic_derivation() {
        let addr1 = derive_shielded_address(&test_seed()).unwrap();
        let addr2 = derive_shielded_address(&test_seed()).unwrap();
        assert_eq!(addr1, addr2, "Same seed must produce the same address");
    }

    #[test]
    fn coin_type_99888_differs_from_zcash() {
        // Zcash coin type 133 vs Kerrigan 99888 — must produce different keys.
        let zcash = spending_key_from_seed(&test_seed(), 133, 0).unwrap();
        let kerrigan = spending_key_from_seed(&test_seed(), params::BIP44_COIN_TYPE, 0).unwrap();

        let zcash_addr = {
            let fvk = full_viewing_key(&zcash);
            let addr = default_payment_address(&fvk);
            encode_payment_address(&addr)
        };
        let kerrigan_addr = {
            let fvk = full_viewing_key(&kerrigan);
            let addr = default_payment_address(&fvk);
            encode_payment_address(&addr)
        };

        assert_ne!(zcash_addr, kerrigan_addr);
    }

    #[test]
    fn payment_address_encode_decode_roundtrip() {
        let extsk = default_spending_key(&test_seed()).unwrap();
        let extfvk = full_viewing_key(&extsk);
        let addr = default_payment_address(&extfvk);

        let encoded = encode_payment_address(&addr);
        let decoded = decode_payment_address(&encoded).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn extsk_encode_decode_roundtrip() {
        let extsk = default_spending_key(&test_seed()).unwrap();
        let encoded = encode_extsk(&extsk);
        let decoded = decode_extsk(&encoded).unwrap();

        // Verify roundtrip by comparing derived addresses.
        let addr1 = default_payment_address(&full_viewing_key(&extsk));
        let addr2 = default_payment_address(&full_viewing_key(&decoded));
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn extfvk_encode_decode_roundtrip() {
        let extsk = default_spending_key(&test_seed()).unwrap();
        let extfvk = full_viewing_key(&extsk);

        let encoded = encode_extfvk(&extfvk);
        let decoded = decode_extfvk(&encoded).unwrap();

        let addr1 = default_payment_address(&extfvk);
        let addr2 = default_payment_address(&decoded);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn nullifier_key_derivation() {
        let extsk = default_spending_key(&test_seed()).unwrap();
        let extfvk = full_viewing_key(&extsk);
        let _nk = nullifier_deriving_key(&extfvk);
        // No panic = success. NullifierDerivingKey is a field access.
    }

    #[test]
    fn nullifier_key_deterministic() {
        let seed = test_seed();
        let nk1 = {
            let extsk = default_spending_key(&seed).unwrap();
            let extfvk = full_viewing_key(&extsk);
            nullifier_deriving_key(&extfvk)
        };
        let nk2 = {
            let extsk = default_spending_key(&seed).unwrap();
            let extfvk = full_viewing_key(&extsk);
            nullifier_deriving_key(&extfvk)
        };
        assert_eq!(nk1, nk2);
    }

    #[test]
    fn decode_invalid_payment_address_fails() {
        let result = decode_payment_address("ks1invalidgarbage");
        assert!(result.is_err());
    }

    #[test]
    fn different_accounts_produce_different_keys() {
        let extsk0 = spending_key_from_seed(&test_seed(), params::BIP44_COIN_TYPE, 0).unwrap();
        let extsk1 = spending_key_from_seed(&test_seed(), params::BIP44_COIN_TYPE, 1).unwrap();

        let addr0 = default_payment_address(&full_viewing_key(&extsk0));
        let addr1 = default_payment_address(&full_viewing_key(&extsk1));
        assert_ne!(addr0, addr1);
    }
}
