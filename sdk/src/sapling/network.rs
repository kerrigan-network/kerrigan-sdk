/// Kerrigan Network — Sapling consensus parameters.
///
/// Implements the zcash consensus traits so all upstream crate code
/// (key derivation, encoding, transaction building) works with Kerrigan's
/// Sapling activation height, address HRP, and transparent prefixes.
use pivx_protocol::consensus::{BlockHeight, NetworkType, NetworkUpgrade, Parameters};

// ---------------------------------------------------------------------------
// Network definition
// ---------------------------------------------------------------------------

/// Kerrigan mainnet parameters for Sapling.
///
/// Note: `Parameters` has a blanket impl of `NetworkConstants` that returns
/// Zcash defaults (since `network_type() == Main`). For Kerrigan-specific
/// HRPs and prefixes, use the constants in this module directly rather than
/// the `NetworkConstants` trait methods.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KerriganMainNetwork;

impl Parameters for KerriganMainNetwork {
    fn network_type(&self) -> NetworkType {
        NetworkType::Main
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Sapling => Some(BlockHeight::from_u32(SAPLING_ACTIVATION_HEIGHT)),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sapling activation height on Kerrigan mainnet.
pub const SAPLING_ACTIVATION_HEIGHT: u32 = 500;

/// Depth of the Sapling commitment Merkle tree.
pub const SAPLING_TREE_DEPTH: u8 = 32;

/// Maximum number of Sapling spends per transaction.
pub const MAX_SAPLING_SPENDS: usize = 500;

/// Maximum number of Sapling outputs per transaction.
pub const MAX_SAPLING_OUTPUTS: usize = 500;

/// Sapling transaction version (nVersion=3, nType=10 → TRANSACTION_SAPLING).
pub const SAPLING_TX_VERSION: u32 = 3;

/// HRP for Sapling payment addresses (bech32): `ks1...`
pub const HRP_SAPLING_PAYMENT_ADDRESS: &str = "ks";

/// HRP for Sapling extended spending keys (bech32).
pub const HRP_SAPLING_EXTENDED_SPENDING_KEY: &str = "ks-secret";

/// HRP for Sapling extended full viewing keys (bech32).
pub const HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY: &str = "ks-viewing";

/// Base58 transparent P2PKH prefix — produces `K...` addresses.
pub const B58_PUBKEY_ADDRESS_PREFIX: [u8; 2] = [0, 45];

/// Base58 transparent P2SH prefix — produces `7...` addresses.
pub const B58_SCRIPT_ADDRESS_PREFIX: [u8; 2] = [0, 16];

/// Sapling proving parameter SHA-256 hashes (Zcash originals).
pub const OUTPUT_PARAMS_SHA256: &str =
    "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4";
pub const SPEND_PARAMS_SHA256: &str =
    "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_type_is_main() {
        assert_eq!(KerriganMainNetwork.network_type(), NetworkType::Main);
    }

    #[test]
    fn sapling_activation_at_500() {
        let height = KerriganMainNetwork.activation_height(NetworkUpgrade::Sapling);
        assert_eq!(height, Some(BlockHeight::from_u32(500)));
    }

    #[test]
    fn no_other_activation_heights() {
        // Kerrigan only defines Sapling — everything else is None.
        assert!(KerriganMainNetwork.activation_height(NetworkUpgrade::Overwinter).is_none());
    }

    #[test]
    fn hrp_constants() {
        // Kerrigan-specific HRPs (NOT from the blanket NetworkConstants impl).
        assert_eq!(HRP_SAPLING_PAYMENT_ADDRESS, "ks");
        assert_eq!(HRP_SAPLING_EXTENDED_SPENDING_KEY, "ks-secret");
        assert_eq!(HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY, "ks-viewing");
    }

    #[test]
    fn transparent_prefix_constants() {
        assert_eq!(B58_PUBKEY_ADDRESS_PREFIX, [0, 45]);
        assert_eq!(B58_SCRIPT_ADDRESS_PREFIX, [0, 16]);
    }

    #[test]
    fn tree_depth_is_32() {
        assert_eq!(SAPLING_TREE_DEPTH, 32);
    }
}
