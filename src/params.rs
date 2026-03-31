/// Kerrigan Network chain parameters.
/// Single source of truth for all network constants.

// -- Coin --
pub const NETWORK_NAME: &str = "Kerrigan";
pub const TICKER: &str = "KRGN";
pub const DECIMALS: u32 = 8;
pub const COIN: u64 = 100_000_000;

// -- Address prefixes (Base58Check version bytes) --
pub const PUBKEY_ADDRESS_PREFIX: u8 = 45;  // K...
pub const SCRIPT_ADDRESS_PREFIX: u8 = 16;  // 7...
pub const WIF_PREFIX: u8 = 204;

// -- BIP44 --
pub const BIP44_COIN_TYPE: u32 = 99888;

// -- BIP32 extended key version bytes --
pub const XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
pub const XPRV_VERSION: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];

// -- Network --
pub const NETWORK_MAGIC: [u8; 4] = [0x4B, 0x52, 0x47, 0x4E]; // "KRGN"
pub const P2P_PORT: u16 = 7120;
pub const RPC_PORT: u16 = 7121;
pub const BLOCK_TIME_SECONDS: u32 = 120;

// -- Explorer --
pub const EXPLORER_URL: &str = "https://explorer.kerrigan.network";

// -- Transaction --
pub const TX_VERSION: u32 = 1;
pub const SIGHASH_ALL: u32 = 1;
pub const DEFAULT_FEE_PER_BYTE: u64 = 10;
pub const DUST_THRESHOLD: u64 = 546;

// -- Wallet storage --
pub const DATA_DIR_NAME: &str = "kerrigan-wallet";
pub const DEVICE_ENCRYPTION_SALT: &[u8] = b"kerrigan-wallet-device-encryption";
pub const WALLET_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_produces_k_address() {
        // Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
        // Prefix byte 45 with 20 zero bytes encodes to a string starting with 'K'
        // This is validated end-to-end in keys tests; here we just sanity-check the constant.
        assert_eq!(PUBKEY_ADDRESS_PREFIX, 45);
        assert_eq!(SCRIPT_ADDRESS_PREFIX, 16);
        assert_eq!(WIF_PREFIX, 204);
    }

    #[test]
    fn coin_constant() {
        assert_eq!(COIN, 100_000_000);
        assert_eq!(DECIMALS, 8);
    }

    #[test]
    fn bip44_coin_type() {
        assert_eq!(BIP44_COIN_TYPE, 99888);
    }
}
