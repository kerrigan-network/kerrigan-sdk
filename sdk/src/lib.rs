/// Kerrigan SDK — pure-Rust transparent wallet primitives.
///
/// No I/O, no network, no filesystem. Compiles to native, WASM, and mobile.
///
/// # Modules
///
/// | Module | Purpose |
/// |--------|---------|
/// | [`params`] | Chain constants (prefixes, coin type, fees) |
/// | [`encoding`] | Hex, Base58Check, varint, SHA256d |
/// | [`bip39`] | BIP39 mnemonic + PBKDF2-HMAC-SHA512 (from scratch) |
/// | [`bip32`] | BIP32 HD keys (from scratch) |
/// | [`keys`] | Address generation, WIF, validation |
/// | [`script`] | P2PKH/P2SH script construction |
/// | [`fees`] | Component-based fee estimation |
/// | [`transaction`] | Serialization, SIGHASH_ALL, ECDSA signing, UTXO selection |
/// | [`sync`] | UTXO derivation from transaction data (pure logic) |
/// | [`wallet`] | Wallet state, encryption, send preparation |

pub mod params;
pub mod encoding;
pub mod bip39;
pub mod bip32;
pub mod keys;
pub mod script;
pub mod fees;
pub mod transaction;
pub mod sync;
pub mod wallet;
pub mod sapling;
