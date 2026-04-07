# kerrigan-sdk

Pure-Rust wallet primitives for the Kerrigan Network. No I/O, no network, no filesystem — compiles to native, WASM, and mobile.

Full Sapling shielded transaction support with Kerrigan-native serialization.

## What's inside

### Transparent

| Module | Purpose |
|--------|---------|
| `params` | Chain constants — address prefixes, coin type, fee rate |
| `encoding` | Hex, Base58Check, varint, SHA256d (from scratch) |
| `bip39` | Mnemonic generation + PBKDF2-HMAC-SHA512 seed derivation (from scratch) |
| `bip32` | HD key derivation at `m/44'/99888'/0'/0/0` (from scratch) |
| `keys` | Address generation, WIF encode/decode, validation |
| `script` | P2PKH/P2SH scriptPubKey + scriptSig construction |
| `fees` | Component-based transaction size and fee estimation |
| `transaction` | Serialization, SIGHASH_ALL, ECDSA signing, UTXO selection |
| `sync` | UTXO derivation from transaction data (pure logic) |
| `wallet` | Wallet state, symmetric encryption, send preparation |

### Sapling (shielded)

| Module | Purpose |
|--------|---------|
| `sapling::network` | Kerrigan Sapling constants (HRP `ks`, activation height 500) |
| `sapling::keys` | ZIP32 key derivation, bech32 encoding, payment addresses |
| `sapling::tree` | Commitment tree operations, hex serialization, witnesses |
| `sapling::notes` | Note types, decryption, transaction processing |
| `sapling::fees` | Sapling fee calculation (Kerrigan formula) |
| `sapling::prover` | Proving parameter types and SHA-256 verification |
| `sapling::builder` | Sapling transaction construction (shield, unshield, private send) |
| `sapling::kerrigan_tx` | Kerrigan type 10 serialization and custom sighash |
| `sapling::sync` | Compact binary stream parser and shield block processing |

## Quick start

```rust
use kerrigan_sdk::{bip39, keys, wallet, sapling};

// Create a wallet (transparent + shielded keys derived automatically)
let data = wallet::create_wallet_data().unwrap();
println!("Public:  {}", data.address);                  // K...
println!("Private: {}", data.sapling_address.unwrap()); // ks1...
println!("Mnemonic: {}", data.mnemonic());              // 24 words

// Import from mnemonic
let data = wallet::import_wallet_data("abandon abandon ... about").unwrap();

// Build a transparent transaction
let signed = wallet::prepare_send(&data, "KDestination...", 50_000_000).unwrap();
println!("TX hex: {}", signed.tx_hex);

// Derive shielded address from seed
let addr = sapling::keys::derive_shielded_address(&data.seed).unwrap();
println!("Shielded: {}", addr); // ks1...

// Encrypt for storage (caller provides key)
let key: [u8; 32] = derive_your_encryption_key();
let encrypted = wallet::encrypt_wallet(&data, &key);
let json = serde_json::to_string(&encrypted).unwrap();
```

## Sapling transaction building

The SDK uses a three-step Kerrigan-native build flow:

1. **Build** unauthorized bundle with `sapling::Builder` (Groth16 proofs generated)
2. **Compute** Kerrigan sighash (differs from Zcash and PIVX — includes `nType` and `payloadVersion`)
3. **Apply** signatures with the correct sighash

Transactions are serialized in Kerrigan's type 10 extra payload format (`0x03000a00` header), not the Zcash v4 format.

```rust
// Shielding (transparent → sapling)
let result = sapling::builder::build_shield(
    &utxos, &privkey, &pubkey, &address, &to_shielded, amount, height, &prover,
).unwrap();

// Shield-to-shield (private → private)
let result = sapling::builder::build_sapling_send(
    &notes, &extsk, &to_addr, amount, memo, &prover,
).unwrap();

// Unshielding (sapling → transparent)
let result = sapling::builder::build_unshield(
    &notes, &extsk, "KAddress...", amount, &prover,
).unwrap();
```

## Compact sync protocol

The SDK defines a binary wire format for efficient shield sync:

| Packet type | Contents | Size per output |
|-------------|----------|-----------------|
| `0x03` Full tx | Raw transaction bytes | 948 bytes |
| `0x04` Compact | cmu + epk + enc_ciphertext only | 644 bytes |

Compact mode strips proofs and signatures that light wallets never verify (42-62% smaller). The `CompactSaplingOutput` type implements `ShieldedOutput` so `try_note_decryption` works directly on compact data.

## Design philosophy

The SDK **never touches the outside world**. No HTTP, no filesystem, no terminal. The caller provides data in, the SDK processes it and returns results.

| Platform | Data source | Storage | Encryption key |
|----------|------------|---------|----------------|
| CLI | `ureq` HTTP | Filesystem | Machine UID |
| WASM | `fetch()` | IndexedDB | User passphrase |
| Mobile | Platform HTTP | Secure storage | Secure enclave |

## Dependencies

| Crate | Purpose |
|-------|---------|
| `sapling` (librustpivx) | Sapling cryptography, Groth16 proofs, ZIP32 |
| `pivx_primitives` (librustpivx) | Transaction types, merkle tree I/O |
| `secp256k1` | ECDSA signing + verification |
| `sha2` | SHA-256, SHA-512 |
| `ripemd` | RIPEMD-160 for Hash160 |
| `hmac` | HMAC construction |
| `serde` + `serde_json` | Serialization |
| `zeroize` | Secure memory clearing |
| `getrandom` | Cryptographic RNG |

## Testing

```bash
cargo test -p kerrigan-sdk    # 276 tests (211 unit + 14 transparent E2E + 51 Sapling E2E)
```

## License

MIT
