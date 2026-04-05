# kerrigan-sdk

Pure-Rust wallet primitives for the Kerrigan Network. No I/O, no network, no filesystem — compiles to native, WASM, and mobile.

## What's inside

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

## Quick start

```rust
use kerrigan_sdk::{bip39, keys, wallet, sync};

// Create a wallet
let data = wallet::create_wallet_data().unwrap();
println!("Address: {}", data.address);     // K...
println!("Mnemonic: {}", data.mnemonic());  // 24 words

// Import from mnemonic
let data = wallet::import_wallet_data("abandon abandon ... about").unwrap();

// Build a transaction
let signed = wallet::prepare_send(&data, "KDestination...", 50_000_000).unwrap();
println!("TX hex: {}", signed.tx_hex);  // broadcast however you want
println!("Fee: {} sat", signed.fee);

// Send max (entire balance minus fee)
let signed = wallet::prepare_send_max(&data, "KDestination...").unwrap();

// Sync (caller provides transaction data — SDK doesn't do HTTP)
let tx_data: Vec<sync::TxData> = fetch_from_your_source();
let result = sync::process_transactions(None, &tx_data, &data.address, &[]);
println!("Balance: {} sat", result.balance);
println!("UTXOs: {}", result.utxos.len());

// Encrypt for storage (caller provides key)
let key: [u8; 32] = derive_your_encryption_key();
let encrypted = wallet::encrypt_wallet(&data, &key);
let json = serde_json::to_string(&encrypted).unwrap();
// ... save json however you want (file, IndexedDB, etc.)

// Decrypt after loading
let loaded: wallet::WalletData = serde_json::from_str(&json).unwrap();
let decrypted = wallet::decrypt_wallet(loaded, &key).unwrap();
```

## Design philosophy

The SDK **never touches the outside world**. No HTTP, no filesystem, no terminal. The caller provides data in, the SDK processes it and returns results.

This means the same SDK works everywhere:

| Platform | Data source | Storage | Encryption key |
|----------|------------|---------|----------------|
| CLI | `ureq` HTTP | Filesystem | Machine UID |
| WASM | `fetch()` | IndexedDB | User passphrase |
| WebXDC | Realtime channels | localStorage | App-derived |
| Mobile | Platform HTTP | Secure storage | Secure enclave |

## Sync architecture

The SDK defines generic transaction types (`TxData`, `TxInput`, `TxOutput`) that don't know where they came from. The caller converts their data source into these types, then feeds them to the sync engine:

```
Your data source ──→ Vec<TxData> ──→ sync::process_transactions()
                                           │
                                           ▼
                                     SyncResult {
                                       utxos, balance,
                                       history, state
                                     }
```

For incremental sync, persist the `SyncState` and pass it back next time — only new transactions need to be fetched.

## Dependencies

| Crate | Purpose |
|-------|---------|
| `secp256k1` | ECDSA signing + verification (audited, constant-time) |
| `sha2` | SHA-256, SHA-512 (audited, hardware-accelerated) |
| `ripemd` | RIPEMD-160 for Hash160 |
| `hmac` | HMAC construction |
| `serde` + `serde_json` | Serialization |
| `zeroize` | Secure memory clearing |
| `getrandom` | Cryptographic RNG (compiles to WASM via `crypto.getRandomValues()`) |

**Zero platform dependencies.** Everything compiles to `wasm32-unknown-unknown`.

## Testing

```bash
cargo test -p kerrigan-sdk          # 158 tests (144 unit + 14 E2E)
```

Includes BIP39 spec vectors, BIP32 spec vectors (verified against Python `bip32utils`), ECDSA signature verification, UTXO derivation simulations, and encryption roundtrips.

## License

MIT
