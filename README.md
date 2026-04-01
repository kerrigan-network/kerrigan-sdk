<p align="center">
  <strong>kerrigan-wallet</strong><br>
  <em>A minimal, transparent-only light wallet CLI for the Kerrigan Network.</em>
</p>

<p align="center">
  <a href="#features">Features</a> &bull;
  <a href="#install">Install</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#security">Security</a> &bull;
  <a href="#building">Building</a> &bull;
  <a href="#testing">Testing</a> &bull;
  <a href="#license">License</a>
</p>

---

> *"My stare alone would reduce you to ashes."*
> — Sarah Kerrigan, Queen of Blades

**kerrigan-wallet** is a from-scratch Rust implementation of a KRGN light wallet. No external BIP crates — BIP39 mnemonics, BIP32 HD keys, Base58Check, PBKDF2, and transaction signing are all implemented from first principles. The entire binary is **2.2 MB** with full LTO.

## Features

- **24-word mnemonic** — BIP39 generation, validation, and PBKDF2-HMAC-SHA512 seed derivation (from scratch)
- **HD key derivation** — BIP32 at `m/44'/99888'/0'/0/0` with hardened and normal child keys (from scratch)
- **P2PKH & P2SH** — Full script construction, SIGHASH_ALL signing, ECDSA verification
- **UTXO sync** — Derives UTXOs client-side from the Insight explorer API (no UTXO endpoint needed)
- **Incremental caching** — Block height fast-path + persisted sync state; repeat balance checks are near-instant
- **Device-bound encryption** — Wallet file is AES-CTR encrypted with a key derived from the machine ID
- **Beautiful CLI** — Purple-branded ANSI colors, animated spinner with progress %, paginated history
- **204 tests** — Unit, integration, E2E, and live mainnet verification

## Install

### From source

```bash
git clone https://github.com/kerrigan-network/kerrigan-wallet.git
cd kerrigan-wallet
cargo build --release
```

The binary is at `target/release/kerrigan-wallet` (2.2 MB, fully stripped).

### Requirements

- Rust 1.70+ (2021 edition)
- No runtime dependencies — single static binary

## Usage

```
kerrigan-wallet <command> [args]
```

### Create a wallet

```
$ kerrigan-wallet create

  ⚡ Welcome to the Swarm. ⚡

  Your 24-word recovery phrase:

    1. dune           2. nose           3. fuel           4. second
    5. fever          6. cheap          7. alcohol        8. olive
    9. unusual       10. portion       11. scare         12. cruel
   13. require       14. wrong         15. laundry       16. system
   17. crop          18. develop       19. barely        20. kiwi
   21. renew         22. umbrella      23. remove        24. crater

  ⚠ Write these down. They are the ONLY way to recover your wallet.

  Address: KGbiKzyCBimceeykM7jughMhqDz1KLLjaq
```

### Check balance

```
$ kerrigan-wallet balance
✓ Up to date

  Balance: 0.49996927 KRGN
  Coins:  2 UTXOs
```

Repeat calls within the same block are instant (cached).

### Send KRGN

```
$ kerrigan-wallet send KGbiKzyCBimceeykM7jughMhqDz1KLLjaq 0.001
✓ Synced 2 transactions

  ▸ Transaction
    To:      KGbiKzyCBimceeykM7jughMhqDz1KLLjaq
    Amount:  0.00100000 KRGN
    Fee:     0.00002260 KRGN
    Total:   0.00102260 KRGN

  Confirm send? (yes/no): yes
✓ Transaction sent!
  TXID: 48d4808310773673dde279800290535145b69543340c5e415cd472c33296530c
```

### Transaction history

```
$ kerrigan-wallet history
  ▸ Transaction History (page 1/1)

  TXID              Amount       Confs  Date
──────────────────────────────────────────────────────
  53746d7badab7032  +0.49999187    123  2026-04-01
  48d4808310773673  -0.00002260    115  2026-04-01
──────────────────────────────────────────────────────
  Balance: 0.49996927 KRGN  │ 2 UTXOs
```

Paginated: `history 2` for page 2, `history all` for everything. Full txids on wide terminals.

### All commands

| Command | Description |
|---------|-------------|
| `create` | Generate a new 24-word wallet |
| `import` | Import from existing mnemonic (interactive) |
| `export` | Display mnemonic (requires "I understand") |
| `address` | Print receiving address |
| `balance` | Sync and show balance |
| `send <addr> <amount>` | Send KRGN with fee preview and confirmation |
| `history [page\|all]` | Paginated transaction history |
| `sync` | Force full resync from scratch |

## Architecture

```
kerrigan-wallet/
├── src/
│   ├── params.rs        # Chain constants (prefixes, ports, fees)
│   ├── encoding.rs      # Hex, Base58Check, varint, SHA256d — from scratch
│   ├── bip39.rs         # BIP39 mnemonic + PBKDF2-HMAC-SHA512 — from scratch
│   ├── bip32.rs         # BIP32 HD keys + Hash160 — from scratch
│   ├── keys.rs          # Address generation, WIF, validation
│   ├── script.rs        # P2PKH/P2SH scriptPubKey + scriptSig (extensible enum)
│   ├── fees.rs          # Component-based fee estimation
│   ├── transaction.rs   # Serialization, SIGHASH_ALL, ECDSA signing, UTXO selection
│   ├── network.rs       # Insight explorer API client (connection-pooled)
│   ├── sync.rs          # UTXO derivation from tx history + incremental sync
│   ├── wallet.rs        # Device encryption, persistence, send orchestration
│   ├── term.rs          # ANSI colors, spinner, terminal width detection
│   ├── main.rs          # CLI command dispatch
│   └── lib.rs           # Library root
└── tests/
    └── e2e.rs           # End-to-end integration tests
```

### Written from scratch (no crate)

| Component | What it does |
|-----------|--------------|
| BIP39 | 2048-word wordlist, entropy → mnemonic, PBKDF2-HMAC-SHA512 |
| BIP32 | Master key, hardened/normal derivation, xprv/xpub serialization |
| Base58Check | Encode/decode with SHA256d checksum |
| Hex | Encode/decode with validation |
| Varint | Bitcoin CompactSize read/write |
| PBKDF2 | HMAC-SHA512, 2048 iterations |
| SIGHASH | Legacy Bitcoin SIGHASH_ALL preimage construction |
| Fee estimation | Component-based size model (extensible for future tx types) |
| Device encryption | SHA256-CTR stream cipher keyed by machine ID |
| CLI argument parsing | Zero-dependency command dispatch |

### Dependencies (11 direct)

| Crate | Purpose | Why not from scratch |
|-------|---------|---------------------|
| `secp256k1` | ECDSA signing + verification | Audited, constant-time, not worth reimplementing |
| `sha2` | SHA-256, SHA-512 | Audited, hardware-accelerated |
| `ripemd` | RIPEMD-160 (Hash160) | Audited |
| `hmac` | HMAC construction | Audited |
| `serde` + `serde_json` | JSON serialization | Ubiquitous, well-tested |
| `ureq` | HTTP client + TLS | TLS is not something you write from scratch |
| `zeroize` | Secure memory clearing | Compiler-barrier zeroization |
| `dirs` | Platform data directory | macOS/Linux/Windows support |
| `machine-uid` | Device-unique identifier | Platform-specific system calls |
| `getrandom` | Cryptographic RNG | OS entropy source |
| `libc` | Terminal width (ioctl) | Single syscall |

## Security

### Device-bound encryption

The wallet file stores the mnemonic and seed encrypted with:

```
key = SHA256(machine_uid ‖ data_dir_path ‖ "kerrigan-wallet-device-encryption")
```

The file is useless on any other machine. Keystream blocks are zeroized after use.

### Atomic writes

Wallet saves use write-to-temp + rename (atomic on Unix) with `0o600` permissions.

### What this wallet does NOT protect against

- A compromised machine (root access can read process memory)
- Clipboard sniffing (addresses are displayed in plaintext)
- Screen capture (mnemonic is shown on `create` and `export`)

This is a light wallet for everyday use, not a vault. For large holdings, use cold storage.

## Building

```bash
# Debug build (fast compile, slow runtime)
cargo build

# Release build (slow compile, fast runtime, 2.2 MB stripped binary)
cargo build --release

# Run tests
cargo test

# Run with live explorer tests
cargo test -- --ignored
```

### Release profile

```toml
[profile.release]
lto = true
codegen-units = 1
opt-level = 3
strip = true
```

## Testing

**204 tests** across unit, integration, and E2E suites:

| Suite | Tests | What it covers |
|-------|-------|----------------|
| `params` | 3 | Chain constants |
| `encoding` | 19 | Hex, Base58, varint, SHA256d |
| `bip39` | 15 | Mnemonic gen, PBKDF2 vectors, BIP39 spec vectors |
| `bip32` | 17 | HD keys, BIP32 spec vectors 1-2, xprv roundtrip |
| `keys` | 13 | Address gen, WIF, validation |
| `script` | 18 | P2PKH/P2SH scripts, opcodes, address conversion |
| `fees` | 14 | Size estimation, fee scaling, dust threshold |
| `transaction` | 27 | Serialization, sighash, signing, UTXO selection |
| `network` | 15+2 | JSON parsing, API types (2 live tests) |
| `sync` | 17 | UTXO derivation, chain simulation, dedup |
| `wallet` | 26 | Encryption, persistence, amount formatting |
| `e2e` | 14+4 | Full lifecycle, fee accuracy, live sync (4 live) |

Live tests hit the real Kerrigan explorer and are gated behind `#[ignore]`:

```bash
cargo test -- --ignored    # Run live tests
```

## Chain Parameters

| Parameter | Value |
|-----------|-------|
| Ticker | KRGN |
| P2PKH prefix | 45 → `K...` addresses |
| P2SH prefix | 16 → `7...` addresses |
| WIF prefix | 204 |
| BIP44 coin type | 99888 |
| Derivation path | `m/44'/99888'/0'/0/0` |
| Block time | 120 seconds |
| Fee rate | 10 sat/byte |
| Tx version | v1 (legacy Bitcoin format) |
| Explorer | https://explorer.kerrigan.network |

## License

MIT

---

<p align="center">
  <em>For the Swarm.</em>
</p>
