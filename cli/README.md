# kerrigan-wallet

A minimal light wallet CLI for the Kerrigan Network. Supports both transparent and Sapling shielded transactions.

## Features

- 24-word BIP39 mnemonic (generated from scratch)
- BIP32 HD key derivation at `m/44'/99888'/0'/0/0`
- ZIP32 Sapling key derivation with `ks1...` shielded addresses
- P2PKH transparent sends and receives
- Sapling shielded sends: shield, unshield, and private transfers
- UTXO + commitment tree sync (parallel transparent + shield)
- Device-bound AES encryption
- Beautiful terminal UI with ANSI colors and spinners

## Install

```bash
cargo build --release -p kerrigan-wallet-cli
cp target/release/kerrigan-wallet ~/.local/bin/
```

## Usage

```bash
kerrigan-wallet create              # Generate a new wallet
kerrigan-wallet import              # Import wallet from mnemonic
kerrigan-wallet export              # Display wallet mnemonic
kerrigan-wallet address             # Show public + private addresses
kerrigan-wallet balance             # Sync and show balances
kerrigan-wallet send <args>         # Send KRGN (see below)
kerrigan-wallet history [page|all]  # Transaction history
kerrigan-wallet sync                # Force full resync
```

## Sending KRGN

The `send` command takes `public` or `private` as the first argument to select which balance to spend from. The destination address type determines the flow:

```bash
# Transparent send (public -> public)
kerrigan-wallet send public KAddress... 1.5

# Shield (public -> private)
kerrigan-wallet send public ks1Address... 1.5

# Private send (private -> private, with optional memo)
kerrigan-wallet send private ks1Address... 1.5 "For the Swarm"

# Unshield (private -> public)
kerrigan-wallet send private KAddress... 1.5

# Send everything (works with all combinations)
kerrigan-wallet send public ks1Address... max
kerrigan-wallet send private KAddress... max
```

| Source | Destination | Flow |
|--------|-------------|------|
| `public` | `K...` | Transparent send |
| `public` | `ks1...` | Shielding |
| `private` | `ks1...` | Shield-to-shield |
| `private` | `K...` | Unshielding |

## Architecture

```
kerrigan-wallet (CLI)
├── main.rs           Entry point, command routing, send flows
├── storage.rs        Device-bound encryption, wallet persistence
├── network.rs        Explorer HTTP client (transparent sync)
├── sync_service.rs   Transparent sync orchestration
├── sapling_sync.rs   Shield sync (bridge HTTP client)
├── sapling_params.rs Sapling parameter download + cache (~50MB)
└── term.rs           ANSI colors, spinners, terminal width
```

## Security

- **Device-bound encryption**: wallet file encrypted with SHA256(machine_uid + data_dir + salt)
- **Atomic writes**: wallet saved via tmp file + rename (no corruption on crash)
- **File permissions**: 0o600 on Unix
- **Sapling params**: SHA-256 verified on download, cached locally

## License

MIT
