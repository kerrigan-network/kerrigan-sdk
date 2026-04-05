<p align="center">
  <strong>Kerrigan SDK</strong><br>
  <em>Rust workspace for the Kerrigan Network — wallet SDK and CLI tooling.</em>
</p>

---

> *"I am the Swarm."*

## Workspace

This repository is a Cargo workspace containing two crates:

### [`sdk/`](sdk/) — kerrigan-sdk

Pure-Rust wallet primitives for the Kerrigan Network. BIP39, BIP32, transaction signing, UTXO sync, and encryption — all from scratch, with zero I/O dependencies.

**Use this when:** you're building a wallet, app, bot, or integration that needs to create addresses, sign transactions, or manage KRGN state.

**Compiles to:** native, WASM, mobile.

[Read the SDK docs →](sdk/README.md)

### [`cli/`](cli/) — kerrigan-wallet

A minimal light wallet CLI built on the SDK. Syncs via the Kerrigan block explorer, stores wallet state with device-bound encryption, and provides a beautiful terminal interface.

**Use this when:** you want to send and receive KRGN from the command line.

[Read the CLI docs →](cli/README.md)

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  kerrigan-sdk                    │
│                                                  │
│  bip39 · bip32 · keys · encoding · params       │
│  script · fees · transaction · sync · wallet     │
│                                                  │
│  Pure logic. No I/O. Compiles everywhere.        │
└──────────────────────┬──────────────────────────┘
                       │
          ┌────────────┼────────────┐
          │            │            │
   ┌──────▼─────┐ ┌───▼────┐ ┌────▼─────┐
   │  CLI       │ │  WASM  │ │  WebXDC  │
   │  ureq HTTP │ │ fetch()│ │ realtime │
   │  filesystem│ │ IDB   │ │ channels │
   └────────────┘ └────────┘ └──────────┘
```

## Quick start

```bash
# Build everything
cargo build --release

# Run the CLI
target/release/kerrigan-wallet help

# Run all tests (SDK + CLI)
cargo test

# Build only the SDK (e.g., for WASM integration)
cargo build -p kerrigan-sdk
```

## Chain parameters

| Parameter | Value |
|-----------|-------|
| Ticker | KRGN |
| P2PKH prefix | 45 → `K...` addresses |
| P2SH prefix | 16 → `7...` addresses |
| BIP44 coin type | 99888 |
| Derivation path | `m/44'/99888'/0'/0/0` |
| Block time | 120 seconds |
| Explorer | https://explorer.kerrigan.network |

## Links

- [Kerrigan Network](https://kerrigan.network)
- [Block Explorer](https://explorer.kerrigan.network)
- [Discord](https://discord.gg/V9P3UDjkFu)

## License

MIT

---

<p align="center">
  <em>For the Swarm.</em>
</p>
