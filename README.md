<p align="center">
  <strong>Kerrigan SDK</strong><br>
  <em>Rust workspace for the Kerrigan Network — wallet SDK, CLI, and shield sync bridge.</em>
</p>

---

> *"I am the Swarm."*

## Workspace

This repository is a Cargo workspace containing three crates:

### [`sdk/`](sdk/) — kerrigan-sdk

Pure-Rust wallet primitives for the Kerrigan Network. BIP39, BIP32, transaction signing, UTXO sync, Sapling shielded transactions, and encryption — all from scratch, with zero I/O dependencies.

**Use this when:** you're building a wallet, app, bot, or integration that needs to create addresses, sign transactions, manage KRGN state, or handle shielded (private) transactions.

**Compiles to:** native, WASM, mobile (via FFI/uniffi).

[Read the SDK docs &rarr;](sdk/README.md)

### [`cli/`](cli/) — kerrigan-wallet

A minimal light wallet CLI built on the SDK. Syncs via the Kerrigan block explorer and shield bridge, stores wallet state with device-bound encryption, and provides a beautiful terminal interface.

**Use this when:** you want to send and receive KRGN (public and private) from the command line.

[Read the CLI docs &rarr;](cli/README.md)

### [`bridge/`](bridge/) — kerrigan-bridge

A shield sync server that connects to a Kerrigan full node via JSON-RPC, scans for Sapling transactions, and serves compact shield data to light wallets over HTTP. Uses ZMQ for real-time block notifications.

**Use this when:** you're running infrastructure for Kerrigan light wallets that need shielded transaction sync.

[Read the Bridge docs &rarr;](bridge/README.md)

## Architecture

```
                          kerrigan-sdk
                 (pure logic, no I/O, compiles everywhere)

  Transparent:  bip39 . bip32 . keys . encoding . params
                script . fees . transaction . sync . wallet

  Sapling:      network . keys . tree . notes . fees
                prover . builder . kerrigan_tx . sync

       |                    |                    |
 +-----+------+      +-----+----+      +--------+-------+
 |   CLI      |      |   WASM   |      |   Mobile       |
 |  ureq HTTP |      | fetch()  |      | platform HTTP   |
 | filesystem |      | IDB      |      | secure storage  |
 +-----+------+      +----------+      +----------------+
       |
       |  compact binary stream
       |
 +-----+--------+
 | Bridge        |
 | axum HTTP     |
 | ZMQ subscribe |
 | node JSON-RPC |
 +---------------+
       |
 +-----+--------+
 | Kerrigan Node |
 | (full node)   |
 +--------------+
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

# Run the bridge (requires a Kerrigan full node)
target/release/kerrigan-bridge --rpc-url http://127.0.0.1:7121 --rpc-user rpc --rpc-pass rpc
```

## Chain parameters

| Parameter | Value |
|-----------|-------|
| Ticker | KRGN |
| P2PKH prefix | 45 &rarr; `K...` addresses |
| P2SH prefix | 16 &rarr; `7...` addresses |
| Sapling HRP | `ks` &rarr; `ks1...` shielded addresses |
| BIP44 coin type | 99888 |
| Derivation path | `m/44'/99888'/0'/0/0` |
| Sapling activation | Block 500 |
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
