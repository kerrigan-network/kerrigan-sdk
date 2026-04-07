# kerrigan-bridge

Shield sync server for the Kerrigan Network. Connects to a Kerrigan full node, scans for Sapling transactions, and serves compact shield data to light wallets over HTTP.

## Features

- Scans blocks for Sapling transactions via JSON-RPC
- Parses Kerrigan type 10 raw transactions to extract compact data
- Serves a compact binary stream (42-62% smaller than full raw tx streaming)
- Real-time block indexing via ZMQ `hashblock` notifications
- Persists shield block index to disk (survives restarts)
- Works around Kerrigan node's `TxToUniv` MoneyRange bug (uses verbosity 1 + getrawtransaction)

## Setup

### 1. Configure the Kerrigan node

Add to `kerrigan.conf`:

```
server=1
rpcuser=rpc
rpcpassword=rpc
zmqpubhashblock=tcp://127.0.0.1:28332
```

### 2. Build and run

```bash
cargo build --release -p kerrigan-bridge

./target/release/kerrigan-bridge \
  --rpc-url http://127.0.0.1:7121 \
  --rpc-user rpc \
  --rpc-pass rpc \
  --zmq-url tcp://127.0.0.1:28332 \
  --port 3001
```

The bridge will scan from Sapling activation (block 500) on first run, then index new blocks in real-time via ZMQ.

## Endpoints

| Route | Method | Description |
|-------|--------|-------------|
| `/getshielddata?startBlock=N` | GET | Compact binary shield stream |
| `/getblockcount` | GET | Current chain height |
| `/getshieldblocks` | GET | JSON array of shield block heights |
| `/sendrawtransaction` | POST | Broadcast raw transaction hex |

## Compact binary protocol

The `/getshielddata` endpoint returns a binary stream of length-prefixed packets:

```
Packet:       [4-byte LE length][payload]
Block marker:  type=0x5d | height(4 LE)
Full tx:       type=0x03 | raw_serialized_tx
Compact tx:    type=0x04 | num_spends(1) | num_outputs(1)
                 per spend: nullifier(32)
                 per output: cmu(32) + epk(32) + enc_ciphertext(580)
```

Light wallets parse this with the SDK's `parse_shield_stream()` function.

### Why compact?

Light wallets don't verify Groth16 proofs — the blockchain already did. The compact format strips proofs (192 bytes each), signatures (64 bytes each), value commitments, and other fields a light wallet never reads:

| Component | Full size | Compact size | Savings |
|-----------|-----------|-------------|---------|
| Per spend | 384 bytes | 32 bytes | 92% |
| Per output | 948 bytes | 644 bytes | 32% |
| 1-spend + 2-output tx | 2,280 bytes | 1,320 bytes | 42% |

## Architecture

```
bridge/
├── main.rs        Startup, initial scan, ZMQ subscriber, axum server
├── config.rs      CLI args (--rpc-url, --rpc-user, --rpc-pass, --zmq-url, --port)
├── rpc.rs         JSON-RPC 1.0 client with auth + connection pooling
├── scanner.rs     Block scanner + Kerrigan type 10 raw tx parser
├── stream.rs      Binary stream encoder using SDK compact format
├── index.rs       Shield block height index with JSON persistence
└── api.rs         HTTP endpoints (axum handlers)
```

## Kerrigan type 10 transaction parser

The bridge includes a custom parser for Kerrigan's Dash-style type 10 Sapling transactions:

```
Header: (type << 16) | version = 0x000a0003
Body:   vin + vout + nLockTime
Payload: nVersion(u16) + spends(384 each) + outputs(948 each) + valueBalance(i64) + bindingSig(64)
```

The parser skips transparent inputs/outputs to reach the Sapling extra payload, then extracts only the compact fields (nullifiers, cmu, epk, enc_ciphertext).

## License

MIT
