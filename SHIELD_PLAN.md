# Kerrigan Shield — Implementation Plan

## Context

Add Sapling shielded transaction support to the Kerrigan SDK + CLI, and build a Rust RPC sync server to replace PivxNodeController.

### Key Discovery: Vanilla Zcash Crates

Kerrigan's own node uses **vanilla zcash crates** (not librustpivx):
- `zcash_primitives = "0.26"`, `sapling-crypto = "0.5"`, `zcash_proofs = "0.26"`

PIVX's agent-kit uses **Duddino's fork** (librustpivx) which renames packages:
- `pivx_primitives` = renamed `zcash_primitives`, etc.

**Decision: Use vanilla zcash crates.** This matches Kerrigan's node, avoids the fork-of-a-fork problem, and gives us direct upstream compatibility. We'll implement a `KerriganNetwork` type with the `NetworkConstants` trait.

### Kerrigan-Specific Parameters

```
Sapling address HRP:         "ks"
Sapling activation height:   500
BIP44 coin type:             99888
P2PKH prefix:                45 (K...)
P2SH prefix:                 16 (7...)

Fee formula:
  base_fee       = 10,000 sat (0.0001 KRGN)
  per_spend_fee  = 5,000 sat
  per_output_fee = 5,000 sat
  total = 10000 + (nSpends × 5000) + (nOutputs × 5000)

Tx version:      3 (nType = 10 = TRANSACTION_SAPLING)
Merkle depth:    32
Max spends/tx:   500
Max outputs/tx:  500

Sapling param files: Zcash originals (same SHA256 hashes)
  output: 2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4
  spend:  8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13

Keys: hex-encoded (NOT bech32), except payment addresses which use HRP "ks"
```

---

## Phase 1: SDK Sapling Network + Keys

**Goal:** Define Kerrigan's Sapling network, derive shielded keys from seed.

### Files

`sdk/src/sapling/mod.rs` — module root, re-exports
`sdk/src/sapling/network.rs` — `KerriganNetwork` + `NetworkConstants` impl
`sdk/src/sapling/keys.rs` — ZIP32 key derivation + encoding

### network.rs

```rust
use zcash_protocol::consensus::{BlockHeight, NetworkConstants, NetworkType, Parameters};

pub struct KerriganMainNetwork;

impl Parameters for KerriganMainNetwork {
    fn network_type(&self) -> NetworkType { NetworkType::Main }
    fn activation_height(nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Sapling => Some(BlockHeight::from_u32(500)),
            _ => None,
        }
    }
}

impl NetworkConstants for KerriganMainNetwork {
    fn hrp_sapling_payment_address(&self) -> &str { "ks" }
    // Extended keys are hex-encoded on Kerrigan, not bech32
    fn hrp_sapling_extended_spending_key(&self) -> &str { "ks-secret" }
    fn hrp_sapling_extended_full_viewing_key(&self) -> &str { "ks-viewing" }
    fn b58_pubkey_address_prefix(&self) -> [u8; 2] { [0, 45] }
    fn b58_script_address_prefix(&self) -> [u8; 2] { [0, 16] }
}

pub const SAPLING_ACTIVATION_HEIGHT: u32 = 500;
pub const SAPLING_TREE_DEPTH: u8 = 32;
```

### keys.rs

Adapted from pivx-agent-kit `keys.rs` lines 18-86:

```rust
pub fn spending_key_from_seed(seed: &[u8], coin_type: u32, account: u32)
    -> Result<ExtendedSpendingKey, Error>

pub fn full_viewing_key(extsk: &ExtendedSpendingKey) -> ExtendedFullViewingKey

pub fn default_payment_address(extfvk: &ExtendedFullViewingKey) -> PaymentAddress

pub fn encode_payment_address(addr: &PaymentAddress) -> String  // ks1...

pub fn nullifier_deriving_key(extfvk: &ExtendedFullViewingKey) -> NullifierDerivingKey
```

### Tests (~15)
- Derive keys from known seed, verify address starts with `ks`
- Roundtrip ESK → EFVK → address → encode → decode
- Coin type 99888 produces different keys than 119 (PIVX)
- NullifierDerivingKey derivation

### Dependencies to add to sdk/Cargo.toml
```toml
# Sapling
sapling-crypto = { version = "0.5", features = ["temporary-zcashd"] }
zcash_primitives = { version = "0.26", features = ["temporary-zcashd"] }
zcash_proofs = "0.26"
zcash_protocol = "0.7"
zcash_note_encryption = "0.4"
zcash_keys = { version = "0.7", features = ["unstable"] }
incrementalmerkletree = "0.7"
bellman = { version = "0.14", features = ["groth16"] }
rand_core = { version = "0.6", features = ["std"] }
```

Note: may need `[patch.crates-io]` for `orchard` and `redjubjub` (same as pivx-agent-kit).

---

## Phase 2: SDK Sapling Notes + Tree

**Goal:** Commitment tree management, note decryption, nullifier derivation.

### Files

`sdk/src/sapling/tree.rs` — commitment tree serialization, append, root
`sdk/src/sapling/notes.rs` — note types, decryption, SpendableNote

### tree.rs

Adapted from pivx-agent-kit `shield.rs` tree operations:

```rust
pub fn read_tree(hex: &str) -> Result<CommitmentTree<Node, 32>, Error>
pub fn write_tree(tree: &CommitmentTree<Node, 32>) -> String  // hex
pub fn tree_root(tree: &CommitmentTree<Node, 32>) -> [u8; 32]
pub fn append_cmu(tree: &mut CommitmentTree<Node, 32>, cmu: &[u8; 32])
```

### notes.rs

Adapted from pivx-agent-kit `shield.rs` SpendableNote + handle_transaction:

```rust
pub struct SerializedNote {
    pub note: serde_json::Value,
    pub witness: String,        // hex-encoded IncrementalWitness
    pub nullifier: String,      // hex
    pub memo: Option<String>,
    pub height: u32,
}

pub struct SpendableNote {
    pub note: Note,
    pub witness: IncrementalWitness<Node, 32>,
    pub nullifier: String,
    pub memo: Option<String>,
    pub height: u32,
}

pub fn process_sapling_transaction(
    tree: &mut CommitmentTree<Node, 32>,
    tx_bytes: &[u8],
    viewing_key: &ExtendedFullViewingKey,
    nullif_key: &NullifierDerivingKey,
    existing_witnesses: &mut Vec<SpendableNote>,
    new_witnesses: &mut Vec<SpendableNote>,
    block_height: u32,
) -> Result<Vec<Nullifier>, Error>

pub fn get_nullifier(
    nk: &NullifierDerivingKey,
    note: &Note,
    witness: &IncrementalWitness<Node, 32>,
) -> Result<String, Error>
```

### Tests (~15)
- Empty tree root matches known value
- Append CMU, verify root changes
- Tree serialization roundtrip (hex)
- Note decryption with known test vector
- Nullifier derivation deterministic
- Witness append + path extraction

---

## Phase 3: SDK Sapling Transaction Builder

**Goal:** Construct, sign, and serialize Sapling transactions.

### Files

`sdk/src/sapling/builder.rs` — transaction construction
`sdk/src/sapling/fees.rs` — Sapling fee calculation (Kerrigan's formula)
`sdk/src/sapling/prover.rs` — prover parameter types

### fees.rs (Sapling-specific)

```rust
pub const SAPLING_BASE_FEE: u64 = 10_000;
pub const SAPLING_PER_SPEND_FEE: u64 = 5_000;
pub const SAPLING_PER_OUTPUT_FEE: u64 = 5_000;

pub fn sapling_fee(num_spends: usize, num_outputs: usize) -> u64 {
    SAPLING_BASE_FEE
        + (num_spends as u64 * SAPLING_PER_SPEND_FEE)
        + (num_outputs as u64 * SAPLING_PER_OUTPUT_FEE)
}
```

### prover.rs

```rust
pub type SaplingProver = (OutputParameters, SpendParameters);

pub const OUTPUT_PARAMS_SHA256: &str = "2f0ebbcb...";
pub const SPEND_PARAMS_SHA256: &str = "8e48ffd2...";

// The SDK defines the type and hashes.
// The CLI loads the actual files from disk.
// WASM loads from fetch().
pub fn verify_params(output_bytes: &[u8], spend_bytes: &[u8]) -> Result<SaplingProver, Error>
```

### builder.rs

Adapted from pivx-agent-kit `shield.rs:create_shield_transaction()`:

```rust
pub enum SaplingDestination {
    Shielded(PaymentAddress),
    Transparent(String),  // K... or 7... address
}

pub struct SaplingTxResult {
    pub tx_hex: String,
    pub nullifiers: Vec<String>,
    pub amount: u64,
    pub fee: u64,
}

pub fn build_sapling_transaction(
    notes: &[SpendableNote],
    extsk: &ExtendedSpendingKey,
    to: SaplingDestination,
    amount: u64,
    memo: &str,
    block_height: u32,
    prover: &SaplingProver,
) -> Result<SaplingTxResult, Error>

// Also: shielding (transparent → sapling) and unshielding (sapling → transparent)
pub fn build_shield_transaction(
    utxos: &[Utxo],
    privkey: &[u8; 32],
    pubkey: &[u8; 33],
    to_shielded: &PaymentAddress,
    amount: u64,
    block_height: u32,
    prover: &SaplingProver,
) -> Result<SaplingTxResult, Error>
```

### Tests (~15)
- Fee calculation matches Kerrigan formula
- Sapling param SHA256 verification
- Transaction builder produces valid hex
- Shielding tx structure (transparent in, sapling out)
- Unshielding tx structure (sapling in, transparent out)
- Shield-to-shield tx structure
- Note selection (largest first, memo-less first)

---

## Phase 4: Node Bridge (kerrigan-node-bridge)

**Goal:** Rust binary that connects to a Kerrigan full node RPC and serves the binary shield stream to light wallets.

### New workspace crate: `bridge/`

```
bridge/
├── Cargo.toml
└── src/
    ├── main.rs          # HTTP server entry point
    ├── config.rs        # CLI args, RPC credentials, port
    ├── rpc.rs           # JSON-RPC 1.0 client to Kerrigan node
    ├── scanner.rs       # Block scanner: find blocks with Sapling txs
    ├── stream.rs        # Binary stream encoder (0x5d blocks, 0x03 txs)
    ├── index.rs         # Shield block index (in-memory + persistence)
    └── api.rs           # HTTP endpoints
```

### Binary Wire Format (PIVX-compatible)

```
Packet: [4-byte LE length] [payload]
Block marker:  payload[0] = 0x5d, payload[1..5] = height (LE u32)
Transaction:   payload[0] = 0x03, payload[1..] = raw serialized tx
```

### Endpoints

```
GET  /getshielddata?startBlock=N   → binary stream
GET  /getblockcount                → block height (text)
GET  /getblockhash?params=N        → block hash (JSON string)
GET  /getblock?params=hash,1       → block JSON
POST /sendrawtransaction           → broadcast tx hex
GET  /getshieldblocks              → JSON array of shield block heights
```

### Dependencies

```toml
axum = "0.8"          # HTTP server
tokio = { version = "1", features = ["full"] }
serde_json = "1"
ureq = "2"            # RPC client (blocking, runs in spawn_blocking)
clap = "4"            # CLI args
```

### How It Works

1. On startup, scan from genesis (or last known height) for shield blocks
2. Cache shield block index in memory + JSON file
3. On `/getshielddata?startBlock=N`:
   - For each shield block >= N:
   - Fetch full block via `getblock(hash, 2)` RPC
   - Filter for Sapling txs (nType == 10 or tx hex starts with "03")
   - Emit block marker (0x5d) + raw tx packets (0x03)
4. Stream response with chunked transfer encoding

### Tests (~10)
- Binary packet encoding/decoding roundtrip
- Shield block detection from raw tx hex
- Stream encoding produces valid output that SDK can parse
- RPC client error handling

---

## Phase 5: SDK Sapling Sync (Binary Stream Parser)

**Goal:** Parse the binary shield stream in the SDK (pure logic, no I/O).

### File

`sdk/src/sapling/sync.rs`

### API

```rust
pub struct RawShieldBlock {
    pub height: u32,
    pub txs: Vec<Vec<u8>>,  // raw serialized transactions
}

pub struct ShieldSyncResult {
    pub commitment_tree: String,       // hex
    pub new_notes: Vec<SerializedNote>,
    pub updated_notes: Vec<SerializedNote>,
    pub nullifiers: Vec<String>,       // spent nullifiers found
}

/// Parse binary stream packets into RawShieldBlocks.
/// Pure parsing, no I/O — caller provides the bytes.
pub fn parse_shield_packets(data: &[u8]) -> Result<Vec<RawShieldBlock>, Error>

/// Process decoded shield blocks against the wallet's viewing key.
/// Updates commitment tree, discovers new notes, advances witnesses.
pub fn process_shield_blocks(
    tree_hex: &str,
    blocks: &[RawShieldBlock],
    extfvk: &ExtendedFullViewingKey,
    existing_notes: &[SerializedNote],
) -> Result<ShieldSyncResult, Error>
```

### Tests (~10)
- Parse empty stream → empty vec
- Parse single block with one tx
- Parse multi-block stream
- Invalid packet type → error
- Truncated packet → error
- Process blocks with no relevant notes → tree updated, no new notes
- Integration: encode (bridge) → parse (SDK) roundtrip

---

## Phase 6: SDK Sapling Checkpoints

**Goal:** Pre-computed commitment tree snapshots for fast sync.

### File

`sdk/src/sapling/checkpoints.rs`

### How to Generate

Need a running Kerrigan node. For each checkpoint height:
1. `getblock(getblockhash(height), 1)` → extract `finalsaplingroot`
2. Reconstruct tree up to that point (or extract from node's DB)

### Fallback for Young Chain

Kerrigan is only ~13,500 blocks old with Sapling active since block 500. That's ~13,000 blocks — scanning from an empty tree at block 500 is feasible (~1-2 minutes). We can start with just one checkpoint at block 500 (empty tree).

```rust
pub const CHECKPOINTS: &[(u32, &str)] = &[
    (500, "000000"),  // Sapling activation — empty tree
    // Add more as the chain grows
];

pub fn get_checkpoint(block_height: u32) -> (u32, &'static str)
```

---

## Phase 7: CLI Shield Integration

**Goal:** Add shield commands to the wallet CLI.

### New CLI Files

`cli/src/sapling_sync.rs` — binary stream consumer (connects to bridge)
`cli/src/sapling_params.rs` — download + cache sapling param files (~50MB)

### New CLI Commands

```
kerrigan-wallet z_address           Show shielded address (ks1...)
kerrigan-wallet z_balance           Sync shield + show balance
kerrigan-wallet z_send <addr> <amt> [memo]   Shield send
kerrigan-wallet shield <amt>        Transparent → shielded
kerrigan-wallet unshield <amt>      Shielded → transparent
kerrigan-wallet z_history [page]    Shielded transaction history
```

### Wallet State Extensions

Add to `WalletData`:
```rust
pub extfvk: Option<String>,              // encoded extended full viewing key
pub sapling_birthday: u32,               // block height when wallet was created
pub sapling_last_block: u32,             // last synced shield block
pub commitment_tree: Option<String>,      // hex-encoded Merkle tree
pub unspent_notes: Vec<SerializedNote>,   // shielded UTXOs
pub sapling_history: Vec<TxHistoryEntry>, // shield tx history
```

### Sapling Param Management

```rust
// CLI downloads on first use, caches in data dir
pub fn ensure_sapling_params() -> Result<SaplingProver, Error>
// ~50MB download, verified by SHA256
```

---

## Phase 8: Live Testing

1. **Generate shielded address** → verify `ks1...` format
2. **Receive shielded tx** → verify note detection after sync
3. **Shield send** → build + broadcast + verify on explorer
4. **Unshield** → sapling → transparent → verify balance
5. **Cross-check** → balance matches `z_getbalance` RPC on a full node

---

## Execution Order

```
Phase 1: SDK network + keys           (independent, start here)
Phase 2: SDK notes + tree             (needs Phase 1)
Phase 3: SDK builder + fees + prover  (needs Phase 1-2)
Phase 4: Node bridge                  (independent, can parallel with 1-3)
Phase 5: SDK binary stream parser     (needs Phase 4 format, but pure logic)
Phase 6: SDK checkpoints              (needs running node or team help)
Phase 7: CLI integration              (needs Phase 1-5)
Phase 8: Live testing                 (needs everything + bridge deployed)
```

Phases 1-3 and Phase 4 can run in parallel.

---

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| zcash crate version mismatch | Won't compile | Pin exact versions matching Kerrigan node's Cargo.toml |
| `NetworkConstants` trait missing methods | Won't compile | Check zcash_protocol 0.7 API; may need to impl custom trait |
| No `/getshielddata` on Kerrigan | Can't sync shield | Build the bridge (Phase 4) |
| Sapling param download fails | Can't build txs | Multiple download mirrors + cache |
| Checkpoints unavailable | Slow initial sync | Start from block 500 empty tree; young chain, manageable |
| `[patch.crates-io]` conflicts | Cargo resolver hell | Test with exact same patches as Kerrigan node |

---

## Estimated Test Count

| Phase | Tests |
|-------|-------|
| 1: Network + Keys | ~15 |
| 2: Notes + Tree | ~15 |
| 3: Builder + Fees | ~15 |
| 4: Node Bridge | ~10 |
| 5: Binary Parser | ~10 |
| 6: Checkpoints | ~3 |
| 7: CLI Integration | ~10 |
| **Total new** | **~78** |
| **Existing** | **173** |
| **Grand total** | **~251** |
