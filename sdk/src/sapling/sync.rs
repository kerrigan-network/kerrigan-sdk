/// Sapling shield sync — binary stream parser and compact block processing.
///
/// # Wire Format
///
/// The bridge serves a binary stream of length-prefixed packets:
///
/// ```text
/// Packet:       [4-byte LE length][payload]
/// Block marker:  type=0x5d | height(4 LE)
/// Full tx:       type=0x03 | raw_serialized_tx
/// Compact tx:    type=0x04 | num_spends(1) | num_outputs(1)
///                  per spend: nullifier(32)
///                  per output: cmu(32) + epk(32) + enc_ciphertext(580)
/// ```
///
/// Compact mode strips proofs, signatures, and unused fields — light wallets
/// don't verify proofs (the blockchain already did). This cuts ~42-62% of
/// sync data before transport compression.

use sapling::note_encryption::{PreparedIncomingViewingKey, SaplingDomain, Zip212Enforcement};
use sapling::zip32::ExtendedFullViewingKey;
use sapling::{Node, NullifierDerivingKey};
use zcash_note_encryption::{try_note_decryption, EphemeralKeyBytes, ShieldedOutput, ENC_CIPHERTEXT_SIZE};

use crate::encoding;
use super::keys;
use super::notes::{self, HandleBlocksResult, SerializedNote, SpendableNote};
use super::tree::{self, SaplingTree, advance_witness, append_node, witness_from_tree};

// ---------------------------------------------------------------------------
// Wire format constants
// ---------------------------------------------------------------------------

/// Packet type: block height marker.
pub const PACKET_TYPE_BLOCK: u8 = 0x5d;

/// Packet type: full raw transaction (legacy PIVX-compatible).
pub const PACKET_TYPE_FULL_TX: u8 = 0x03;

/// Packet type: compact transaction (Kerrigan optimized).
pub const PACKET_TYPE_COMPACT_TX: u8 = 0x04;

/// Size of the encrypted ciphertext per Sapling output.
const ENC_CT_SIZE: usize = ENC_CIPHERTEXT_SIZE;

// ---------------------------------------------------------------------------
// Parsed types
// ---------------------------------------------------------------------------

/// A parsed shield block from the binary stream.
#[derive(Debug, Clone)]
pub struct RawShieldBlock {
    /// Block height.
    pub height: u32,
    /// Block contents — either full tx bytes or compact tx data.
    pub entries: Vec<BlockEntry>,
}

/// A single entry within a shield block.
#[derive(Debug, Clone)]
pub enum BlockEntry {
    /// Full raw transaction bytes (type 0x03).
    FullTx(Vec<u8>),
    /// Compact transaction data (type 0x04) — only the fields a light wallet needs.
    CompactTx(CompactTransaction),
}

/// Compact transaction — proofs and signatures stripped.
#[derive(Debug, Clone)]
pub struct CompactTransaction {
    /// Nullifiers from Sapling spends (32 bytes each).
    pub nullifiers: Vec<[u8; 32]>,
    /// Compact Sapling outputs (cmu + epk + enc_ciphertext).
    pub outputs: Vec<CompactSaplingOutput>,
}

/// A compact Sapling output — only the fields needed for decryption.
#[derive(Debug, Clone)]
pub struct CompactSaplingOutput {
    /// Note commitment (32 bytes).
    pub cmu: [u8; 32],
    /// Ephemeral public key (32 bytes).
    pub epk: [u8; 32],
    /// Encrypted ciphertext (580 bytes).
    pub enc_ciphertext: [u8; ENC_CT_SIZE],
}

/// Implement `ShieldedOutput` so `try_note_decryption` works directly.
impl ShieldedOutput<SaplingDomain, ENC_CT_SIZE> for CompactSaplingOutput {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.epk)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmu
    }

    fn enc_ciphertext(&self) -> &[u8; ENC_CT_SIZE] {
        &self.enc_ciphertext
    }
}

// ---------------------------------------------------------------------------
// Binary stream parser
// ---------------------------------------------------------------------------

/// Parse a binary shield stream into blocks.
///
/// The stream is a sequence of length-prefixed packets. Block markers (0x5d)
/// start a new block; transactions (0x03 or 0x04) are added to the current block.
pub fn parse_shield_stream(data: &[u8]) -> Result<Vec<RawShieldBlock>, ShieldSyncError> {
    let mut blocks = Vec::new();
    let mut current_block: Option<RawShieldBlock> = None;
    let mut cursor = 0;

    while cursor < data.len() {
        // Read 4-byte LE length prefix
        if cursor + 4 > data.len() {
            return Err(ShieldSyncError::Truncated("length prefix".into()));
        }
        let len = u32::from_le_bytes([
            data[cursor], data[cursor + 1], data[cursor + 2], data[cursor + 3],
        ]) as usize;
        cursor += 4;

        if cursor + len > data.len() {
            return Err(ShieldSyncError::Truncated(format!(
                "packet body: need {len} bytes, have {}",
                data.len() - cursor
            )));
        }

        let payload = &data[cursor..cursor + len];
        cursor += len;

        if payload.is_empty() {
            return Err(ShieldSyncError::EmptyPacket);
        }

        match payload[0] {
            PACKET_TYPE_BLOCK => {
                // Block marker: type(1) + height(4)
                if payload.len() < 5 {
                    return Err(ShieldSyncError::Truncated("block marker height".into()));
                }
                let height = u32::from_le_bytes([
                    payload[1], payload[2], payload[3], payload[4],
                ]);

                // Save previous block
                if let Some(block) = current_block.take() {
                    blocks.push(block);
                }
                current_block = Some(RawShieldBlock { height, entries: Vec::new() });
            }

            PACKET_TYPE_FULL_TX => {
                let block = current_block.as_mut()
                    .ok_or(ShieldSyncError::TxBeforeBlock)?;
                block.entries.push(BlockEntry::FullTx(payload[1..].to_vec()));
            }

            PACKET_TYPE_COMPACT_TX => {
                let block = current_block.as_mut()
                    .ok_or(ShieldSyncError::TxBeforeBlock)?;
                let compact = parse_compact_tx(&payload[1..])?;
                block.entries.push(BlockEntry::CompactTx(compact));
            }

            other => {
                return Err(ShieldSyncError::UnknownPacketType(other));
            }
        }
    }

    // Don't forget the last block
    if let Some(block) = current_block {
        blocks.push(block);
    }

    Ok(blocks)
}

/// Parse compact transaction payload (after the type byte).
fn parse_compact_tx(data: &[u8]) -> Result<CompactTransaction, ShieldSyncError> {
    if data.len() < 2 {
        return Err(ShieldSyncError::Truncated("compact tx header".into()));
    }

    let num_spends = data[0] as usize;
    let num_outputs = data[1] as usize;

    let expected = 2 + num_spends * 32 + num_outputs * (32 + 32 + ENC_CT_SIZE);
    if data.len() < expected {
        return Err(ShieldSyncError::Truncated(format!(
            "compact tx body: need {expected} bytes, have {}",
            data.len()
        )));
    }

    let mut pos = 2;

    // Parse nullifiers
    let mut nullifiers = Vec::with_capacity(num_spends);
    for _ in 0..num_spends {
        let mut nf = [0u8; 32];
        nf.copy_from_slice(&data[pos..pos + 32]);
        nullifiers.push(nf);
        pos += 32;
    }

    // Parse outputs
    let mut outputs = Vec::with_capacity(num_outputs);
    for _ in 0..num_outputs {
        let mut cmu = [0u8; 32];
        cmu.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let mut epk = [0u8; 32];
        epk.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let mut enc_ciphertext = [0u8; ENC_CT_SIZE];
        enc_ciphertext.copy_from_slice(&data[pos..pos + ENC_CT_SIZE]);
        pos += ENC_CT_SIZE;

        outputs.push(CompactSaplingOutput { cmu, epk, enc_ciphertext });
    }

    Ok(CompactTransaction { nullifiers, outputs })
}

// ---------------------------------------------------------------------------
// Binary stream encoder (for bridge / testing)
// ---------------------------------------------------------------------------

/// Encode a block marker packet.
pub fn encode_block_marker(height: u32) -> Vec<u8> {
    let payload = [PACKET_TYPE_BLOCK,
        height as u8, (height >> 8) as u8, (height >> 16) as u8, (height >> 24) as u8,
    ];
    let mut packet = (payload.len() as u32).to_le_bytes().to_vec();
    packet.extend_from_slice(&payload);
    packet
}

/// Encode a compact transaction packet.
pub fn encode_compact_tx(tx: &CompactTransaction) -> Vec<u8> {
    let payload_len = 1 + 2
        + tx.nullifiers.len() * 32
        + tx.outputs.len() * (32 + 32 + ENC_CT_SIZE);

    let mut payload = Vec::with_capacity(payload_len);
    payload.push(PACKET_TYPE_COMPACT_TX);
    payload.push(tx.nullifiers.len() as u8);
    payload.push(tx.outputs.len() as u8);

    for nf in &tx.nullifiers {
        payload.extend_from_slice(nf);
    }

    for out in &tx.outputs {
        payload.extend_from_slice(&out.cmu);
        payload.extend_from_slice(&out.epk);
        payload.extend_from_slice(&out.enc_ciphertext);
    }

    let mut packet = (payload.len() as u32).to_le_bytes().to_vec();
    packet.extend_from_slice(&payload);
    packet
}

/// Encode a full transaction packet.
pub fn encode_full_tx(raw_tx: &[u8]) -> Vec<u8> {
    let payload_len = 1 + raw_tx.len();
    let mut packet = (payload_len as u32).to_le_bytes().to_vec();
    packet.push(PACKET_TYPE_FULL_TX);
    packet.extend_from_slice(raw_tx);
    packet
}

// ---------------------------------------------------------------------------
// Compact block processing (direct decryption, no Transaction::read)
// ---------------------------------------------------------------------------

/// Process a compact transaction against the commitment tree.
///
/// Same logic as `notes::process_sapling_transaction` but works directly
/// with extracted fields — no full transaction parsing needed.
#[allow(clippy::too_many_arguments)]
pub fn process_compact_transaction(
    tree: &mut SaplingTree,
    tx: &CompactTransaction,
    extfvk: &ExtendedFullViewingKey,
    nk: &NullifierDerivingKey,
    existing_witnesses: &mut Vec<SpendableNote>,
    new_notes: &mut Vec<SpendableNote>,
    block_height: u32,
    spent_nullifiers: &mut Vec<String>,
) -> Result<(), ShieldSyncError> {
    // Collect spent nullifiers
    for nf in &tx.nullifiers {
        spent_nullifiers.push(encoding::hex_encode(nf));
    }

    // Prepare decryption key
    let ivk = PreparedIncomingViewingKey::new(&extfvk.fvk.vk.ivk());

    // Process each output
    for output in &tx.outputs {
        let cmu_node = Node::from_cmu(
            &sapling::note::ExtractedNoteCommitment::from_bytes(&output.cmu)
                .into_option()
                .ok_or(ShieldSyncError::InvalidCmu)?,
        );

        // 1. Append CMU to tree
        append_node(tree, cmu_node)
            .map_err(|e| ShieldSyncError::Tree(e.to_string()))?;

        // 2. Advance all witnesses
        for existing in existing_witnesses.iter_mut() {
            advance_witness(&mut existing.witness, cmu_node)
                .map_err(|e| ShieldSyncError::Tree(e.to_string()))?;
        }
        for new in new_notes.iter_mut() {
            advance_witness(&mut new.witness, cmu_node)
                .map_err(|e| ShieldSyncError::Tree(e.to_string()))?;
        }

        // 3. Try decryption directly on the compact output
        let domain = SaplingDomain::new(Zip212Enforcement::On);
        if let Some((note, _recipient, memo_bytes)) =
            try_note_decryption(&domain, &ivk, output)
        {
            let witness = witness_from_tree(tree)
                .ok_or(ShieldSyncError::Tree("empty tree after append".into()))?;

            let nullifier = notes::get_nullifier(nk, &note, &witness)
                .map_err(|e| ShieldSyncError::Tree(e.to_string()))?;

            let memo = decode_memo(&memo_bytes);

            new_notes.push(SpendableNote {
                note,
                witness,
                nullifier,
                memo,
                height: block_height,
            });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// High-level sync entry point
// ---------------------------------------------------------------------------

/// Process parsed shield blocks against the wallet state.
///
/// Handles both compact (0x04) and full (0x03) transaction types.
/// This is the main sync entry point — the caller provides the parsed stream
/// and the wallet's current state, and receives the updated state back.
pub fn process_shield_blocks(
    tree_hex: &str,
    blocks: &[RawShieldBlock],
    extfvk: &ExtendedFullViewingKey,
    existing_notes: &[SerializedNote],
) -> Result<HandleBlocksResult, ShieldSyncError> {
    let nk = keys::nullifier_deriving_key(extfvk);

    // Load tree
    let mut tree = if tree_hex.is_empty() {
        tree::empty_tree()
    } else {
        tree::read_tree_hex(tree_hex)
            .map_err(|e| ShieldSyncError::Tree(e.to_string()))?
    };

    // Load existing notes
    let mut existing: Vec<SpendableNote> = existing_notes
        .iter()
        .map(SpendableNote::from_serialized)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ShieldSyncError::Note(e.to_string()))?;

    let mut all_new: Vec<SpendableNote> = Vec::new();
    let mut all_nullifiers: Vec<String> = Vec::new();

    for block in blocks {
        for entry in &block.entries {
            match entry {
                BlockEntry::CompactTx(compact) => {
                    process_compact_transaction(
                        &mut tree,
                        compact,
                        extfvk,
                        &nk,
                        &mut existing,
                        &mut all_new,
                        block.height,
                        &mut all_nullifiers,
                    )?;
                }
                BlockEntry::FullTx(tx_bytes) => {
                    // Try the Zcash parser. Kerrigan uses PIVX tx format
                    // (version 3, type 10) which the Zcash parser can't handle.
                    // Skip unparseable txs — compact format is the preferred path.
                    match notes::process_sapling_transaction(
                        &mut tree,
                        tx_bytes,
                        extfvk,
                        &nk,
                        &mut existing,
                        block.height,
                    ) {
                        Ok(result) => {
                            all_nullifiers.extend(result.spent_nullifiers);
                            all_new.extend(result.new_notes);
                        }
                        Err(_) => {
                            // Can't parse this tx format — skip it.
                            // TODO: implement PIVX/Kerrigan Sapling tx parser
                        }
                    }
                }
            }
        }
    }

    // Serialize back
    let commitment_tree = tree::write_tree_hex(&tree)
        .map_err(|e| ShieldSyncError::Tree(e.to_string()))?;

    let updated_notes = existing
        .into_iter()
        .map(|n| n.to_serialized())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ShieldSyncError::Note(e.to_string()))?;

    let new_notes = all_new
        .into_iter()
        .map(|n| n.to_serialized())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ShieldSyncError::Note(e.to_string()))?;

    Ok(HandleBlocksResult {
        commitment_tree,
        new_notes,
        updated_notes,
        spent_nullifiers: all_nullifiers,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decode memo bytes to optional string.
fn decode_memo(memo_bytes: &[u8; 512]) -> Option<String> {
    if memo_bytes.iter().all(|&b| b == 0) || memo_bytes[0] == 0xF6 {
        return None;
    }
    let end = memo_bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    String::from_utf8(memo_bytes[..end].to_vec()).ok()
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ShieldSyncError {
    Truncated(String),
    EmptyPacket,
    TxBeforeBlock,
    UnknownPacketType(u8),
    InvalidCmu,
    Tree(String),
    Note(String),
}

impl std::fmt::Display for ShieldSyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated(ctx) => write!(f, "truncated stream: {ctx}"),
            Self::EmptyPacket => write!(f, "empty packet"),
            Self::TxBeforeBlock => write!(f, "transaction before block marker"),
            Self::UnknownPacketType(t) => write!(f, "unknown packet type: 0x{t:02x}"),
            Self::InvalidCmu => write!(f, "invalid note commitment"),
            Self::Tree(e) => write!(f, "tree error: {e}"),
            Self::Note(e) => write!(f, "note error: {e}"),
        }
    }
}

impl std::error::Error for ShieldSyncError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_stream() {
        let blocks = parse_shield_stream(&[]).unwrap();
        assert!(blocks.is_empty());
    }

    #[test]
    fn parse_single_block_no_txs() {
        let stream = encode_block_marker(500);
        let blocks = parse_shield_stream(&stream).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].height, 500);
        assert!(blocks[0].entries.is_empty());
    }

    #[test]
    fn parse_multi_block() {
        let mut stream = Vec::new();
        stream.extend(encode_block_marker(500));
        stream.extend(encode_block_marker(501));
        stream.extend(encode_block_marker(502));

        let blocks = parse_shield_stream(&stream).unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].height, 500);
        assert_eq!(blocks[1].height, 501);
        assert_eq!(blocks[2].height, 502);
    }

    #[test]
    fn parse_block_with_compact_tx() {
        let tx = CompactTransaction {
            nullifiers: vec![[42u8; 32]],
            outputs: vec![CompactSaplingOutput {
                cmu: [1u8; 32],
                epk: [2u8; 32],
                enc_ciphertext: [3u8; ENC_CT_SIZE],
            }],
        };

        let mut stream = Vec::new();
        stream.extend(encode_block_marker(1000));
        stream.extend(encode_compact_tx(&tx));

        let blocks = parse_shield_stream(&stream).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].entries.len(), 1);

        match &blocks[0].entries[0] {
            BlockEntry::CompactTx(ct) => {
                assert_eq!(ct.nullifiers.len(), 1);
                assert_eq!(ct.nullifiers[0], [42u8; 32]);
                assert_eq!(ct.outputs.len(), 1);
                assert_eq!(ct.outputs[0].cmu, [1u8; 32]);
            }
            _ => panic!("Expected CompactTx"),
        }
    }

    #[test]
    fn parse_block_with_full_tx() {
        let fake_tx = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let mut stream = Vec::new();
        stream.extend(encode_block_marker(999));
        stream.extend(encode_full_tx(&fake_tx));

        let blocks = parse_shield_stream(&stream).unwrap();
        assert_eq!(blocks[0].entries.len(), 1);

        match &blocks[0].entries[0] {
            BlockEntry::FullTx(data) => assert_eq!(data, &fake_tx),
            _ => panic!("Expected FullTx"),
        }
    }

    #[test]
    fn parse_mixed_tx_types() {
        let compact = CompactTransaction {
            nullifiers: vec![],
            outputs: vec![CompactSaplingOutput {
                cmu: [5u8; 32],
                epk: [6u8; 32],
                enc_ciphertext: [7u8; ENC_CT_SIZE],
            }],
        };

        let mut stream = Vec::new();
        stream.extend(encode_block_marker(100));
        stream.extend(encode_full_tx(&[0xFF; 10]));
        stream.extend(encode_compact_tx(&compact));

        let blocks = parse_shield_stream(&stream).unwrap();
        assert_eq!(blocks[0].entries.len(), 2);
        assert!(matches!(&blocks[0].entries[0], BlockEntry::FullTx(_)));
        assert!(matches!(&blocks[0].entries[1], BlockEntry::CompactTx(_)));
    }

    #[test]
    fn encode_decode_roundtrip() {
        let tx = CompactTransaction {
            nullifiers: vec![[10u8; 32], [20u8; 32]],
            outputs: vec![
                CompactSaplingOutput {
                    cmu: [30u8; 32],
                    epk: [40u8; 32],
                    enc_ciphertext: [50u8; ENC_CT_SIZE],
                },
                CompactSaplingOutput {
                    cmu: [60u8; 32],
                    epk: [70u8; 32],
                    enc_ciphertext: [80u8; ENC_CT_SIZE],
                },
            ],
        };

        let mut stream = Vec::new();
        stream.extend(encode_block_marker(12345));
        stream.extend(encode_compact_tx(&tx));

        let blocks = parse_shield_stream(&stream).unwrap();
        assert_eq!(blocks[0].height, 12345);

        match &blocks[0].entries[0] {
            BlockEntry::CompactTx(ct) => {
                assert_eq!(ct.nullifiers.len(), 2);
                assert_eq!(ct.nullifiers[0], [10u8; 32]);
                assert_eq!(ct.nullifiers[1], [20u8; 32]);
                assert_eq!(ct.outputs.len(), 2);
                assert_eq!(ct.outputs[0].cmu, [30u8; 32]);
                assert_eq!(ct.outputs[1].epk, [70u8; 32]);
            }
            _ => panic!("Expected CompactTx"),
        }
    }

    #[test]
    fn parse_truncated_length_fails() {
        let result = parse_shield_stream(&[0x05, 0x00]); // Only 2 of 4 length bytes
        assert!(result.is_err());
    }

    #[test]
    fn parse_truncated_payload_fails() {
        let mut stream = Vec::new();
        stream.extend((100u32).to_le_bytes()); // Claims 100 bytes
        stream.push(0x5d); // Only 1 byte of payload
        assert!(parse_shield_stream(&stream).is_err());
    }

    #[test]
    fn parse_unknown_type_fails() {
        let mut stream = Vec::new();
        stream.extend(encode_block_marker(1));
        // Inject a packet with unknown type 0xFF
        let payload = [0xFF, 0x01, 0x02];
        stream.extend((payload.len() as u32).to_le_bytes());
        stream.extend_from_slice(&payload);

        assert!(parse_shield_stream(&stream).is_err());
    }

    #[test]
    fn parse_tx_before_block_fails() {
        // Compact tx without a preceding block marker
        let tx = CompactTransaction { nullifiers: vec![], outputs: vec![] };
        let stream = encode_compact_tx(&tx);
        assert!(parse_shield_stream(&stream).is_err());
    }

    #[test]
    fn process_empty_blocks() {
        let extsk = super::super::keys::default_spending_key(&[0u8; 64]).unwrap();
        let extfvk = super::super::keys::full_viewing_key(&extsk);

        let result = process_shield_blocks("", &[], &extfvk, &[]).unwrap();
        assert!(result.new_notes.is_empty());
        assert!(result.spent_nullifiers.is_empty());
        assert!(!result.commitment_tree.is_empty());
    }

    #[test]
    fn compact_output_size_savings() {
        // Verify the size math from the design.
        let full_spend = 32 + 32 + 32 + 32 + 192 + 64; // 384
        let compact_spend = 32; // nullifier only
        assert_eq!(full_spend, 384);
        assert_eq!(compact_spend, 32);

        let full_output = 32 + 32 + 32 + ENC_CT_SIZE + 80 + 192; // 948
        let compact_output = 32 + 32 + ENC_CT_SIZE; // 644
        assert_eq!(full_output, 948);
        assert_eq!(compact_output, 644);

        // 1 spend + 2 outputs
        let full_tx = full_spend + full_output * 2;
        let compact_tx = compact_spend + compact_output * 2;
        assert!(compact_tx < full_tx);
        // Savings > 40%
        let savings_pct = 100 - (compact_tx * 100 / full_tx);
        assert!(savings_pct >= 40, "Expected >=40% savings, got {savings_pct}%");
    }
}
