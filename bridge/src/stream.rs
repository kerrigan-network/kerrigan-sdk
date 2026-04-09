/// Binary stream encoder — produces the compact shield sync protocol.
///
/// Takes scanned `RawShieldBlock`s and encodes them into the binary wire
/// format that light wallets consume via the SDK's `parse_shield_stream`.
use kerrigan_sdk::sapling::sync::{
    encode_block_marker, encode_compact_tx, encode_compact_plus_tx,
    BlockEntry, RawShieldBlock,
};

use crate::api::StreamFormat;

/// Encode a slice of shield blocks into a binary stream.
///
/// The stream is a sequence of length-prefixed packets that the SDK's
/// `parse_shield_stream()` can decode directly.
///
/// The `format` parameter controls which packet type is used for compact data:
/// - `Compact` (default): 0x04 packets with out_ciphertext (724 bytes/output)
/// - `CompactPlus`: 0x05 packets without out_ciphertext (644 bytes/output)
pub fn encode_shield_stream(blocks: &[RawShieldBlock], format: StreamFormat) -> Vec<u8> {
    let mut stream = Vec::new();

    for block in blocks {
        // Block marker
        stream.extend(encode_block_marker(block.height));

        // Transactions
        for entry in &block.entries {
            match entry {
                BlockEntry::CompactTx(tx) => match format {
                    StreamFormat::Compact => stream.extend(encode_compact_tx(tx)),
                    StreamFormat::CompactPlus => stream.extend(encode_compact_plus_tx(tx)),
                },
                BlockEntry::FullTx(raw) => {
                    // Full tx encoding (legacy compat)
                    stream.extend(kerrigan_sdk::sapling::sync::encode_full_tx(raw));
                }
            }
        }
    }

    stream
}
