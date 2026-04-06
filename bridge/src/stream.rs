/// Binary stream encoder — produces the compact shield sync protocol.
///
/// Takes scanned `RawShieldBlock`s and encodes them into the binary wire
/// format that light wallets consume via the SDK's `parse_shield_stream`.
use kerrigan_sdk::sapling::sync::{
    encode_block_marker, encode_compact_tx, BlockEntry, RawShieldBlock,
};

/// Encode a slice of shield blocks into a binary stream.
///
/// The stream is a sequence of length-prefixed packets that the SDK's
/// `parse_shield_stream()` can decode directly.
pub fn encode_shield_stream(blocks: &[RawShieldBlock]) -> Vec<u8> {
    let mut stream = Vec::new();

    for block in blocks {
        // Block marker
        stream.extend(encode_block_marker(block.height));

        // Transactions
        for entry in &block.entries {
            match entry {
                BlockEntry::CompactTx(tx) => {
                    stream.extend(encode_compact_tx(tx));
                }
                BlockEntry::FullTx(raw) => {
                    // Full tx encoding (legacy compat)
                    stream.extend(kerrigan_sdk::sapling::sync::encode_full_tx(raw));
                }
            }
        }
    }

    stream
}
