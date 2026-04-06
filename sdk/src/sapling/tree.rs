/// Sapling commitment tree operations.
///
/// Wraps `incrementalmerkletree` types for the Kerrigan Sapling tree (depth 32).
/// Provides hex serialization for persistence and root extraction for verification.

use std::io::Cursor;

use incrementalmerkletree::frontier::CommitmentTree;
use incrementalmerkletree::witness::IncrementalWitness;
use sapling::Node;
use pivx_primitives::merkle_tree::{
    read_commitment_tree, read_incremental_witness, write_commitment_tree,
    write_incremental_witness,
};

use crate::encoding;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

/// Depth of the Sapling Merkle commitment tree.
pub const DEPTH: u8 = 32;

/// Sapling commitment tree (Merkle frontier).
pub type SaplingTree = CommitmentTree<Node, DEPTH>;

/// Incremental witness for a single note in the Sapling commitment tree.
pub type SaplingWitness = IncrementalWitness<Node, DEPTH>;

// ---------------------------------------------------------------------------
// Tree lifecycle
// ---------------------------------------------------------------------------

/// Create a new, empty commitment tree.
pub fn empty_tree() -> SaplingTree {
    SaplingTree::empty()
}

/// Append a Sapling note commitment (CMU node) to the tree.
pub fn append_node(tree: &mut SaplingTree, node: Node) -> Result<(), SaplingTreeError> {
    tree.append(node)
        .map_err(|_| SaplingTreeError::TreeFull)
}

/// Get the root hash of the commitment tree (32 bytes).
pub fn tree_root(tree: &SaplingTree) -> [u8; 32] {
    tree.root().to_bytes()
}

/// Get the root hash as a hex string (byte-reversed for network endianness).
pub fn tree_root_hex(tree: &SaplingTree) -> String {
    let mut bytes = tree.root().to_bytes();
    bytes.reverse();
    encoding::hex_encode(&bytes)
}

// ---------------------------------------------------------------------------
// Witness operations
// ---------------------------------------------------------------------------

/// Create a witness snapshot at the current tree state.
///
/// Call this immediately after appending a note we own — the witness tracks
/// the Merkle path from that leaf to the root as future leaves are appended.
///
/// Returns the witness, or `None` if the tree is empty.
pub fn witness_from_tree(tree: &SaplingTree) -> Option<SaplingWitness> {
    // incrementalmerkletree 0.7: from_tree returns directly (not Option).
    // It panics on empty tree, so we guard with size check.
    if tree.size() == 0 {
        None
    } else {
        Some(SaplingWitness::from_tree(tree.clone()))
    }
}

/// Advance a witness by appending a new node.
///
/// Must be called for every CMU appended to the tree (whether ours or not)
/// to keep the witness's Merkle path up to date.
pub fn advance_witness(
    witness: &mut SaplingWitness,
    node: Node,
) -> Result<(), SaplingTreeError> {
    witness
        .append(node)
        .map_err(|_| SaplingTreeError::WitnessAppend)
}

// ---------------------------------------------------------------------------
// Hex serialization (persistence)
// ---------------------------------------------------------------------------

/// Deserialize a commitment tree from a hex string.
pub fn read_tree_hex(hex: &str) -> Result<SaplingTree, SaplingTreeError> {
    let bytes = encoding::hex_decode(hex)
        .map_err(|e| SaplingTreeError::Hex(e.to_string()))?;
    read_commitment_tree(Cursor::new(bytes))
        .map_err(|e| SaplingTreeError::Io(e.to_string()))
}

/// Serialize a commitment tree to a hex string.
pub fn write_tree_hex(tree: &SaplingTree) -> Result<String, SaplingTreeError> {
    let mut buf = Vec::new();
    write_commitment_tree(tree, &mut buf)
        .map_err(|e| SaplingTreeError::Io(e.to_string()))?;
    Ok(encoding::hex_encode(&buf))
}

/// Deserialize an incremental witness from a hex string.
pub fn read_witness_hex(hex: &str) -> Result<SaplingWitness, SaplingTreeError> {
    let bytes = encoding::hex_decode(hex)
        .map_err(|e| SaplingTreeError::Hex(e.to_string()))?;
    read_incremental_witness(Cursor::new(bytes))
        .map_err(|e| SaplingTreeError::Io(e.to_string()))
}

/// Serialize an incremental witness to a hex string.
pub fn write_witness_hex(witness: &SaplingWitness) -> Result<String, SaplingTreeError> {
    let mut buf = Vec::new();
    write_incremental_witness(witness, &mut buf)
        .map_err(|e| SaplingTreeError::Io(e.to_string()))?;
    Ok(encoding::hex_encode(&buf))
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum SaplingTreeError {
    TreeFull,
    WitnessAppend,
    Io(String),
    Hex(String),
}

impl std::fmt::Display for SaplingTreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TreeFull => write!(f, "Sapling commitment tree is full"),
            Self::WitnessAppend => write!(f, "failed to append node to witness"),
            Self::Io(e) => write!(f, "tree I/O error: {e}"),
            Self::Hex(e) => write!(f, "hex decode error: {e}"),
        }
    }
}

impl std::error::Error for SaplingTreeError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a deterministic test node from a byte value.
    fn test_node(val: u8) -> Node {
        let mut bytes = [0u8; 32];
        bytes[0] = val;
        Node::from_bytes(bytes).unwrap()
    }

    #[test]
    fn empty_tree_has_root() {
        let tree = empty_tree();
        let root = tree_root(&tree);
        // Empty tree root is deterministic (all-zero leaves hashed up).
        assert_ne!(root, [0u8; 32], "Empty tree root should not be all zeros");
    }

    #[test]
    fn empty_tree_root_is_deterministic() {
        let root1 = tree_root(&empty_tree());
        let root2 = tree_root(&empty_tree());
        assert_eq!(root1, root2);
    }

    #[test]
    fn append_changes_root() {
        let mut tree = empty_tree();
        let root_before = tree_root(&tree);
        // Note: test_node(1) == the Sapling "uncommitted" leaf (jubjub::Base::one()),
        // so use a different value to observe a root change.
        append_node(&mut tree, test_node(42)).unwrap();
        let root_after = tree_root(&tree);
        assert_ne!(root_before, root_after);
    }

    #[test]
    fn different_nodes_produce_different_roots() {
        let mut tree_a = empty_tree();
        append_node(&mut tree_a, test_node(1)).unwrap();

        let mut tree_b = empty_tree();
        append_node(&mut tree_b, test_node(2)).unwrap();

        assert_ne!(tree_root(&tree_a), tree_root(&tree_b));
    }

    #[test]
    fn tree_hex_roundtrip() {
        let mut tree = empty_tree();
        append_node(&mut tree, test_node(42)).unwrap();

        let hex = write_tree_hex(&tree).unwrap();
        let restored = read_tree_hex(&hex).unwrap();

        assert_eq!(tree_root(&tree), tree_root(&restored));
    }

    #[test]
    fn empty_tree_hex_roundtrip() {
        let tree = empty_tree();
        let hex = write_tree_hex(&tree).unwrap();
        let restored = read_tree_hex(&hex).unwrap();
        assert_eq!(tree_root(&tree), tree_root(&restored));
    }

    #[test]
    fn tree_root_hex_is_reversed() {
        let tree = empty_tree();
        let raw = tree_root(&tree);
        let hex = tree_root_hex(&tree);

        // Decode the hex back and verify it's the reverse of raw.
        let decoded = encoding::hex_decode(&hex).unwrap();
        let reversed: Vec<u8> = raw.iter().rev().copied().collect();
        assert_eq!(decoded, reversed);
    }

    #[test]
    fn witness_from_empty_tree_is_none() {
        let tree = empty_tree();
        assert!(witness_from_tree(&tree).is_none());
    }

    #[test]
    fn witness_from_nonempty_tree_is_some() {
        let mut tree = empty_tree();
        append_node(&mut tree, test_node(1)).unwrap();
        assert!(witness_from_tree(&tree).is_some());
    }

    #[test]
    fn witness_hex_roundtrip() {
        let mut tree = empty_tree();
        append_node(&mut tree, test_node(1)).unwrap();
        let witness = witness_from_tree(&tree).unwrap();

        let hex = write_witness_hex(&witness).unwrap();
        let _restored = read_witness_hex(&hex).unwrap();
    }

    #[test]
    fn advance_witness_succeeds() {
        let mut tree = empty_tree();
        append_node(&mut tree, test_node(1)).unwrap();
        let mut witness = witness_from_tree(&tree).unwrap();

        // Append more nodes — witness must stay in sync with tree.
        for i in 2..=5 {
            let node = test_node(i);
            append_node(&mut tree, node).unwrap();
            advance_witness(&mut witness, node).unwrap();
        }
    }

    #[test]
    fn read_tree_invalid_hex_fails() {
        assert!(read_tree_hex("zzzz").is_err());
    }
}
