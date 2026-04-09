/// Shield block index — tracks which blocks contain Sapling transactions.
///
/// Persisted as JSON. Tracks both block heights and byte offsets into
/// shield.bin for instant buffer-slice serving.
use serde::{Deserialize, Serialize};
use std::path::Path;

/// An entry in the shield index: block height + byte offset into shield.bin.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexEntry {
    pub block: u32,
    /// Byte offset into shield.bin where this block's data starts.
    #[serde(default)]
    pub offset: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldIndex {
    /// Ordered list of shield block entries (with byte offsets).
    pub entries: Vec<IndexEntry>,
    /// Just the heights (for fast lookup).
    #[serde(default)]
    pub shield_heights: Vec<u32>,
    /// Highest block we've scanned so far.
    pub last_scanned: u32,
}

impl ShieldIndex {
    pub fn new(start_height: u32) -> Self {
        Self {
            entries: Vec::new(),
            shield_heights: Vec::new(),
            last_scanned: start_height.saturating_sub(1),
        }
    }

    /// Load from a JSON file, or create a new index if the file doesn't exist.
    pub fn load_or_new(path: &str, start_height: u32) -> Self {
        if Path::new(path).exists() {
            match std::fs::read_to_string(path) {
                Ok(json) => match serde_json::from_str(&json) {
                    Ok(index) => return index,
                    Err(e) => eprintln!("Warning: corrupt index file, starting fresh: {e}"),
                },
                Err(e) => eprintln!("Warning: can't read index file, starting fresh: {e}"),
            }
        }
        Self::new(start_height)
    }

    /// Persist to a JSON file.
    pub fn save(&self, path: &str) -> Result<(), std::io::Error> {
        let json = serde_json::to_string_pretty(self)
            .map_err(std::io::Error::other)?;
        std::fs::write(path, json)
    }

    /// Record a shield block with its byte offset into shield.bin.
    pub fn add(&mut self, height: u32, byte_offset: u64) {
        if !self.shield_heights.contains(&height) {
            self.entries.push(IndexEntry { block: height, offset: byte_offset });
            self.shield_heights.push(height);
        }
    }

    /// Legacy: record a shield block without offset (backward compat).
    pub fn add_shield_block(&mut self, height: u32) {
        self.add(height, 0);
    }

    /// Get shield block heights >= start_block.
    pub fn heights_from(&self, start_block: u32) -> Vec<u32> {
        let idx = self.shield_heights.partition_point(|&h| h < start_block);
        self.shield_heights[idx..].to_vec()
    }

    /// Get the byte offset for the first shield block >= start_block.
    pub fn offset_for_height(&self, height: u32) -> Option<u64> {
        let idx = self.entries.partition_point(|e| e.block < height);
        self.entries.get(idx).map(|e| e.offset)
    }

    /// Remove all entries at or above the given height (for reorg handling).
    pub fn remove_from(&mut self, height: u32) {
        self.entries.retain(|e| e.block < height);
        self.shield_heights.retain(|&h| h < height);
    }
}
