/// Shield block index — tracks which blocks contain Sapling transactions.
///
/// Persisted as a simple JSON file so the bridge doesn't need to rescan
/// the entire chain on restart.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldIndex {
    /// Block heights that contain Sapling transactions.
    pub shield_heights: Vec<u32>,
    /// Highest block we've scanned so far.
    pub last_scanned: u32,
}

impl ShieldIndex {
    pub fn new(start_height: u32) -> Self {
        Self {
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

    /// Record that a block at the given height has Sapling data.
    pub fn add_shield_block(&mut self, height: u32) {
        if !self.shield_heights.contains(&height) {
            self.shield_heights.push(height);
            self.shield_heights.sort_unstable();
        }
    }

    /// Get shield block heights >= start_block.
    pub fn heights_from(&self, start_block: u32) -> Vec<u32> {
        self.shield_heights
            .iter()
            .copied()
            .filter(|&h| h >= start_block)
            .collect()
    }
}
