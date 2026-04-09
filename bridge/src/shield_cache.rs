/// Persistent binary cache — shield.bin management.
///
/// The scan loop writes pre-encoded compact shield data to disk.
/// On startup, the entire file is loaded into RAM. HTTP requests serve
/// byte slices from the in-memory buffer — zero disk I/O, zero RPC.
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use kerrigan_sdk::sapling::sync::RawShieldBlock;

use crate::api::StreamFormat;
use crate::stream;

/// Open (or create) the shield.bin cache file.
pub fn open_cache(path: &str) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

/// Append multiple shield blocks to the cache file with a single flush.
///
/// Returns a vec of `(height, byte_offset, byte_length)` for each block.
pub fn append_blocks(
    file: &mut File,
    blocks: &[RawShieldBlock],
) -> std::io::Result<Vec<(u32, u64, u64)>> {
    let mut current_offset = file.seek(SeekFrom::End(0))?;
    let mut entries = Vec::with_capacity(blocks.len());

    for block in blocks {
        let encoded = stream::encode_shield_stream(
            std::slice::from_ref(block),
            StreamFormat::Compact, // default format
        );
        file.write_all(&encoded)?;
        entries.push((block.height, current_offset, encoded.len() as u64));
        current_offset += encoded.len() as u64;
    }

    file.flush()?;
    Ok(entries)
}

/// Recover shield.bin by truncating to the last complete block marker.
///
/// Scans through the binary stream to find the last valid block marker
/// (0x5d packet), then truncates everything after it. Prevents a
/// half-written block from corrupting the stream on crash.
///
/// Returns the height of the last good block, or None if empty/corrupt.
pub fn recover_cache(path: &str) -> Option<u32> {
    if !Path::new(path).exists() || fs::metadata(path).map(|m| m.len()).unwrap_or(0) == 0 {
        return None;
    }

    let data = fs::read(path).ok()?;
    let last_marker_end = find_last_block_marker(&data)?;

    if last_marker_end < data.len() {
        eprintln!(
            "  [recovery] Truncating shield.bin from {} to {} bytes",
            data.len(),
            last_marker_end
        );
        let file = OpenOptions::new().write(true).open(path).ok()?;
        file.set_len(last_marker_end as u64).ok()?;
    }

    // Extract height from the last block marker.
    // Compact block marker: [4-byte LE len=5][0x5d][height:4LE]
    let marker_start = last_marker_end - 5; // 5-byte payload
    let height = u32::from_le_bytes([
        data[marker_start + 1],
        data[marker_start + 2],
        data[marker_start + 3],
        data[marker_start + 4],
    ]);

    Some(height)
}

/// Scan the binary stream to find the byte offset just past the last
/// complete block marker (0x5d packet).
fn find_last_block_marker(data: &[u8]) -> Option<usize> {
    let mut pos = 0;
    let mut last_marker_end = None;

    while pos + 4 <= data.len() {
        let len = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
            as usize;

        let packet_end = pos + 4 + len;
        if packet_end > data.len() {
            break; // Incomplete packet
        }

        // Block marker: first payload byte is 0x5d, length is 5 (compact) or 9 (pivx-compat)
        if (len == 5 || len == 9) && data[pos + 4] == 0x5d {
            last_marker_end = Some(packet_end);
        }

        pos = packet_end;
    }

    last_marker_end
}
