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

/// Recover shield.bin by truncating only the trailing incomplete packet, if any.
///
/// Walks the binary stream packet-by-packet. A packet is complete when the
/// entire body declared by its length prefix is present in the file. The
/// first truncated packet marks the recovery point: everything before it is
/// kept (including the full last-block's tx packets), everything from it
/// onwards is discarded.
///
/// Previous behavior truncated at the byte right after the last block
/// marker, which unconditionally deleted the final block's tx packets even
/// on a clean shutdown — so every restart silently orphaned one block's
/// worth of data, leaving a marker-only entry in the stream.
///
/// Returns the height of the last block marker that survives the recovery,
/// or None if the file is empty / has no markers.
pub fn recover_cache(path: &str) -> Option<u32> {
    if !Path::new(path).exists() || fs::metadata(path).map(|m| m.len()).unwrap_or(0) == 0 {
        return None;
    }

    let data = fs::read(path).ok()?;

    // Walk packets: advance while each is complete, stop at the first truncated one.
    let mut pos = 0;
    let mut last_complete_end = 0;
    let mut last_marker_height: Option<u32> = None;

    while pos + 4 <= data.len() {
        let len = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
            as usize;
        let packet_end = pos + 4 + len;
        if packet_end > data.len() {
            // Truncated packet — recovery point.
            break;
        }

        // Block marker: payload type byte 0x5d with payload len 5 (compact) or 9 (legacy).
        // We need +8 bounds for the 4-byte height read below.
        if (len == 5 || len == 9) && pos + 9 <= data.len() && data[pos + 4] == 0x5d {
            last_marker_height = Some(u32::from_le_bytes([
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
                data[pos + 8],
            ]));
        }

        pos = packet_end;
        last_complete_end = packet_end;
    }

    if last_complete_end < data.len() {
        eprintln!(
            "  [recovery] Truncating shield.bin from {} to {} bytes (incomplete trailing packet)",
            data.len(),
            last_complete_end
        );
        let file = OpenOptions::new().write(true).open(path).ok()?;
        file.set_len(last_complete_end as u64).ok()?;
    }

    last_marker_height
}
