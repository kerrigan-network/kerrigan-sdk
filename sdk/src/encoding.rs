/// From-scratch encoding utilities: hex, Base58Check, and Bitcoin varint.
use sha2::{Sha256, Digest};
use std::fmt;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum EncodingError {
    InvalidHex(String),
    InvalidBase58(String),
    ChecksumMismatch,
    InvalidLength,
}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHex(s) => write!(f, "Invalid hex: {s}"),
            Self::InvalidBase58(s) => write!(f, "Invalid Base58: {s}"),
            Self::ChecksumMismatch => write!(f, "Base58Check checksum mismatch"),
            Self::InvalidLength => write!(f, "Invalid length"),
        }
    }
}

impl std::error::Error for EncodingError {}

// ---------------------------------------------------------------------------
// Hex encoding/decoding
// ---------------------------------------------------------------------------

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

/// Encode bytes to lowercase hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode a hex string to bytes. Accepts both upper and lowercase.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, EncodingError> {
    if !s.len().is_multiple_of(2) {
        return Err(EncodingError::InvalidHex("odd length".into()));
    }
    let bytes = s.as_bytes();
    let mut result = Vec::with_capacity(s.len() / 2);
    for chunk in bytes.chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        result.push((hi << 4) | lo);
    }
    Ok(result)
}

#[inline]
fn hex_nibble(c: u8) -> Result<u8, EncodingError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(EncodingError::InvalidHex(format!("invalid char: {}", c as char))),
    }
}

// ---------------------------------------------------------------------------
// Base58 encoding/decoding
// ---------------------------------------------------------------------------

const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Reverse lookup table: ASCII byte -> Base58 digit (0-57), or 0xFF if invalid.
const BASE58_DECODE_TABLE: [u8; 128] = {
    let mut table = [0xFFu8; 128];
    let mut i = 0;
    while i < 58 {
        table[BASE58_ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// Encode bytes to Base58 (no checksum).
pub fn base58_encode(payload: &[u8]) -> String {
    if payload.is_empty() {
        return String::new();
    }

    // Count leading zeros
    let leading_zeros = payload.iter().take_while(|&&b| b == 0).count();

    // Convert the non-zero suffix to base58 using repeated division
    let mut digits = payload[leading_zeros..].to_vec();
    let mut encoded = Vec::new();

    while !digits.is_empty() {
        let mut remainder = 0u32;
        let mut new_digits = Vec::new();
        for &d in &digits {
            let acc = (remainder << 8) | d as u32;
            let quotient = acc / 58;
            remainder = acc % 58;
            if !new_digits.is_empty() || quotient > 0 {
                new_digits.push(quotient as u8);
            }
        }
        encoded.push(BASE58_ALPHABET[remainder as usize]);
        digits = new_digits;
    }

    // Add '1' for each leading zero byte
    encoded.resize(encoded.len() + leading_zeros, b'1');

    encoded.reverse();
    String::from_utf8(encoded).expect("Base58 alphabet is ASCII")
}

/// Decode a Base58 string to bytes (no checksum verification).
pub fn base58_decode(s: &str) -> Result<Vec<u8>, EncodingError> {
    if s.is_empty() {
        return Ok(Vec::new());
    }

    // Count leading '1's (represent zero bytes)
    let leading_ones = s.bytes().take_while(|&b| b == b'1').count();

    // Convert from base58 to base256
    let mut result: Vec<u8> = Vec::new();
    for c in s.bytes() {
        if c >= 128 {
            return Err(EncodingError::InvalidBase58(format!("non-ASCII char: {}", c as char)));
        }
        let digit = BASE58_DECODE_TABLE[c as usize];
        if digit == 0xFF {
            return Err(EncodingError::InvalidBase58(format!("invalid char: {}", c as char)));
        }

        let mut carry = digit as u32;
        for byte in result.iter_mut().rev() {
            let acc = (*byte as u32) * 58 + carry;
            *byte = (acc & 0xFF) as u8;
            carry = acc >> 8;
        }
        while carry > 0 {
            result.insert(0, (carry & 0xFF) as u8);
            carry >>= 8;
        }
    }

    // Prepend zero bytes for leading '1's
    let mut output = vec![0u8; leading_ones];
    output.extend_from_slice(&result);
    Ok(output)
}

/// Encode with Base58Check: [version_byte || data || checksum(4)].
pub fn base58check_encode(version: u8, data: &[u8]) -> String {
    let mut payload = Vec::with_capacity(1 + data.len() + 4);
    payload.push(version);
    payload.extend_from_slice(data);

    let checksum = sha256d(&payload);
    payload.extend_from_slice(&checksum[..4]);

    base58_encode(&payload)
}

/// Decode Base58Check, returning (version_byte, data).
pub fn base58check_decode(s: &str) -> Result<(u8, Vec<u8>), EncodingError> {
    let bytes = base58_decode(s)?;
    if bytes.len() < 5 {
        return Err(EncodingError::InvalidLength);
    }

    let (payload, checksum) = bytes.split_at(bytes.len() - 4);
    let computed = sha256d(payload);
    if checksum != &computed[..4] {
        return Err(EncodingError::ChecksumMismatch);
    }

    let version = payload[0];
    let data = payload[1..].to_vec();
    Ok((version, data))
}

// ---------------------------------------------------------------------------
// Bitcoin varint (CompactSize)
// ---------------------------------------------------------------------------

/// Write a Bitcoin-style variable-length integer to a buffer.
pub fn write_varint(buf: &mut Vec<u8>, val: u64) {
    if val < 0xfd {
        buf.push(val as u8);
    } else if val <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

/// Read a Bitcoin-style variable-length integer from data at the given offset.
/// Advances the offset past the varint.
pub fn read_varint(data: &[u8], offset: &mut usize) -> Result<u64, EncodingError> {
    if *offset >= data.len() {
        return Err(EncodingError::InvalidLength);
    }

    let first = data[*offset];
    *offset += 1;

    match first {
        0..=0xfc => Ok(first as u64),
        0xfd => {
            if *offset + 2 > data.len() {
                return Err(EncodingError::InvalidLength);
            }
            let val = u16::from_le_bytes([data[*offset], data[*offset + 1]]);
            *offset += 2;
            Ok(val as u64)
        }
        0xfe => {
            if *offset + 4 > data.len() {
                return Err(EncodingError::InvalidLength);
            }
            let val = u32::from_le_bytes([
                data[*offset], data[*offset + 1],
                data[*offset + 2], data[*offset + 3],
            ]);
            *offset += 4;
            Ok(val as u64)
        }
        0xff => {
            if *offset + 8 > data.len() {
                return Err(EncodingError::InvalidLength);
            }
            let val = u64::from_le_bytes([
                data[*offset], data[*offset + 1],
                data[*offset + 2], data[*offset + 3],
                data[*offset + 4], data[*offset + 5],
                data[*offset + 6], data[*offset + 7],
            ]);
            *offset += 8;
            Ok(val)
        }
    }
}

// ---------------------------------------------------------------------------
// Hash utilities (used by Base58Check and throughout the codebase)
// ---------------------------------------------------------------------------

/// Double SHA256: SHA256(SHA256(data)).
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let hash1 = Sha256::digest(data);
    let hash2 = Sha256::digest(hash1);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash2);
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Hex tests --

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn hex_encode_basic() {
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xff]), "ff");
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn hex_decode_basic() {
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(hex_decode("00").unwrap(), vec![0x00]);
        assert_eq!(hex_decode("ff").unwrap(), vec![0xff]);
        assert_eq!(hex_decode("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn hex_decode_uppercase() {
        assert_eq!(hex_decode("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(hex_decode("DeAdBeEf").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn hex_decode_odd_length() {
        assert!(matches!(hex_decode("abc"), Err(EncodingError::InvalidHex(_))));
    }

    #[test]
    fn hex_decode_invalid_char() {
        assert!(matches!(hex_decode("zz"), Err(EncodingError::InvalidHex(_))));
    }

    #[test]
    fn hex_roundtrip() {
        let data = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(hex_decode(&hex_encode(&data)).unwrap(), data);
    }

    // -- Base58 tests --

    #[test]
    fn base58_encode_empty() {
        assert_eq!(base58_encode(&[]), "");
    }

    #[test]
    fn base58_leading_zeros() {
        // Leading zero bytes map to '1' characters
        assert_eq!(base58_encode(&[0, 0, 0]), "111");
        assert_eq!(base58_encode(&[0, 0, 1]), "112");
    }

    #[test]
    fn base58_known_vectors() {
        // Bitcoin wiki test vectors
        assert_eq!(base58_encode(&hex_decode("00").unwrap()), "1");
        assert_eq!(
            base58_encode(&hex_decode("0000000000000000000000000000000000000000").unwrap()),
            "11111111111111111111"
        );
    }

    #[test]
    fn base58_decode_roundtrip() {
        let test_cases: Vec<&[u8]> = vec![
            &[],
            &[0],
            &[0, 0, 0],
            &[1],
            &[0, 0, 1],
            &[255],
            &[1, 2, 3, 4, 5],
            &[0xde, 0xad, 0xbe, 0xef],
        ];
        for data in test_cases {
            let encoded = base58_encode(data);
            let decoded = base58_decode(&encoded).unwrap();
            assert_eq!(decoded, data, "roundtrip failed for {:?}", data);
        }
    }

    #[test]
    fn base58_decode_invalid_char() {
        assert!(matches!(base58_decode("0OIl"), Err(EncodingError::InvalidBase58(_))));
    }

    // -- Base58Check tests --

    #[test]
    fn base58check_roundtrip() {
        let test_data: &[u8] = &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                                  0x11, 0x12, 0x13, 0x14];
        for version in [0u8, 45, 16, 204, 255] {
            let encoded = base58check_encode(version, test_data);
            let (dec_version, dec_data) = base58check_decode(&encoded).unwrap();
            assert_eq!(dec_version, version);
            assert_eq!(dec_data, test_data);
        }
    }

    #[test]
    fn base58check_invalid_checksum() {
        let encoded = base58check_encode(45, &[0u8; 20]);
        // Tamper with the last character
        let mut chars: Vec<char> = encoded.chars().collect();
        let last = chars.last_mut().unwrap();
        *last = if *last == '1' { '2' } else { '1' };
        let tampered: String = chars.into_iter().collect();
        assert!(matches!(base58check_decode(&tampered), Err(EncodingError::ChecksumMismatch)));
    }

    #[test]
    fn base58check_too_short() {
        assert!(matches!(base58check_decode("1"), Err(EncodingError::InvalidLength)));
    }

    #[test]
    fn base58check_kerrigan_prefix() {
        // Version byte 45 should produce addresses starting with 'K'
        let hash = [0u8; 20]; // Dummy pubkey hash
        let addr = base58check_encode(45, &hash);
        assert!(addr.starts_with('K'), "Expected K prefix, got: {}", addr);
    }

    #[test]
    fn base58check_p2sh_prefix() {
        // Version byte 16 should produce addresses starting with '7'
        let hash = [0u8; 20];
        let addr = base58check_encode(16, &hash);
        assert!(addr.starts_with('7'), "Expected 7 prefix, got: {}", addr);
    }

    // -- Varint tests --

    #[test]
    fn varint_single_byte() {
        for val in [0u64, 1, 127, 252] {
            let mut buf = Vec::new();
            write_varint(&mut buf, val);
            assert_eq!(buf.len(), 1);
            let mut offset = 0;
            assert_eq!(read_varint(&buf, &mut offset).unwrap(), val);
            assert_eq!(offset, 1);
        }
    }

    #[test]
    fn varint_two_byte() {
        for val in [253u64, 254, 1000, 0xFFFF] {
            let mut buf = Vec::new();
            write_varint(&mut buf, val);
            assert_eq!(buf.len(), 3);
            assert_eq!(buf[0], 0xfd);
            let mut offset = 0;
            assert_eq!(read_varint(&buf, &mut offset).unwrap(), val);
            assert_eq!(offset, 3);
        }
    }

    #[test]
    fn varint_four_byte() {
        for val in [0x10000u64, 0xFFFF_FFFF] {
            let mut buf = Vec::new();
            write_varint(&mut buf, val);
            assert_eq!(buf.len(), 5);
            assert_eq!(buf[0], 0xfe);
            let mut offset = 0;
            assert_eq!(read_varint(&buf, &mut offset).unwrap(), val);
            assert_eq!(offset, 5);
        }
    }

    #[test]
    fn varint_eight_byte() {
        let val = 0x1_0000_0000u64;
        let mut buf = Vec::new();
        write_varint(&mut buf, val);
        assert_eq!(buf.len(), 9);
        assert_eq!(buf[0], 0xff);
        let mut offset = 0;
        assert_eq!(read_varint(&buf, &mut offset).unwrap(), val);
        assert_eq!(offset, 9);
    }

    #[test]
    fn varint_read_truncated() {
        let buf = vec![0xfd, 0x01]; // Missing second byte
        let mut offset = 0;
        assert!(read_varint(&buf, &mut offset).is_err());
    }

    #[test]
    fn varint_read_empty() {
        let buf = vec![];
        let mut offset = 0;
        assert!(read_varint(&buf, &mut offset).is_err());
    }

    // -- sha256d tests --

    #[test]
    fn sha256d_empty() {
        // SHA256(SHA256("")) is a well-known value
        let result = sha256d(&[]);
        assert_eq!(
            hex_encode(&result),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }

    #[test]
    fn sha256d_known() {
        // SHA256d("hello") — verifiable with external tools
        let result = sha256d(b"hello");
        let hex = hex_encode(&result);
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
        // Cross-check: known SHA256d of "hello"
        assert_eq!(hex, "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50");
    }
}
