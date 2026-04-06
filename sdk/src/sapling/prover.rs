/// Sapling proving parameter types and verification.
///
/// The SDK defines the types and expected SHA-256 hashes for the Sapling
/// parameters. The caller is responsible for loading the actual files
/// (from disk, network, etc.) — the SDK never touches I/O.
///
/// Parameter files are the standard Zcash Sapling params (~50 MB total).
use sapling::circuit::{OutputParameters, SpendParameters};
use sha2::{Digest, Sha256};

use crate::encoding;

// ---------------------------------------------------------------------------
// Type alias
// ---------------------------------------------------------------------------

/// Loaded Sapling proving parameters: (output_params, spend_params).
pub type SaplingProver = (OutputParameters, SpendParameters);

// ---------------------------------------------------------------------------
// SHA-256 hashes for parameter verification
// ---------------------------------------------------------------------------

/// Expected SHA-256 hash of `sapling-output.params`.
pub const OUTPUT_PARAMS_SHA256: &str =
    "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4";

/// Expected SHA-256 hash of `sapling-spend.params`.
pub const SPEND_PARAMS_SHA256: &str =
    "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13";

// ---------------------------------------------------------------------------
// Verification + loading
// ---------------------------------------------------------------------------

/// Verify raw parameter bytes against expected SHA-256 hashes, then parse.
///
/// Returns the loaded prover parameters ready for transaction building.
///
/// # Errors
///
/// Returns an error if SHA-256 doesn't match or if the parameter files
/// can't be parsed (corrupted download, wrong format, etc.).
pub fn verify_and_load_params(
    output_bytes: &[u8],
    spend_bytes: &[u8],
) -> Result<SaplingProver, SaplingProverError> {
    // Verify output params
    let output_hash = sha256_hex(output_bytes);
    if output_hash != OUTPUT_PARAMS_SHA256 {
        return Err(SaplingProverError::HashMismatch {
            param: "sapling-output.params",
            expected: OUTPUT_PARAMS_SHA256.to_string(),
            actual: output_hash,
        });
    }

    // Verify spend params
    let spend_hash = sha256_hex(spend_bytes);
    if spend_hash != SPEND_PARAMS_SHA256 {
        return Err(SaplingProverError::HashMismatch {
            param: "sapling-spend.params",
            expected: SPEND_PARAMS_SHA256.to_string(),
            actual: spend_hash,
        });
    }

    // Parse parameters
    let output_params = OutputParameters::read(output_bytes, false)
        .map_err(|e| SaplingProverError::Parse(format!("output params: {e}")))?;
    let spend_params = SpendParameters::read(spend_bytes, false)
        .map_err(|e| SaplingProverError::Parse(format!("spend params: {e}")))?;

    Ok((output_params, spend_params))
}

/// Compute SHA-256 hex digest of raw bytes.
fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    encoding::hex_encode(&hash)
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum SaplingProverError {
    HashMismatch {
        param: &'static str,
        expected: String,
        actual: String,
    },
    Parse(String),
}

impl std::fmt::Display for SaplingProverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HashMismatch { param, expected, actual } => {
                write!(f, "SHA-256 mismatch for {param}: expected {expected}, got {actual}")
            }
            Self::Parse(e) => write!(f, "parameter parse error: {e}"),
        }
    }
}

impl std::error::Error for SaplingProverError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = sha256_hex(b"");
        assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn verify_params_rejects_wrong_hash() {
        let result = verify_and_load_params(b"fake output data", b"fake spend data");
        match result {
            Err(SaplingProverError::HashMismatch { param, .. }) => {
                assert_eq!(param, "sapling-output.params");
            }
            Err(e) => panic!("Expected HashMismatch, got: {e}"),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    #[test]
    fn hash_constants_are_valid_hex() {
        assert_eq!(OUTPUT_PARAMS_SHA256.len(), 64);
        assert_eq!(SPEND_PARAMS_SHA256.len(), 64);
        assert!(encoding::hex_decode(OUTPUT_PARAMS_SHA256).is_ok());
        assert!(encoding::hex_decode(SPEND_PARAMS_SHA256).is_ok());
    }
}
