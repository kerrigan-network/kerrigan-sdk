/// Sapling proving parameter management — download, cache, and load.
///
/// The parameters are ~50MB total (output: ~3.5MB, spend: ~47MB).
/// Downloaded on first use and cached in the wallet data directory.
use std::fs;
use std::io::Read;
use std::path::PathBuf;

use kerrigan_sdk::params;
use kerrigan_sdk::sapling::prover::{self, SaplingProver};
use kerrigan_sdk::wallet::WalletError;

const OUTPUT_FILENAME: &str = "sapling-output.params";
const SPEND_FILENAME: &str = "sapling-spend.params";

/// Ensure Sapling parameters are available, downloading if needed.
///
/// Returns the loaded prover ready for transaction building.
pub fn ensure_params(on_progress: impl Fn(&str)) -> Result<SaplingProver, WalletError> {
    let dir = params_dir()?;
    fs::create_dir_all(&dir)
        .map_err(|e| WalletError::Other(format!("create params dir: {e}")))?;

    let output_path = dir.join(OUTPUT_FILENAME);
    let spend_path = dir.join(SPEND_FILENAME);

    // Download if either file is missing
    if !output_path.exists() || !spend_path.exists() {
        on_progress("Downloading Sapling parameters (first time only, ~50MB)...");

        if !output_path.exists() {
            on_progress("  Downloading sapling-output.params...");
            let bytes = download(params::SAPLING_OUTPUT_PARAMS_URL)?;
            fs::write(&output_path, &bytes)
                .map_err(|e| WalletError::Other(format!("write output params: {e}")))?;
        }

        if !spend_path.exists() {
            on_progress("  Downloading sapling-spend.params...");
            let bytes = download(params::SAPLING_SPEND_PARAMS_URL)?;
            fs::write(&spend_path, &bytes)
                .map_err(|e| WalletError::Other(format!("write spend params: {e}")))?;
        }
    }

    // Load and verify
    on_progress("Loading Sapling parameters...");
    let output_bytes = fs::read(&output_path)
        .map_err(|e| WalletError::Other(format!("read output params: {e}")))?;
    let spend_bytes = fs::read(&spend_path)
        .map_err(|e| WalletError::Other(format!("read spend params: {e}")))?;

    prover::verify_and_load_params(&output_bytes, &spend_bytes)
        .map_err(|e| {
            // If verification fails, delete corrupted files
            let _ = fs::remove_file(&output_path);
            let _ = fs::remove_file(&spend_path);
            WalletError::Other(format!("Sapling params corrupted (deleted, retry): {e}"))
        })
}

/// Get the params cache directory.
fn params_dir() -> Result<PathBuf, WalletError> {
    let dir = dirs::data_dir()
        .ok_or(WalletError::Other("cannot determine data directory".into()))?
        .join(params::DATA_DIR_NAME)
        .join("params");
    Ok(dir)
}

/// Download a file from URL, returning the bytes.
fn download(url: &str) -> Result<Vec<u8>, WalletError> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(300)) // 5 min for large files
        .build();

    let resp = agent
        .get(url)
        .call()
        .map_err(|e| WalletError::Other(format!("download failed: {e}")))?;

    let mut bytes = Vec::new();
    resp.into_reader()
        .read_to_end(&mut bytes)
        .map_err(|e| WalletError::Other(format!("reading download: {e}")))?;

    Ok(bytes)
}
