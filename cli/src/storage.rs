/// Filesystem persistence and device-bound encryption for the CLI.
///
/// Uses the SDK's `wallet::encrypt_wallet` / `decrypt_wallet` with a
/// device-specific key derived from machine ID + data directory.
use sha2::{Sha256, Digest};
use std::fs;
use std::path::PathBuf;

use kerrigan_sdk::params;
use kerrigan_sdk::wallet::{self, WalletData, WalletError};

// ---------------------------------------------------------------------------
// Device key derivation
// ---------------------------------------------------------------------------

/// Derive a device-specific encryption key.
fn device_key() -> Result<[u8; 32], WalletError> {
    let machine_id = machine_uid::get()
        .map_err(|_| WalletError::Other("Failed to read machine ID".into()))?;
    let mut hasher = Sha256::new();
    hasher.update(machine_id.as_bytes());
    hasher.update(get_data_dir().to_string_lossy().as_bytes());
    hasher.update(params::DEVICE_ENCRYPTION_SALT);
    Ok(hasher.finalize().into())
}

// ---------------------------------------------------------------------------
// Data directory
// ---------------------------------------------------------------------------

/// Get the wallet data directory.
pub fn get_data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(params::DATA_DIR_NAME)
}

fn wallet_path() -> PathBuf {
    get_data_dir().join("wallet.json")
}

/// Check if a wallet file exists on disk.
pub fn wallet_exists() -> bool {
    wallet_path().exists()
}

// ---------------------------------------------------------------------------
// Create / Import
// ---------------------------------------------------------------------------

/// Create a new wallet and save to disk.
pub fn create_wallet() -> Result<WalletData, WalletError> {
    if wallet_exists() {
        return Err(WalletError::Other("Wallet already exists. Delete it first to create a new one.".into()));
    }
    let data = wallet::create_wallet_data()?;
    save_wallet(&data)?;
    Ok(data)
}

/// Import a wallet from mnemonic and save to disk.
pub fn import_wallet(mnemonic: &str) -> Result<WalletData, WalletError> {
    if wallet_exists() {
        return Err(WalletError::Other("Wallet already exists. Delete it first to import.".into()));
    }
    let data = wallet::import_wallet_data(mnemonic)?;
    save_wallet(&data)?;
    Ok(data)
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Save wallet data to disk atomically with device encryption.
pub fn save_wallet(data: &WalletData) -> Result<(), WalletError> {
    let dir = get_data_dir();
    fs::create_dir_all(&dir)
        .map_err(|e| WalletError::Other(format!("I/O error: {e}")))?;

    let key = device_key()?;
    let encrypted = wallet::encrypt_wallet(data, &key);
    let json = serde_json::to_string_pretty(&encrypted)
        .map_err(|e| WalletError::Other(format!("Serialization error: {e}")))?;

    let path = wallet_path();
    let tmp_path = path.with_extension("json.tmp");

    fs::write(&tmp_path, &json)
        .map_err(|e| WalletError::Other(format!("I/O error: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
    }

    fs::rename(&tmp_path, &path)
        .map_err(|e| WalletError::Other(format!("I/O error: {e}")))?;

    Ok(())
}

/// Load and decrypt the wallet from disk.
///
/// Automatically upgrades old wallets by deriving Sapling shielded keys
/// from the existing seed (if not already present).
pub fn load_wallet() -> Result<WalletData, WalletError> {
    let path = wallet_path();
    if !path.exists() {
        return Err(WalletError::Other("No wallet found. Run 'create' or 'import' first.".into()));
    }

    let json = fs::read_to_string(&path)
        .map_err(|e| WalletError::Other(format!("I/O error: {e}")))?;
    let data: WalletData = serde_json::from_str(&json)
        .map_err(|e| WalletError::Other(format!("Corrupt wallet file: {e}")))?;

    let key = device_key()?;
    let mut data = wallet::decrypt_wallet(data, &key)?;

    // Auto-migrate: derive Sapling keys if missing (pre-shield wallet)
    if data.sapling_address.is_none() {
        migrate_add_sapling_keys(&mut data)?;
        save_wallet(&data)?;
    }

    Ok(data)
}

/// Derive Sapling shielded keys from the existing BIP39 seed.
fn migrate_add_sapling_keys(data: &mut WalletData) -> Result<(), WalletError> {
    use kerrigan_sdk::sapling::keys;

    let extsk = keys::default_spending_key(&data.seed)
        .map_err(|e| WalletError::Other(format!("sapling key derivation: {e}")))?;
    let extfvk = keys::full_viewing_key(&extsk);
    let addr = keys::default_payment_address(&extfvk);

    data.sapling_extsk = Some(keys::encode_extsk(&extsk));
    data.sapling_extfvk = Some(keys::encode_extfvk(&extfvk));
    data.sapling_address = Some(keys::encode_payment_address(&addr));

    Ok(())
}
