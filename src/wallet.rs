/// Wallet state management, device-bound encryption, and persistence.
///
/// # Security model
///
/// The wallet file stores the BIP39 mnemonic and seed encrypted with a
/// **device-bound key** derived from:
///
/// ```text
/// SHA256(machine_uid || data_dir_path || "kerrigan-wallet-device-encryption")
/// ```
///
/// This means the wallet file is useless on any other machine. The encryption
/// uses a SHA256-CTR stream cipher (same pattern as the PIVX agent kit).
///
/// # Persistence
///
/// The wallet is stored as JSON at `<data_dir>/kerrigan-wallet/wallet.json`.
/// Writes use atomic rename (write to `.tmp`, then rename) and Unix 0o600
/// permissions.

use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use crate::bip39;
use crate::encoding::{hex_encode, hex_decode};
use crate::keys;
use crate::network::ExplorerClient;
use crate::params;
use crate::sync;
use crate::transaction::{self, Utxo, SignedTransaction};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum WalletError {
    NotFound,
    AlreadyExists,
    DecryptionFailed,
    InvalidMnemonic(String),
    Io(String),
    Sync(String),
    Transaction(String),
    Other(String),
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "No wallet found. Run 'create' or 'import' first."),
            Self::AlreadyExists => write!(f, "Wallet already exists. Delete it first to create a new one."),
            Self::DecryptionFailed => write!(f, "Failed to decrypt wallet — wrong device or corrupted file."),
            Self::InvalidMnemonic(s) => write!(f, "Invalid mnemonic: {s}"),
            Self::Io(s) => write!(f, "I/O error: {s}"),
            Self::Sync(s) => write!(f, "Sync error: {s}"),
            Self::Transaction(s) => write!(f, "Transaction error: {s}"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for WalletError {}

// ---------------------------------------------------------------------------
// Wallet data (persisted to disk)
// ---------------------------------------------------------------------------

/// Persistent wallet state.
///
/// Sensitive fields (`seed`, `mnemonic`) are device-encrypted on disk.
/// Non-sensitive fields are stored in plaintext for easy inspection.
#[derive(Serialize, Deserialize, Clone)]
pub struct WalletData {
    /// Schema version (for future migrations).
    pub version: u32,

    /// 64-byte BIP39 seed (device-encrypted on disk).
    #[serde(with = "hex_bytes")]
    seed: Vec<u8>,

    /// BIP39 mnemonic phrase (device-encrypted on disk as hex).
    mnemonic: String,

    /// The wallet's primary receiving address (derived from seed).
    /// Used for decryption validation — if re-derivation doesn't match, decryption failed.
    pub address: String,

    /// Unspent transparent outputs.
    pub utxos: Vec<Utxo>,

    /// Transaction IDs already processed by sync (for incremental sync).
    pub processed_txids: HashSet<String>,

    /// Persisted sync state (potential UTXOs + spent outpoints).
    /// Enables true incremental sync — only new txids are fetched.
    #[serde(default)]
    pub sync_state: Option<sync::SyncState>,

    /// Transaction history entries (newest first).
    #[serde(default)]
    pub history: Vec<sync::TxHistoryEntry>,

    /// Last known block height at sync time.
    pub last_sync_height: u64,
}

/// Serde helper: serialize Vec<u8> as hex string.
mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use crate::encoding::{hex_encode, hex_decode};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(&hex_encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        hex_decode(&s).map_err(serde::de::Error::custom)
    }
}

impl WalletData {
    /// Get the mnemonic phrase (for export).
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// Get the 64-byte seed.
    pub fn seed(&self) -> &[u8] {
        &self.seed
    }

    /// Get the total balance in satoshis (saturating — never wraps).
    pub fn balance(&self) -> u64 {
        self.utxos.iter().fold(0u64, |acc, u| acc.saturating_add(u.amount))
    }

    /// Get the balance formatted as KRGN string (e.g., "1.50000000").
    pub fn balance_display(&self) -> String {
        format_krgn(self.balance())
    }

    /// Derive the keypair from the stored seed.
    pub fn derive_keypair(&self) -> Result<keys::Keypair, Box<dyn Error>> {
        keys::derive_keypair(&self.seed).map_err(|e| e.into())
    }

    /// Remove spent UTXOs after a send.
    pub fn finalize_send(&mut self, spent: &[(String, u32)]) {
        self.utxos.retain(|u| {
            !spent.iter().any(|(txid, vout)| u.txid == *txid && u.vout == *vout)
        });
    }
}

// ---------------------------------------------------------------------------
// Device-bound encryption
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

/// SHA256-CTR stream cipher. Symmetric — same function encrypts and decrypts.
/// Keystream blocks are zeroized after use to minimize secret residue in memory.
fn device_crypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    use zeroize::Zeroize;
    let mut result = Vec::with_capacity(data.len());
    let mut offset = 0;
    let mut counter = 0u64;

    while offset < data.len() {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(&counter.to_le_bytes());
        let mut block: [u8; 32] = hasher.finalize().into();

        let chunk_len = (data.len() - offset).min(32);
        for i in 0..chunk_len {
            result.push(data[offset + i] ^ block[i]);
        }
        block.zeroize();
        offset += chunk_len;
        counter += 1;
    }
    result
}

/// Encrypt seed and mnemonic in a WalletData clone for disk storage.
fn encrypt_for_disk(data: &WalletData) -> Result<WalletData, WalletError> {
    let key = device_key()?;

    let encrypted_seed = device_crypt(&data.seed, &key);
    let encrypted_mnemonic = device_crypt(data.mnemonic.as_bytes(), &key);

    Ok(WalletData {
        version: data.version,
        seed: encrypted_seed,
        mnemonic: hex_encode(&encrypted_mnemonic),
        address: data.address.clone(),
        utxos: data.utxos.clone(),
        processed_txids: data.processed_txids.clone(),
        sync_state: data.sync_state.clone(),
        history: data.history.clone(),
        last_sync_height: data.last_sync_height,
    })
}

/// Decrypt seed and mnemonic after loading from disk.
fn decrypt_from_disk(mut data: WalletData) -> Result<WalletData, WalletError> {
    let key = device_key()?;

    // Decrypt seed
    let decrypted_seed = device_crypt(&data.seed, &key);
    data.seed = decrypted_seed;

    // Decrypt mnemonic (stored as hex-encoded encrypted bytes)
    let encrypted_bytes = hex_decode(&data.mnemonic)
        .map_err(|_| WalletError::DecryptionFailed)?;
    let decrypted_bytes = device_crypt(&encrypted_bytes, &key);
    data.mnemonic = String::from_utf8(decrypted_bytes)
        .map_err(|_| WalletError::DecryptionFailed)?;

    // Validate decryption: re-derive the address and compare
    let kp = keys::derive_keypair(&data.seed)
        .map_err(|_| WalletError::DecryptionFailed)?;
    if kp.address != data.address {
        return Err(WalletError::DecryptionFailed);
    }

    Ok(data)
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

/// Create a brand-new wallet with a fresh 24-word mnemonic.
///
/// Returns the wallet data (with the mnemonic for display) and saves to disk.
pub fn create_wallet() -> Result<WalletData, WalletError> {
    if wallet_exists() {
        return Err(WalletError::AlreadyExists);
    }

    let mnemonic = bip39::generate_mnemonic()
        .map_err(|e| WalletError::Other(e.to_string()))?;

    let wallet = wallet_from_mnemonic(&mnemonic)?;
    save_wallet(&wallet)?;
    Ok(wallet)
}

/// Import a wallet from an existing BIP39 mnemonic phrase.
pub fn import_wallet(mnemonic: &str) -> Result<WalletData, WalletError> {
    if wallet_exists() {
        return Err(WalletError::AlreadyExists);
    }

    bip39::validate_mnemonic(mnemonic)
        .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;

    let wallet = wallet_from_mnemonic(mnemonic)?;
    save_wallet(&wallet)?;
    Ok(wallet)
}

/// Internal: build a WalletData from a mnemonic string.
fn wallet_from_mnemonic(mnemonic: &str) -> Result<WalletData, WalletError> {
    let seed = bip39::mnemonic_to_seed(mnemonic, "");
    let kp = keys::derive_keypair(&seed)
        .map_err(|e| WalletError::Other(e.to_string()))?;

    Ok(WalletData {
        version: params::WALLET_VERSION,
        seed,
        mnemonic: mnemonic.to_string(),
        address: kp.address,
        utxos: Vec::new(),
        processed_txids: HashSet::new(),
        sync_state: None,
        history: Vec::new(),
        last_sync_height: 0,
    })
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Save wallet data to disk atomically.
pub fn save_wallet(data: &WalletData) -> Result<(), WalletError> {
    let dir = get_data_dir();
    fs::create_dir_all(&dir)
        .map_err(|e| WalletError::Io(e.to_string()))?;

    let encrypted = encrypt_for_disk(data)?;
    let json = serde_json::to_string_pretty(&encrypted)
        .map_err(|e| WalletError::Io(e.to_string()))?;

    let path = wallet_path();
    let tmp_path = path.with_extension("json.tmp");

    fs::write(&tmp_path, &json)
        .map_err(|e| WalletError::Io(e.to_string()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
    }

    fs::rename(&tmp_path, &path)
        .map_err(|e| WalletError::Io(e.to_string()))?;

    Ok(())
}

/// Load and decrypt the wallet from disk.
pub fn load_wallet() -> Result<WalletData, WalletError> {
    let path = wallet_path();
    if !path.exists() {
        return Err(WalletError::NotFound);
    }

    let json = fs::read_to_string(&path)
        .map_err(|e| WalletError::Io(e.to_string()))?;
    let data: WalletData = serde_json::from_str(&json)
        .map_err(|e| WalletError::Io(format!("corrupt wallet file: {e}")))?;

    decrypt_from_disk(data)
}

// ---------------------------------------------------------------------------
// Sync orchestration
// ---------------------------------------------------------------------------

/// Sync the wallet's UTXO set from the explorer.
pub fn sync_wallet(wallet: &mut WalletData) -> Result<sync::SyncResult, WalletError> {
    sync_wallet_with_progress(wallet, |_, _| {})
}

/// Sync with a progress callback: `on_progress(completed, total)`.
///
/// Two-layer cache:
/// 1. **Fast path**: if block height hasn't changed since last sync, return cached data instantly.
/// 2. **Incremental**: if new blocks exist, fetch address info. If no new txids, return cached.
///    If new txids, fetch only *those* and merge into persisted SyncState.
pub fn sync_wallet_with_progress(
    wallet: &mut WalletData,
    on_progress: impl Fn(usize, usize),
) -> Result<sync::SyncResult, WalletError> {
    let client = ExplorerClient::new();

    // --- Fast path: check block height ---
    let current_height = client.get_block_height()
        .map_err(|e| WalletError::Sync(e.to_string()))?;

    if wallet.last_sync_height > 0 && current_height == wallet.last_sync_height {
        if let Some(state) = &wallet.sync_state {
            // No new blocks — return cached state
            let utxos = state.derive_utxos();
            let balance = utxos.iter().fold(0u64, |a, u| a.saturating_add(u.amount));
            return Ok(sync::SyncResult {
                utxos,
                balance,
                new_tx_count: 0,
                processed_txids: state.processed_txids.clone(),
                history: wallet.history.clone(),
                state: state.clone(),
                was_cached: true,
            });
        }
    }

    // --- Incremental sync: pass persisted state ---
    let result = sync::sync_incremental(
        &client,
        &wallet.address,
        wallet.sync_state.take(),
        &wallet.history,
        on_progress,
    ).map_err(|e| WalletError::Sync(e.to_string()))?;

    // Persist everything
    wallet.utxos = result.utxos.clone();
    wallet.processed_txids = result.processed_txids.clone();
    wallet.sync_state = Some(result.state.clone());
    wallet.history = result.history.clone();
    wallet.last_sync_height = current_height;

    Ok(result)
}

// ---------------------------------------------------------------------------
// Send orchestration
// ---------------------------------------------------------------------------

/// Build and sign a send transaction.
///
/// Does NOT broadcast — returns the signed tx for the caller to confirm and broadcast.
pub fn prepare_send(
    wallet: &WalletData,
    to_address: &str,
    amount: u64,
) -> Result<SignedTransaction, WalletError> {
    let kp = wallet.derive_keypair()
        .map_err(|e| WalletError::Other(e.to_string()))?;

    transaction::build_transaction(
        &wallet.utxos,
        to_address,
        amount,
        &kp.privkey,
        &kp.pubkey,
        &wallet.address,
    ).map_err(|e| WalletError::Transaction(e.to_string()))
}

/// Broadcast a signed transaction and update the wallet's UTXO set.
pub fn broadcast_and_finalize(
    wallet: &mut WalletData,
    signed: &SignedTransaction,
) -> Result<String, WalletError> {
    let client = ExplorerClient::new();
    let txid = client.broadcast(&signed.tx_hex)
        .map_err(|e| WalletError::Transaction(e.to_string()))?;

    wallet.finalize_send(&signed.spent_utxos);
    save_wallet(wallet)?;

    Ok(txid)
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

/// Format a satoshi amount as a KRGN string (e.g., 150000000 → "1.50000000").
pub fn format_krgn(satoshis: u64) -> String {
    let whole = satoshis / params::COIN;
    let frac = satoshis % params::COIN;
    format!("{whole}.{frac:08}")
}

/// Parse a KRGN string to satoshis (e.g., "1.5" → 150000000).
pub fn parse_krgn(s: &str) -> Result<u64, WalletError> {
    let s = s.trim();

    if let Some(dot_pos) = s.find('.') {
        let whole: u64 = s[..dot_pos].parse()
            .map_err(|_| WalletError::Other(format!("Invalid amount: {s}")))?;
        let frac_str = &s[dot_pos + 1..];
        if frac_str.len() > 8 {
            return Err(WalletError::Other(format!("Too many decimal places: {s}")));
        }
        let padded = format!("{:0<8}", frac_str);
        let frac: u64 = padded.parse()
            .map_err(|_| WalletError::Other(format!("Invalid amount: {s}")))?;
        Ok(whole * params::COIN + frac)
    } else {
        let whole: u64 = s.parse()
            .map_err(|_| WalletError::Other(format!("Invalid amount: {s}")))?;
        Ok(whole * params::COIN)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- device_crypt symmetry --

    #[test]
    fn crypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, Kerrigan Network! This is a longer message to test multi-block.";
        let ciphertext = device_crypt(plaintext, &key);
        assert_ne!(&ciphertext, plaintext);
        let decrypted = device_crypt(&ciphertext, &key);
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn crypt_empty() {
        let key = [0x01u8; 32];
        let ciphertext = device_crypt(b"", &key);
        assert!(ciphertext.is_empty());
        let decrypted = device_crypt(&ciphertext, &key);
        assert!(decrypted.is_empty());
    }

    #[test]
    fn crypt_single_byte() {
        let key = [0xAA; 32];
        let plaintext = &[0x42u8];
        let ct = device_crypt(plaintext, &key);
        assert_eq!(ct.len(), 1);
        assert_ne!(ct[0], 0x42);
        let pt = device_crypt(&ct, &key);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn crypt_exact_block_boundary() {
        let key = [0xBB; 32];
        let plaintext = vec![0xCC; 32]; // exactly 1 block
        let ct = device_crypt(&plaintext, &key);
        assert_ne!(ct, plaintext);
        let pt = device_crypt(&ct, &key);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn crypt_multi_block() {
        let key = [0xDD; 32];
        let plaintext = vec![0xEE; 100]; // 3+ blocks
        let ct = device_crypt(&plaintext, &key);
        assert_eq!(ct.len(), 100);
        let pt = device_crypt(&ct, &key);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn crypt_different_keys() {
        let key1 = [0x01; 32];
        let key2 = [0x02; 32];
        let plaintext = b"same message";
        let ct1 = device_crypt(plaintext, &key1);
        let ct2 = device_crypt(plaintext, &key2);
        assert_ne!(ct1, ct2, "Different keys should produce different ciphertext");
    }

    // -- wallet_from_mnemonic --

    #[test]
    fn wallet_from_known_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = wallet_from_mnemonic(mnemonic).unwrap();

        assert_eq!(wallet.version, params::WALLET_VERSION);
        assert_eq!(wallet.seed.len(), 64);
        assert!(wallet.address.starts_with('K'));
        assert_eq!(wallet.mnemonic, mnemonic);
        assert!(wallet.utxos.is_empty());
        assert!(wallet.processed_txids.is_empty());
    }

    #[test]
    fn wallet_deterministic() {
        let mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
        let w1 = wallet_from_mnemonic(mnemonic).unwrap();
        let w2 = wallet_from_mnemonic(mnemonic).unwrap();
        assert_eq!(w1.address, w2.address);
        assert_eq!(w1.seed, w2.seed);
    }

    #[test]
    fn wallet_different_mnemonics() {
        let w1 = wallet_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        let w2 = wallet_from_mnemonic(
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        ).unwrap();
        assert_ne!(w1.address, w2.address);
    }

    // -- encrypt/decrypt roundtrip (uses device_key) --

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let original = wallet_from_mnemonic(mnemonic).unwrap();

        let encrypted = encrypt_for_disk(&original).unwrap();
        // Encrypted mnemonic should differ from original
        assert_ne!(encrypted.mnemonic, original.mnemonic);
        // Encrypted seed should differ from original
        assert_ne!(encrypted.seed, original.seed);
        // Address (not encrypted) should match
        assert_eq!(encrypted.address, original.address);

        let decrypted = decrypt_from_disk(encrypted).unwrap();
        assert_eq!(decrypted.mnemonic, original.mnemonic);
        assert_eq!(decrypted.seed, original.seed);
        assert_eq!(decrypted.address, original.address);
    }

    #[test]
    fn decrypt_wrong_data_fails() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let original = wallet_from_mnemonic(mnemonic).unwrap();
        let mut encrypted = encrypt_for_disk(&original).unwrap();

        // Corrupt the encrypted seed
        encrypted.seed[0] ^= 0xFF;

        // Decryption should fail (address validation won't match)
        assert!(decrypt_from_disk(encrypted).is_err());
    }

    // -- format_krgn --

    #[test]
    fn format_krgn_basic() {
        assert_eq!(format_krgn(0), "0.00000000");
        assert_eq!(format_krgn(1), "0.00000001");
        assert_eq!(format_krgn(100_000_000), "1.00000000");
        assert_eq!(format_krgn(150_000_000), "1.50000000");
        assert_eq!(format_krgn(123_456_789), "1.23456789");
        assert_eq!(format_krgn(10_000_000_000), "100.00000000");
    }

    // -- parse_krgn --

    #[test]
    fn parse_krgn_whole() {
        assert_eq!(parse_krgn("1").unwrap(), 100_000_000);
        assert_eq!(parse_krgn("0").unwrap(), 0);
        assert_eq!(parse_krgn("100").unwrap(), 10_000_000_000);
    }

    #[test]
    fn parse_krgn_fractional() {
        assert_eq!(parse_krgn("1.5").unwrap(), 150_000_000);
        assert_eq!(parse_krgn("0.00000001").unwrap(), 1);
        assert_eq!(parse_krgn("1.23456789").unwrap(), 123_456_789);
    }

    #[test]
    fn parse_krgn_roundtrip() {
        for sat in [0u64, 1, 100_000_000, 150_000_000, 123_456_789, 10_000_000_000] {
            let formatted = format_krgn(sat);
            let parsed = parse_krgn(&formatted).unwrap();
            assert_eq!(parsed, sat, "Roundtrip failed for {sat}");
        }
    }

    #[test]
    fn parse_krgn_invalid() {
        assert!(parse_krgn("abc").is_err());
        assert!(parse_krgn("1.123456789").is_err()); // 9 decimals
        assert!(parse_krgn("").is_err());
    }

    // -- balance --

    #[test]
    fn balance_sum() {
        let mut wallet = wallet_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        wallet.utxos = vec![
            Utxo { txid: "a".into(), vout: 0, amount: 100_000_000, script_pubkey: "s".into() },
            Utxo { txid: "b".into(), vout: 0, amount: 50_000_000, script_pubkey: "s".into() },
        ];
        assert_eq!(wallet.balance(), 150_000_000);
        assert_eq!(wallet.balance_display(), "1.50000000");
    }

    // -- finalize_send --

    #[test]
    fn finalize_send_removes_spent() {
        let mut wallet = wallet_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        wallet.utxos = vec![
            Utxo { txid: "aa".into(), vout: 0, amount: 100, script_pubkey: "s".into() },
            Utxo { txid: "bb".into(), vout: 1, amount: 200, script_pubkey: "s".into() },
            Utxo { txid: "cc".into(), vout: 0, amount: 300, script_pubkey: "s".into() },
        ];

        wallet.finalize_send(&[("aa".into(), 0), ("cc".into(), 0)]);
        assert_eq!(wallet.utxos.len(), 1);
        assert_eq!(wallet.utxos[0].txid, "bb");
    }

    // -- data dir --

    #[test]
    fn data_dir_contains_name() {
        let dir = get_data_dir();
        assert!(
            dir.to_string_lossy().contains(params::DATA_DIR_NAME),
            "Data dir should contain '{}': {:?}",
            params::DATA_DIR_NAME,
            dir
        );
    }

    // -- parse_krgn edge cases --

    #[test]
    fn parse_krgn_whitespace() {
        assert_eq!(parse_krgn("  1.5  ").unwrap(), 150_000_000);
        assert_eq!(parse_krgn("\t0.001\n").unwrap(), 100_000);
    }

    #[test]
    fn parse_krgn_negative_rejected() {
        assert!(parse_krgn("-1").is_err());
        assert!(parse_krgn("-0.5").is_err());
    }

    #[test]
    fn parse_krgn_large_value() {
        // 21 million KRGN (Bitcoin-scale supply)
        assert_eq!(parse_krgn("21000000").unwrap(), 2_100_000_000_000_000);
    }

    #[test]
    fn parse_krgn_just_dot() {
        assert!(parse_krgn(".").is_err());
        assert!(parse_krgn(".5").is_err()); // no leading zero
    }

    #[test]
    fn parse_krgn_trailing_dot() {
        // "1." should parse as 1.00000000
        assert_eq!(parse_krgn("1.").unwrap(), 100_000_000);
    }

    // -- balance saturation --

    #[test]
    fn balance_saturates() {
        let mut wallet = wallet_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        wallet.utxos = vec![
            Utxo { txid: "a".into(), vout: 0, amount: u64::MAX, script_pubkey: "s".into() },
            Utxo { txid: "b".into(), vout: 0, amount: 1, script_pubkey: "s".into() },
        ];
        assert_eq!(wallet.balance(), u64::MAX, "Balance should saturate, not wrap");
    }

    // -- format_krgn large values --

    #[test]
    fn format_krgn_u64_max() {
        // Should not panic
        let s = format_krgn(u64::MAX);
        assert!(s.contains('.'));
    }
}
