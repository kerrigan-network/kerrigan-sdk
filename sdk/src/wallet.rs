/// Wallet state management — pure logic, no I/O.
///
/// This module handles:
/// - Wallet creation from mnemonic
/// - Keypair derivation
/// - Balance calculation
/// - Send preparation (transaction building + signing)
/// - Device-bound encryption (symmetric cipher, caller provides key)
///
/// Persistence (filesystem, IndexedDB, etc.) is the caller's responsibility.
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::collections::HashSet;
use std::fmt;
use zeroize::Zeroize;

use crate::bip39;
use crate::encoding::{hex_encode, hex_decode};
use crate::keys;
use crate::params;
use crate::sapling;
use crate::sapling::notes::SerializedNote;
use crate::sync;
use crate::transaction::{self, Utxo, SignedTransaction};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum WalletError {
    InvalidMnemonic(String),
    Transaction(String),
    Encryption(String),
    Other(String),
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMnemonic(s) => write!(f, "Invalid mnemonic: {s}"),
            Self::Transaction(s) => write!(f, "Transaction error: {s}"),
            Self::Encryption(s) => write!(f, "Encryption error: {s}"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for WalletError {}

// ---------------------------------------------------------------------------
// Wallet data
// ---------------------------------------------------------------------------

/// Persistent wallet state.
///
/// This struct is fully serializable. The caller is responsible for
/// encrypting sensitive fields (`seed`, `mnemonic`) before persisting
/// and decrypting after loading.
#[derive(Serialize, Deserialize, Clone)]
pub struct WalletData {
    /// Schema version (for future migrations).
    pub version: u32,

    /// 64-byte BIP39 seed (should be encrypted before persisting).
    #[serde(with = "hex_bytes")]
    pub seed: Vec<u8>,

    /// BIP39 mnemonic phrase (should be encrypted before persisting).
    pub mnemonic: String,

    /// The wallet's primary receiving address.
    pub address: String,

    /// Unspent transparent outputs.
    pub utxos: Vec<Utxo>,

    /// Processed transaction IDs (for incremental sync).
    pub processed_txids: HashSet<String>,

    /// Persisted sync state (for incremental sync).
    #[serde(default)]
    pub sync_state: Option<sync::SyncState>,

    /// Transaction history (newest first).
    #[serde(default)]
    pub history: Vec<sync::TxHistoryEntry>,

    /// Last known block height at sync time.
    pub last_sync_height: u64,

    // -- Sapling shielded state --

    /// Encoded Sapling extended spending key (bech32).
    #[serde(default)]
    pub sapling_extsk: Option<String>,

    /// Encoded Sapling extended full viewing key (bech32).
    #[serde(default)]
    pub sapling_extfvk: Option<String>,

    /// Sapling payment address (`ks1...`).
    #[serde(default)]
    pub sapling_address: Option<String>,

    /// Hex-encoded Sapling commitment tree.
    #[serde(default)]
    pub commitment_tree: Option<String>,

    /// Unspent shielded notes.
    #[serde(default)]
    pub unspent_notes: Vec<SerializedNote>,

    /// Last synced shield block height.
    #[serde(default)]
    pub sapling_last_block: u32,
}

/// Serde helper: Vec<u8> as hex string.
mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use crate::encoding::{hex_encode, hex_decode};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
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
    /// Get the mnemonic phrase.
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// Get the 64-byte seed.
    pub fn seed(&self) -> &[u8] {
        &self.seed
    }

    /// Get the total balance in satoshis (saturating).
    pub fn balance(&self) -> u64 {
        self.utxos.iter().fold(0u64, |a, u| a.saturating_add(u.amount))
    }

    /// Get the balance formatted as KRGN string.
    pub fn balance_display(&self) -> String {
        format_krgn(self.balance())
    }

    /// Derive the keypair from the stored seed.
    pub fn derive_keypair(&self) -> Result<keys::Keypair, WalletError> {
        keys::derive_keypair(&self.seed).map_err(|e| WalletError::Other(e.to_string()))
    }

    /// Get the shielded balance in satoshis (sum of unspent notes).
    pub fn shielded_balance(&self) -> u64 {
        self.unspent_notes.iter().fold(0u64, |a, n| a.saturating_add(n.value))
    }

    /// Get the shielded balance formatted as KRGN string.
    pub fn shielded_balance_display(&self) -> String {
        format_krgn(self.shielded_balance())
    }

    /// Get the shielded address, if derived.
    pub fn sapling_address(&self) -> Option<&str> {
        self.sapling_address.as_deref()
    }

    /// Remove spent UTXOs after a send.
    pub fn finalize_send(&mut self, spent: &[(String, u32)]) {
        self.utxos.retain(|u| {
            !spent.iter().any(|(txid, vout)| u.txid == *txid && u.vout == *vout)
        });
    }
}

// ---------------------------------------------------------------------------
// Wallet creation
// ---------------------------------------------------------------------------

/// Create a new wallet from fresh entropy.
pub fn create_wallet_data() -> Result<WalletData, WalletError> {
    let mnemonic = bip39::generate_mnemonic()
        .map_err(|e| WalletError::Other(e.to_string()))?;
    wallet_from_mnemonic(&mnemonic)
}

/// Create a wallet from an existing mnemonic.
pub fn import_wallet_data(mnemonic: &str) -> Result<WalletData, WalletError> {
    bip39::validate_mnemonic(mnemonic)
        .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;
    wallet_from_mnemonic(mnemonic)
}

fn wallet_from_mnemonic(mnemonic: &str) -> Result<WalletData, WalletError> {
    let seed = bip39::mnemonic_to_seed(mnemonic, "");
    let kp = keys::derive_keypair(&seed)
        .map_err(|e| WalletError::Other(e.to_string()))?;

    // Derive Sapling shielded keys from the same seed
    let sapling_extsk = sapling::keys::default_spending_key(&seed)
        .map_err(|e| WalletError::Other(format!("sapling key derivation: {e}")))?;
    let sapling_extfvk = sapling::keys::full_viewing_key(&sapling_extsk);
    let sapling_addr = sapling::keys::default_payment_address(&sapling_extfvk);

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

        sapling_extsk: Some(sapling::keys::encode_extsk(&sapling_extsk)),
        sapling_extfvk: Some(sapling::keys::encode_extfvk(&sapling_extfvk)),
        sapling_address: Some(sapling::keys::encode_payment_address(&sapling_addr)),
        commitment_tree: None,
        unspent_notes: Vec::new(),
        sapling_last_block: 0,
    })
}

// ---------------------------------------------------------------------------
// Send preparation
// ---------------------------------------------------------------------------

/// Build and sign a send transaction.
pub fn prepare_send(
    wallet: &WalletData,
    to_address: &str,
    amount: u64,
) -> Result<SignedTransaction, WalletError> {
    let kp = wallet.derive_keypair()?;
    transaction::build_transaction(
        &wallet.utxos, to_address, amount,
        &kp.privkey, &kp.pubkey, &wallet.address,
    ).map_err(|e| WalletError::Transaction(e.to_string()))
}

/// Build and sign a "send max" transaction (entire balance minus fee).
pub fn prepare_send_max(
    wallet: &WalletData,
    to_address: &str,
) -> Result<SignedTransaction, WalletError> {
    let kp = wallet.derive_keypair()?;
    let own_script = crate::script::address_to_script_pubkey(&wallet.address)
        .map_err(|e| WalletError::Other(e.to_string()))?;
    transaction::build_max_transaction(
        &wallet.utxos, to_address,
        &kp.privkey, &kp.pubkey, &own_script,
    ).map_err(|e| WalletError::Transaction(e.to_string()))
}

// ---------------------------------------------------------------------------
// Encryption (symmetric — caller provides the key)
// ---------------------------------------------------------------------------

/// SHA256-CTR stream cipher. Symmetric — same function encrypts and decrypts.
/// Keystream blocks are zeroized after use.
pub fn crypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut offset = 0;
    let mut counter = 0u64;

    while offset < data.len() {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(counter.to_le_bytes());
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

/// Encrypt the sensitive fields of a WalletData for storage.
/// Returns a new WalletData with encrypted seed and mnemonic.
pub fn encrypt_wallet(data: &WalletData, key: &[u8; 32]) -> WalletData {
    let encrypted_seed = crypt(&data.seed, key);
    let encrypted_mnemonic = crypt(data.mnemonic.as_bytes(), key);

    WalletData {
        version: data.version,
        seed: encrypted_seed,
        mnemonic: hex_encode(&encrypted_mnemonic),
        address: data.address.clone(),
        utxos: data.utxos.clone(),
        processed_txids: data.processed_txids.clone(),
        sync_state: data.sync_state.clone(),
        history: data.history.clone(),
        last_sync_height: data.last_sync_height,

        sapling_extsk: data.sapling_extsk.clone(),
        sapling_extfvk: data.sapling_extfvk.clone(),
        sapling_address: data.sapling_address.clone(),
        commitment_tree: data.commitment_tree.clone(),
        unspent_notes: data.unspent_notes.clone(),
        sapling_last_block: data.sapling_last_block,
    }
}

/// Decrypt the sensitive fields of a WalletData after loading.
/// Returns the decrypted WalletData, or an error if decryption fails validation.
pub fn decrypt_wallet(mut data: WalletData, key: &[u8; 32]) -> Result<WalletData, WalletError> {
    // Decrypt seed
    data.seed = crypt(&data.seed, key);

    // Decrypt mnemonic
    let encrypted_bytes = hex_decode(&data.mnemonic)
        .map_err(|_| WalletError::Encryption("corrupt mnemonic field".into()))?;
    let decrypted_bytes = crypt(&encrypted_bytes, key);
    data.mnemonic = String::from_utf8(decrypted_bytes)
        .map_err(|_| WalletError::Encryption("decryption failed — wrong key?".into()))?;

    // Validate: re-derive address and compare
    let kp = keys::derive_keypair(&data.seed)
        .map_err(|_| WalletError::Encryption("decryption failed — wrong key?".into()))?;
    if kp.address != data.address {
        return Err(WalletError::Encryption("decryption failed — wrong key or corrupted file".into()));
    }

    Ok(data)
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

    #[test]
    fn crypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, Kerrigan Network!";
        let ct = crypt(plaintext, &key);
        assert_ne!(&ct, plaintext);
        let pt = crypt(&ct, &key);
        assert_eq!(&pt, plaintext);
    }

    #[test]
    fn wallet_from_known_mnemonic() {
        let wallet = wallet_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        assert!(wallet.address.starts_with('K'));
        assert_eq!(wallet.seed.len(), 64);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let wallet = wallet_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        let key = [0xAB; 32];
        let encrypted = encrypt_wallet(&wallet, &key);
        assert_ne!(encrypted.seed, wallet.seed);
        let decrypted = decrypt_wallet(encrypted, &key).unwrap();
        assert_eq!(decrypted.seed, wallet.seed);
        assert_eq!(decrypted.mnemonic, wallet.mnemonic);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let wallet = wallet_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        let encrypted = encrypt_wallet(&wallet, &[0xAB; 32]);
        assert!(decrypt_wallet(encrypted, &[0xCD; 32]).is_err());
    }

    #[test]
    fn format_parse_roundtrip() {
        for sat in [0u64, 1, 100_000_000, 150_000_000, 123_456_789] {
            let formatted = format_krgn(sat);
            let parsed = parse_krgn(&formatted).unwrap();
            assert_eq!(parsed, sat);
        }
    }

    #[test]
    fn balance_saturates() {
        let mut wallet = wallet_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        wallet.utxos = vec![
            Utxo { txid: "a".into(), vout: 0, amount: u64::MAX, script_pubkey: "s".into() },
            Utxo { txid: "b".into(), vout: 0, amount: 1, script_pubkey: "s".into() },
        ];
        assert_eq!(wallet.balance(), u64::MAX);
    }
}
