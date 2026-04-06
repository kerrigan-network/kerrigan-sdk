/// BIP32 hierarchical deterministic key derivation — from scratch.
/// No external BIP32 crate: HMAC-SHA512 derivation, hardened/normal children, path parsing.
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512, Digest};
use ripemd::Ripemd160;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use zeroize::Zeroize;
use std::fmt;

use crate::encoding::{base58_encode, base58_decode};
use crate::params;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum Bip32Error {
    InvalidSeed,
    InvalidKey,
    InvalidPath(String),
    InvalidChild,
    InvalidXKey(String),
}

impl fmt::Display for Bip32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSeed => write!(f, "Invalid seed (must be 16-64 bytes)"),
            Self::InvalidKey => write!(f, "Invalid private key (zero or >= curve order)"),
            Self::InvalidPath(s) => write!(f, "Invalid derivation path: {s}"),
            Self::InvalidChild => write!(f, "Child derivation produced invalid key"),
            Self::InvalidXKey(s) => write!(f, "Invalid extended key: {s}"),
        }
    }
}

impl std::error::Error for Bip32Error {}

// ---------------------------------------------------------------------------
// Extended private key
// ---------------------------------------------------------------------------

const HARDENED_BIT: u32 = 0x8000_0000;

#[derive(Clone)]
pub struct ExtendedPrivKey {
    /// 32-byte private key
    key: [u8; 32],
    /// 32-byte chain code
    chain_code: [u8; 32],
    /// Depth in the derivation tree (0 = master)
    pub depth: u8,
    /// Index of this key in its parent (0 for master)
    pub child_index: u32,
    /// First 4 bytes of the parent's key fingerprint (0x00000000 for master)
    pub parent_fingerprint: [u8; 4],
}

impl Drop for ExtendedPrivKey {
    fn drop(&mut self) {
        self.key.zeroize();
        self.chain_code.zeroize();
    }
}

impl ExtendedPrivKey {
    /// Create a master key from a BIP39 seed (16-64 bytes).
    /// HMAC-SHA512(key = "Bitcoin seed", data = seed)
    pub fn from_seed(seed: &[u8]) -> Result<Self, Bip32Error> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(Bip32Error::InvalidSeed);
        }

        let mut mac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed")
            .expect("HMAC accepts any key length");
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);

        // Validate that the key is a valid secp256k1 private key
        SecretKey::from_slice(&key).map_err(|_| Bip32Error::InvalidKey)?;

        Ok(Self {
            key,
            chain_code,
            depth: 0,
            child_index: 0,
            parent_fingerprint: [0; 4],
        })
    }

    /// Derive a child key at the given index.
    /// If index >= 0x80000000, this is a hardened derivation.
    pub fn derive_child(&self, index: u32) -> Result<Self, Bip32Error> {
        let secp = Secp256k1::new();

        let mut mac = Hmac::<Sha512>::new_from_slice(&self.chain_code)
            .expect("HMAC accepts any key length");

        if index >= HARDENED_BIT {
            // Hardened child: HMAC-SHA512(key = chain_code, data = 0x00 || key || index)
            mac.update(&[0x00]);
            mac.update(&self.key);
        } else {
            // Normal child: HMAC-SHA512(key = chain_code, data = pubkey || index)
            let secret = SecretKey::from_slice(&self.key)
                .map_err(|_| Bip32Error::InvalidKey)?;
            let pubkey = PublicKey::from_secret_key(&secp, &secret);
            mac.update(&pubkey.serialize());
        }
        mac.update(&index.to_be_bytes());

        let result = mac.finalize().into_bytes();
        let mut child_key_bytes = [0u8; 32];
        let mut child_chain = [0u8; 32];
        child_key_bytes.copy_from_slice(&result[..32]);
        child_chain.copy_from_slice(&result[32..]);

        // child_key = parse256(IL) + parent_key (mod n)
        let parent_secret = SecretKey::from_slice(&self.key)
            .map_err(|_| Bip32Error::InvalidKey)?;
        let tweak = SecretKey::from_slice(&child_key_bytes)
            .map_err(|_| Bip32Error::InvalidChild)?;
        let child_secret = parent_secret.add_tweak(&tweak.into())
            .map_err(|_| Bip32Error::InvalidChild)?;

        // Parent fingerprint = first 4 bytes of Hash160(parent_pubkey)
        let parent_pubkey = PublicKey::from_secret_key(&secp, &parent_secret);
        let parent_hash = hash160(&parent_pubkey.serialize());
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&parent_hash[..4]);

        let mut key = [0u8; 32];
        key.copy_from_slice(&child_secret[..]);

        Ok(Self {
            key,
            chain_code: child_chain,
            depth: self.depth.checked_add(1).ok_or(Bip32Error::InvalidChild)?,
            child_index: index,
            parent_fingerprint: fingerprint,
        })
    }

    /// Derive a key at the given BIP32 path string (e.g., "m/44'/99888'/0'/0/0").
    pub fn derive_path(&self, path: &str) -> Result<Self, Bip32Error> {
        let indices = parse_path(path)?;
        let mut current = self.clone();
        for index in indices {
            current = current.derive_child(index)?;
        }
        Ok(current)
    }

    /// Get the raw 32-byte private key.
    pub fn private_key_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Get the compressed public key (33 bytes).
    pub fn public_key_bytes(&self) -> [u8; 33] {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&self.key)
            .expect("key was validated at creation");
        let pubkey = PublicKey::from_secret_key(&secp, &secret);
        pubkey.serialize()
    }

    /// Serialize to xprv format (Base58Check with version prefix).
    pub fn to_xprv(&self) -> String {
        let mut data = Vec::with_capacity(78);
        data.extend_from_slice(&params::XPRV_VERSION);
        data.push(self.depth);
        data.extend_from_slice(&self.parent_fingerprint);
        data.extend_from_slice(&self.child_index.to_be_bytes());
        data.extend_from_slice(&self.chain_code);
        data.push(0x00); // private key prefix
        data.extend_from_slice(&self.key);

        // Base58Check: payload + SHA256d checksum
        let checksum = crate::encoding::sha256d(&data);
        data.extend_from_slice(&checksum[..4]);
        base58_encode(&data)
    }

    /// Serialize the corresponding xpub format.
    pub fn to_xpub(&self) -> String {
        let pubkey = self.public_key_bytes();
        let mut data = Vec::with_capacity(78);
        data.extend_from_slice(&params::XPUB_VERSION);
        data.push(self.depth);
        data.extend_from_slice(&self.parent_fingerprint);
        data.extend_from_slice(&self.child_index.to_be_bytes());
        data.extend_from_slice(&self.chain_code);
        data.extend_from_slice(&pubkey);

        let checksum = crate::encoding::sha256d(&data);
        data.extend_from_slice(&checksum[..4]);
        base58_encode(&data)
    }

    /// Decode an xprv string back to an ExtendedPrivKey.
    pub fn from_xprv(xprv: &str) -> Result<Self, Bip32Error> {
        let bytes = base58_decode(xprv)
            .map_err(|e| Bip32Error::InvalidXKey(e.to_string()))?;
        if bytes.len() != 82 {
            return Err(Bip32Error::InvalidXKey("wrong length".into()));
        }

        // Verify checksum
        let (payload, checksum) = bytes.split_at(78);
        let computed = crate::encoding::sha256d(payload);
        if checksum != &computed[..4] {
            return Err(Bip32Error::InvalidXKey("checksum mismatch".into()));
        }

        // Verify version
        if payload[..4] != params::XPRV_VERSION {
            return Err(Bip32Error::InvalidXKey("not an xprv key".into()));
        }

        let depth = payload[4];
        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&payload[5..9]);
        let child_index = u32::from_be_bytes([payload[9], payload[10], payload[11], payload[12]]);
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&payload[13..45]);
        // payload[45] should be 0x00 (private key prefix)
        if payload[45] != 0x00 {
            return Err(Bip32Error::InvalidXKey("missing private key prefix".into()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&payload[46..78]);

        // Validate
        SecretKey::from_slice(&key).map_err(|_| Bip32Error::InvalidKey)?;

        Ok(Self {
            key,
            chain_code,
            depth,
            child_index,
            parent_fingerprint,
        })
    }
}

// ---------------------------------------------------------------------------
// Path parsing
// ---------------------------------------------------------------------------

/// Parse a BIP32 derivation path like "m/44'/99888'/0'/0/0" into a list of child indices.
pub fn parse_path(path: &str) -> Result<Vec<u32>, Bip32Error> {
    let path = path.trim();
    if path == "m" || path == "m/" {
        return Ok(Vec::new());
    }

    let stripped = path.strip_prefix("m/")
        .ok_or_else(|| Bip32Error::InvalidPath("must start with 'm/'".into()))?;

    let mut indices = Vec::new();
    for component in stripped.split('/') {
        let component = component.trim();
        if component.is_empty() {
            return Err(Bip32Error::InvalidPath("empty component".into()));
        }

        let (num_str, hardened) = if component.ends_with('\'') || component.ends_with('h') {
            (&component[..component.len() - 1], true)
        } else {
            (component, false)
        };

        let index: u32 = num_str.parse()
            .map_err(|_| Bip32Error::InvalidPath(format!("invalid index: {component}")))?;

        if index >= HARDENED_BIT {
            return Err(Bip32Error::InvalidPath(format!("index too large: {index}")));
        }

        indices.push(if hardened { index | HARDENED_BIT } else { index });
    }

    Ok(indices)
}

// ---------------------------------------------------------------------------
// Hash160 (SHA256 → RIPEMD160)
// ---------------------------------------------------------------------------

/// Hash160: RIPEMD160(SHA256(data)). Used for public key hashing.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripemd = Ripemd160::digest(sha);
    let mut result = [0u8; 20];
    result.copy_from_slice(&ripemd);
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{hex_encode, hex_decode};

    // -- BIP32 Test Vector 1 --
    // Seed: 000102030405060708090a0b0c0d0e0f

    fn vector1_seed() -> Vec<u8> {
        hex_decode("000102030405060708090a0b0c0d0e0f").unwrap()
    }

    #[test]
    fn vector1_master() {
        let master = ExtendedPrivKey::from_seed(&vector1_seed()).unwrap();
        assert_eq!(
            master.to_xprv(),
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        );
        assert_eq!(
            master.to_xpub(),
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        );
    }

    #[test]
    fn vector1_chain_m_0h() {
        let master = ExtendedPrivKey::from_seed(&vector1_seed()).unwrap();
        let child = master.derive_child(HARDENED_BIT).unwrap();
        assert_eq!(
            child.to_xprv(),
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        );
        assert_eq!(
            child.to_xpub(),
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
        );
    }

    #[test]
    fn vector1_chain_m_0h_1() {
        let master = ExtendedPrivKey::from_seed(&vector1_seed()).unwrap();
        let child = master.derive_child(HARDENED_BIT).unwrap()
            .derive_child(1).unwrap();
        assert_eq!(
            child.to_xprv(),
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
        );
    }

    #[test]
    fn vector1_chain_m_0h_1_2h() {
        let master = ExtendedPrivKey::from_seed(&vector1_seed()).unwrap();
        let child = master.derive_path("m/0'/1/2'").unwrap();
        assert_eq!(
            child.to_xprv(),
            "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
        );
        assert_eq!(
            child.to_xpub(),
            "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
        );
    }

    #[test]
    fn vector1_chain_full() {
        // m/0'/1/2'/2/1000000000
        let master = ExtendedPrivKey::from_seed(&vector1_seed()).unwrap();
        let child = master.derive_path("m/0'/1/2'/2/1000000000").unwrap();
        assert_eq!(
            child.to_xprv(),
            "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
        );
    }

    // -- BIP32 Test Vector 2 --
    // Seed: fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542

    fn vector2_seed() -> Vec<u8> {
        hex_decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap()
    }

    #[test]
    fn vector2_master() {
        let master = ExtendedPrivKey::from_seed(&vector2_seed()).unwrap();
        assert_eq!(
            master.to_xprv(),
            "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
        );
    }

    #[test]
    fn vector2_chain_m_0() {
        let master = ExtendedPrivKey::from_seed(&vector2_seed()).unwrap();
        let child = master.derive_child(0).unwrap();
        assert_eq!(
            child.to_xprv(),
            "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
        );
        assert_eq!(
            child.to_xpub(),
            "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
        );
    }

    #[test]
    fn vector2_chain_m_0_2147483647h_1() {
        let master = ExtendedPrivKey::from_seed(&vector2_seed()).unwrap();
        let child = master.derive_path("m/0/2147483647'/1").unwrap();
        assert_eq!(
            child.to_xprv(),
            "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"
        );
        assert_eq!(
            child.to_xpub(),
            "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
        );
    }

    // -- Path parsing tests --

    #[test]
    fn parse_path_basic() {
        assert_eq!(parse_path("m").unwrap(), Vec::<u32>::new());
        assert_eq!(parse_path("m/").unwrap(), Vec::<u32>::new());
        assert_eq!(parse_path("m/0").unwrap(), vec![0]);
        assert_eq!(parse_path("m/0'").unwrap(), vec![HARDENED_BIT]);
        assert_eq!(parse_path("m/0h").unwrap(), vec![HARDENED_BIT]);
        assert_eq!(
            parse_path("m/44'/99888'/0'/0/0").unwrap(),
            vec![44 | HARDENED_BIT, 99888 | HARDENED_BIT, HARDENED_BIT, 0, 0]
        );
    }

    #[test]
    fn parse_path_invalid() {
        assert!(parse_path("44'/0'/0'").is_err()); // no m/ prefix
        assert!(parse_path("m//0").is_err()); // empty component
        assert!(parse_path("m/abc").is_err()); // non-numeric
    }

    // -- Derive path end-to-end --

    #[test]
    fn derive_path_kerrigan() {
        // Derive at m/44'/99888'/0'/0/0 from a known seed
        let seed = hex_decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        let child = master.derive_path("m/44'/99888'/0'/0/0").unwrap();

        // Should be depth 5
        assert_eq!(child.depth, 5);

        // Public key should be 33 bytes (compressed)
        let pubkey = child.public_key_bytes();
        assert_eq!(pubkey.len(), 33);
        assert!(pubkey[0] == 0x02 || pubkey[0] == 0x03);
    }

    // -- xprv roundtrip --

    #[test]
    fn xprv_roundtrip() {
        let seed = hex_decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        let xprv_str = master.to_xprv();
        let restored = ExtendedPrivKey::from_xprv(&xprv_str).unwrap();
        assert_eq!(restored.to_xprv(), xprv_str);
        assert_eq!(restored.to_xpub(), master.to_xpub());
    }

    // -- Hash160 --

    #[test]
    fn hash160_known() {
        // Hash160 of a compressed public key — known Bitcoin test
        let pubkey = hex_decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        let h = hash160(&pubkey);
        assert_eq!(
            hex_encode(&h),
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        );
    }

    // -- Seed edge cases --

    #[test]
    fn seed_too_short() {
        assert!(matches!(ExtendedPrivKey::from_seed(&[0u8; 15]), Err(Bip32Error::InvalidSeed)));
    }

    #[test]
    fn seed_too_long() {
        assert!(matches!(ExtendedPrivKey::from_seed(&[0u8; 65]), Err(Bip32Error::InvalidSeed)));
    }

    #[test]
    fn seed_min_length() {
        let seed = [0x42u8; 16];
        assert!(ExtendedPrivKey::from_seed(&seed).is_ok());
    }

    #[test]
    fn seed_max_length() {
        let seed = [0x42u8; 64];
        assert!(ExtendedPrivKey::from_seed(&seed).is_ok());
    }
}
