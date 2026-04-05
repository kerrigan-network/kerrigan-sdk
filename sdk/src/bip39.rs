/// BIP39 mnemonic generation and seed derivation — from scratch.
/// No external BIP39 crate: wordlist, entropy, PBKDF2-HMAC-SHA512 all implemented here.

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512, Digest};
use zeroize::Zeroize;
use std::fmt;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum Bip39Error {
    InvalidWordCount(usize),
    InvalidWord(String),
    InvalidChecksum,
    InvalidEntropy,
}

impl fmt::Display for Bip39Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWordCount(n) => write!(f, "Invalid word count: {n} (expected 12, 15, 18, 21, or 24)"),
            Self::InvalidWord(w) => write!(f, "Word not in BIP39 wordlist: {w}"),
            Self::InvalidChecksum => write!(f, "Invalid mnemonic checksum"),
            Self::InvalidEntropy => write!(f, "Invalid entropy length"),
        }
    }
}

impl std::error::Error for Bip39Error {}

// ---------------------------------------------------------------------------
// BIP39 English wordlist (2048 words)
// ---------------------------------------------------------------------------

const WORDLIST: [&str; 2048] = include!("bip39_wordlist.rs");

/// Look up a word's index in the wordlist (0-2047), or None if not found.
fn word_index(word: &str) -> Option<usize> {
    // Binary search since the wordlist is sorted alphabetically
    WORDLIST.binary_search(&word).ok()
}

// ---------------------------------------------------------------------------
// Mnemonic generation
// ---------------------------------------------------------------------------

/// Generate a 24-word BIP39 mnemonic from 256 bits of entropy.
pub fn generate_mnemonic() -> Result<String, Bip39Error> {
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy)
        .map_err(|_| Bip39Error::InvalidEntropy)?;
    let mnemonic = entropy_to_mnemonic(&entropy)?;
    entropy.zeroize();
    Ok(mnemonic)
}

/// Convert entropy bytes to a mnemonic sentence.
/// Accepts 16, 20, 24, 28, or 32 bytes (128-256 bits).
pub fn entropy_to_mnemonic(entropy: &[u8]) -> Result<String, Bip39Error> {
    let ent_bits = entropy.len() * 8;
    if ![128, 160, 192, 224, 256].contains(&ent_bits) {
        return Err(Bip39Error::InvalidEntropy);
    }

    // Checksum: first (ENT/32) bits of SHA256(entropy)
    let checksum_byte = Sha256::digest(entropy)[0];
    let cs_bits = ent_bits / 32;

    // Concatenate entropy bits + checksum bits, then split into 11-bit groups
    // Total bits = ent_bits + cs_bits, always divisible by 11
    let total_bits = ent_bits + cs_bits;
    let word_count = total_bits / 11;

    // Build a bit reader over entropy || checksum
    let mut words = Vec::with_capacity(word_count);
    for i in 0..word_count {
        let mut idx: u16 = 0;
        for j in 0..11 {
            let bit_pos = i * 11 + j;
            let bit = if bit_pos < ent_bits {
                // From entropy
                (entropy[bit_pos / 8] >> (7 - (bit_pos % 8))) & 1
            } else {
                // From checksum byte
                let cs_pos = bit_pos - ent_bits;
                (checksum_byte >> (7 - cs_pos)) & 1
            };
            idx = (idx << 1) | bit as u16;
        }
        words.push(WORDLIST[idx as usize]);
    }

    Ok(words.join(" "))
}

// ---------------------------------------------------------------------------
// Mnemonic validation
// ---------------------------------------------------------------------------

/// Validate a BIP39 mnemonic: word lookup + checksum verification.
pub fn validate_mnemonic(mnemonic: &str) -> Result<(), Bip39Error> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    let word_count = words.len();

    if ![12, 15, 18, 21, 24].contains(&word_count) {
        return Err(Bip39Error::InvalidWordCount(word_count));
    }

    // Convert words back to 11-bit indices
    let mut indices = Vec::with_capacity(word_count);
    for word in &words {
        let idx = word_index(word)
            .ok_or_else(|| Bip39Error::InvalidWord(word.to_string()))?;
        indices.push(idx as u16);
    }

    // Reconstruct entropy + checksum bits
    let total_bits = word_count * 11;
    let cs_bits = word_count / 3; // CS = ENT/32, and word_count = (ENT + CS) / 11
    let ent_bits = total_bits - cs_bits;
    let ent_bytes = ent_bits / 8;

    // Extract entropy bytes from the 11-bit indices
    let mut entropy = vec![0u8; ent_bytes];
    for (i, &idx) in indices.iter().enumerate() {
        for j in 0..11 {
            let bit_pos = i * 11 + j;
            if bit_pos < ent_bits {
                if (idx >> (10 - j)) & 1 == 1 {
                    entropy[bit_pos / 8] |= 1 << (7 - (bit_pos % 8));
                }
            }
        }
    }

    // Verify checksum
    let checksum_byte = Sha256::digest(&entropy)[0];
    let expected_cs = checksum_byte >> (8 - cs_bits);

    // Extract actual checksum from the last cs_bits of the mnemonic
    let mut actual_cs: u8 = 0;
    for i in 0..cs_bits {
        let bit_pos = ent_bits + i;
        let word_idx = bit_pos / 11;
        let bit_in_word = bit_pos % 11;
        if (indices[word_idx] >> (10 - bit_in_word)) & 1 == 1 {
            actual_cs |= 1 << (cs_bits - 1 - i);
        }
    }

    if expected_cs != actual_cs {
        return Err(Bip39Error::InvalidChecksum);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA512 (from scratch)
// ---------------------------------------------------------------------------

/// PBKDF2-HMAC-SHA512 with the given password, salt, iteration count, and output length.
pub fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    let hlen = 64; // SHA-512 output length
    let blocks_needed = (dk_len + hlen - 1) / hlen;
    let mut dk = Vec::with_capacity(dk_len);

    for block_idx in 1..=blocks_needed as u32 {
        // U_1 = PRF(password, salt || INT(block_idx))
        let mut salt_block = Vec::with_capacity(salt.len() + 4);
        salt_block.extend_from_slice(salt);
        salt_block.extend_from_slice(&block_idx.to_be_bytes());

        let mut mac = Hmac::<Sha512>::new_from_slice(password)
            .expect("HMAC accepts any key length");
        mac.update(&salt_block);
        let mut u_prev = mac.finalize().into_bytes();
        let mut block = [0u8; 64];
        block.copy_from_slice(&u_prev);

        // U_2 .. U_c: XOR together
        for _ in 1..iterations {
            let mut mac = Hmac::<Sha512>::new_from_slice(password)
                .expect("HMAC accepts any key length");
            mac.update(&u_prev);
            u_prev = mac.finalize().into_bytes();
            for (b, u) in block.iter_mut().zip(u_prev.iter()) {
                *b ^= u;
            }
        }

        dk.extend_from_slice(&block);
    }

    dk.truncate(dk_len);
    dk
}

/// Derive a 64-byte seed from a BIP39 mnemonic and optional passphrase.
/// Uses PBKDF2-HMAC-SHA512 with 2048 iterations.
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Vec<u8> {
    let password = mnemonic.as_bytes();
    let salt = format!("mnemonic{}", passphrase);
    pbkdf2_hmac_sha512(password, salt.as_bytes(), 2048, 64)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex_encode;

    // -- PBKDF2 RFC 6070 test vectors (HMAC-SHA1 vectors aren't applicable,
    //    but we test HMAC-SHA512 with known BIP39 vectors) --

    #[test]
    fn pbkdf2_hmac_sha512_basic() {
        // Test with a simple known input: PBKDF2-HMAC-SHA512("password", "salt", 1, 64)
        // Verified against OpenSSL / Python hashlib
        let result = pbkdf2_hmac_sha512(b"password", b"salt", 1, 64);
        assert_eq!(result.len(), 64);
        assert_eq!(
            hex_encode(&result),
            "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf2\
             52c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a5\
             7fce"
        );
    }

    #[test]
    fn pbkdf2_hmac_sha512_2048_iterations() {
        // PBKDF2-HMAC-SHA512("password", "salt", 2048, 64)
        let result = pbkdf2_hmac_sha512(b"password", b"salt", 2048, 64);
        assert_eq!(result.len(), 64);
        assert_eq!(
            hex_encode(&result),
            "91be23564f09fc855c82ce84a223ebe7d63d8b49d69372593a0d9ed39e143c\
             83e1ab2f722a5ddb969feefc88403f7e2afe1afb8b2f0e6b20add0fb7b2836\
             8807"
        );
    }

    #[test]
    fn pbkdf2_hmac_sha512_4096_iterations() {
        // PBKDF2-HMAC-SHA512("password", "salt", 4096, 64)
        let result = pbkdf2_hmac_sha512(b"password", b"salt", 4096, 64);
        assert_eq!(result.len(), 64);
        assert_eq!(
            hex_encode(&result),
            "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457\
             b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af\
             2d5"
        );
    }

    // -- BIP39 test vectors (from Trezor's python-mnemonic vectors.json) --

    #[test]
    fn bip39_vector_0_all_zeros() {
        // Entropy: 00000000000000000000000000000000 (128-bit)
        // Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let entropy = crate::encoding::hex_decode("00000000000000000000000000000000").unwrap();
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        assert_eq!(
            mnemonic,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        validate_mnemonic(&mnemonic).unwrap();

        let seed = mnemonic_to_seed(&mnemonic, "TREZOR");
        assert_eq!(
            hex_encode(&seed),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
             1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn bip39_vector_1_all_ones() {
        // Entropy: 7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f (128-bit)
        let entropy = crate::encoding::hex_decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f").unwrap();
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        assert_eq!(
            mnemonic,
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
        );
        validate_mnemonic(&mnemonic).unwrap();

        let seed = mnemonic_to_seed(&mnemonic, "TREZOR");
        assert_eq!(
            hex_encode(&seed),
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f\
             a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"
        );
    }

    #[test]
    fn bip39_vector_24_word() {
        // Entropy: 0000000000000000000000000000000000000000000000000000000000000000 (256-bit)
        let entropy = crate::encoding::hex_decode(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ).unwrap();
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        assert_eq!(
            mnemonic,
            "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon art"
        );
        validate_mnemonic(&mnemonic).unwrap();

        let seed = mnemonic_to_seed(&mnemonic, "TREZOR");
        assert_eq!(
            hex_encode(&seed),
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971\
             70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
        );
    }

    #[test]
    fn bip39_vector_all_ff() {
        // Entropy: ffffffffffffffffffffffffffffffff (128-bit)
        let entropy = crate::encoding::hex_decode("ffffffffffffffffffffffffffffffff").unwrap();
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        assert_eq!(
            mnemonic,
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        );
        validate_mnemonic(&mnemonic).unwrap();

        let seed = mnemonic_to_seed(&mnemonic, "TREZOR");
        assert_eq!(
            hex_encode(&seed),
            "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13\
             332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069"
        );
    }

    #[test]
    fn bip39_vector_mixed_256bit() {
        // Entropy: 68a79eead171a4d1c6b5dc1cbf0b7a4e8ef72e0b7b7b7c7d7e7f808182838485 (256-bit)
        let entropy = crate::encoding::hex_decode(
            "68a79eead171a4d1c6b5dc1cbf0b7a4e8ef72e0b7b7b7c7d7e7f808182838485"
        ).unwrap();
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 24);
        validate_mnemonic(&mnemonic).unwrap();
    }

    // -- Mnemonic validation --

    #[test]
    fn validate_rejects_bad_word() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzzz";
        assert!(matches!(validate_mnemonic(bad), Err(Bip39Error::InvalidWord(_))));
    }

    #[test]
    fn validate_rejects_bad_count() {
        let bad = "abandon abandon abandon";
        assert!(matches!(validate_mnemonic(bad), Err(Bip39Error::InvalidWordCount(3))));
    }

    #[test]
    fn validate_rejects_bad_checksum() {
        // Valid words, wrong checksum (change "about" to "abandon")
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(matches!(validate_mnemonic(bad), Err(Bip39Error::InvalidChecksum)));
    }

    // -- Generate roundtrip --

    #[test]
    fn generate_roundtrip() {
        let mnemonic = generate_mnemonic().unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24);
        validate_mnemonic(&mnemonic).unwrap();

        // Seed should be 64 bytes
        let seed = mnemonic_to_seed(&mnemonic, "");
        assert_eq!(seed.len(), 64);
    }

    // -- Entropy edge cases --

    #[test]
    fn entropy_invalid_length() {
        assert!(matches!(entropy_to_mnemonic(&[0u8; 15]), Err(Bip39Error::InvalidEntropy)));
        assert!(matches!(entropy_to_mnemonic(&[0u8; 33]), Err(Bip39Error::InvalidEntropy)));
    }

    #[test]
    fn entropy_all_valid_lengths() {
        for len in [16, 20, 24, 28, 32] {
            let entropy = vec![0xABu8; len];
            let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
            let expected_words = (len * 8 + len * 8 / 32) / 11;
            assert_eq!(mnemonic.split_whitespace().count(), expected_words);
            validate_mnemonic(&mnemonic).unwrap();
        }
    }

    // -- Seed derivation with empty passphrase --

    #[test]
    fn seed_empty_passphrase() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "");
        assert_eq!(seed.len(), 64);
        // Different from TREZOR passphrase
        let seed_trezor = mnemonic_to_seed(mnemonic, "TREZOR");
        assert_ne!(seed, seed_trezor);
    }
}
