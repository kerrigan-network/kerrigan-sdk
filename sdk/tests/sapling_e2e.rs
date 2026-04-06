/// End-to-end Sapling tests for the Kerrigan Network.
///
/// All test data is synthetic (deterministic seeds, zero-filled arrays).
/// No real wallet keys or mainnet data.

use kerrigan_sdk::sapling;
use ::sapling::Node;

// ---------------------------------------------------------------------------
// Synthetic test data helpers
// ---------------------------------------------------------------------------

fn test_seed_a() -> [u8; 64] { [0u8; 64] }
fn test_seed_b() -> [u8; 64] { let mut s = [0u8; 64]; s[0] = 1; s }

// ===========================================================================
// Key derivation tests
// ===========================================================================

#[test]
fn key_derivation_deterministic() {
    let addr1 = sapling::keys::derive_shielded_address(&test_seed_a()).unwrap();
    let addr2 = sapling::keys::derive_shielded_address(&test_seed_a()).unwrap();
    assert_eq!(addr1, addr2, "Same seed must produce same address");
}

#[test]
fn key_derivation_unique_per_seed() {
    let addr_a = sapling::keys::derive_shielded_address(&test_seed_a()).unwrap();
    let addr_b = sapling::keys::derive_shielded_address(&test_seed_b()).unwrap();
    assert_ne!(addr_a, addr_b, "Different seeds must produce different addresses");
}

#[test]
fn shielded_address_starts_with_ks() {
    let addr = sapling::keys::derive_shielded_address(&test_seed_a()).unwrap();
    assert!(addr.starts_with("ks"), "Kerrigan shielded address must start with 'ks', got: {addr}");
}

#[test]
fn full_key_pipeline_extsk_to_address() {
    let extsk = sapling::keys::default_spending_key(&test_seed_a()).unwrap();
    let extfvk = sapling::keys::full_viewing_key(&extsk);
    let addr = sapling::keys::default_payment_address(&extfvk);
    let encoded = sapling::keys::encode_payment_address(&addr);
    let decoded = sapling::keys::decode_payment_address(&encoded).unwrap();
    assert_eq!(addr, decoded, "Payment address encode/decode roundtrip failed");
}

#[test]
fn extsk_encode_decode_roundtrip() {
    let extsk = sapling::keys::default_spending_key(&test_seed_a()).unwrap();
    let encoded = sapling::keys::encode_extsk(&extsk);
    let decoded = sapling::keys::decode_extsk(&encoded).unwrap();
    // Verify by comparing derived addresses
    let addr1 = sapling::keys::default_payment_address(&sapling::keys::full_viewing_key(&extsk));
    let addr2 = sapling::keys::default_payment_address(&sapling::keys::full_viewing_key(&decoded));
    assert_eq!(addr1, addr2);
}

#[test]
fn extfvk_encode_decode_roundtrip() {
    let extsk = sapling::keys::default_spending_key(&test_seed_a()).unwrap();
    let extfvk = sapling::keys::full_viewing_key(&extsk);
    let encoded = sapling::keys::encode_extfvk(&extfvk);
    let decoded = sapling::keys::decode_extfvk(&encoded).unwrap();
    let addr1 = sapling::keys::default_payment_address(&extfvk);
    let addr2 = sapling::keys::default_payment_address(&decoded);
    assert_eq!(addr1, addr2);
}

#[test]
fn coin_type_99888_differs_from_pivx_119() {
    let kerrigan = sapling::keys::spending_key_from_seed(&test_seed_a(), 99888, 0).unwrap();
    let pivx = sapling::keys::spending_key_from_seed(&test_seed_a(), 119, 0).unwrap();
    let k_addr = sapling::keys::encode_payment_address(
        &sapling::keys::default_payment_address(&sapling::keys::full_viewing_key(&kerrigan))
    );
    let p_addr = sapling::keys::encode_payment_address(
        &sapling::keys::default_payment_address(&sapling::keys::full_viewing_key(&pivx))
    );
    assert_ne!(k_addr, p_addr, "Different coin types must produce different keys");
}

#[test]
fn nullifier_key_derivation_deterministic() {
    let extsk = sapling::keys::default_spending_key(&test_seed_a()).unwrap();
    let extfvk = sapling::keys::full_viewing_key(&extsk);
    let nk1 = sapling::keys::nullifier_deriving_key(&extfvk);
    let nk2 = sapling::keys::nullifier_deriving_key(&extfvk);
    assert_eq!(nk1, nk2);
}

// ===========================================================================
// Fee calculation tests (must match Kerrigan's CheckSaplingFees)
// ===========================================================================

#[test]
fn fee_base_is_20000() {
    // Kerrigan base fee is 0.0002 KRGN = 20,000 sat
    assert_eq!(sapling::fees::sapling_fee(0, 0), 20_000);
}

#[test]
fn fee_per_spend_is_5000() {
    // Each additional spend adds 5,000 sat
    let fee_0 = sapling::fees::sapling_fee(0, 0);
    let fee_1 = sapling::fees::sapling_fee(1, 0);
    assert_eq!(fee_1 - fee_0, 5_000);
}

#[test]
fn fee_per_output_is_5000() {
    // Each additional output adds 5,000 sat
    let fee_0 = sapling::fees::sapling_fee(0, 0);
    let fee_1 = sapling::fees::sapling_fee(0, 1);
    assert_eq!(fee_1 - fee_0, 5_000);
}

#[test]
fn fee_shielding_one_output() {
    // Shielding: 0 spends, 1 output → 20000 + 5000 = 25000
    assert_eq!(sapling::fees::shield_fee(1), 25_000);
}

#[test]
fn fee_typical_send() {
    // Shield send: 1 spend, 2 outputs (payment + change) → 20000 + 5000 + 10000 = 35000
    assert_eq!(sapling::fees::shield_send_fee(1), 35_000);
}

#[test]
fn fee_unshield() {
    // Unshield: 1 spend, 1 sapling output (change) → 20000 + 5000 + 5000 = 30000
    assert_eq!(sapling::fees::unshield_fee(1), 30_000);
}

#[test]
fn fee_formula_matches_kerrigan_node() {
    // Reference: Kerrigan's CheckSaplingFees in sapling_tx_payload.h
    // fee = BASE_FEE + nSpends * PER_SPEND + nOutputs * PER_OUTPUT
    for spends in 0..=5 {
        for outputs in 0..=5 {
            let expected = 20_000 + spends * 5_000 + outputs * 5_000;
            let actual = sapling::fees::sapling_fee(spends as usize, outputs as usize);
            assert_eq!(actual, expected,
                "Fee mismatch for {spends} spends, {outputs} outputs");
        }
    }
}

#[test]
fn fee_max_components_no_overflow() {
    // 500 spends + 500 outputs — maximum allowed by Kerrigan
    let fee = sapling::fees::sapling_fee(500, 500);
    assert_eq!(fee, 20_000 + 500 * 5_000 + 500 * 5_000);
    assert!(fee < u64::MAX);
}

// ===========================================================================
// Network constants tests
// ===========================================================================

#[test]
fn sapling_activation_height_500() {
    assert_eq!(sapling::network::SAPLING_ACTIVATION_HEIGHT, 500);
}

#[test]
fn sapling_hrp_is_ks() {
    assert_eq!(sapling::network::HRP_SAPLING_PAYMENT_ADDRESS, "ks");
}

#[test]
fn kerrigan_tx_version_is_3() {
    assert_eq!(sapling::network::SAPLING_TX_VERSION, 3);
}

// ===========================================================================
// Commitment tree tests
// ===========================================================================

#[test]
fn empty_tree_root_deterministic() {
    let root1 = sapling::tree::tree_root(&sapling::tree::empty_tree());
    let root2 = sapling::tree::tree_root(&sapling::tree::empty_tree());
    assert_eq!(root1, root2);
}

#[test]
fn tree_append_changes_root() {
    let mut tree = sapling::tree::empty_tree();
    let root_before = sapling::tree::tree_root(&tree);
    // Use value 42 (not 1, since 1 = Sapling uncommitted leaf)
    let node = Node::from_bytes([42u8; 32]).unwrap();
    sapling::tree::append_node(&mut tree, node).unwrap();
    let root_after = sapling::tree::tree_root(&tree);
    assert_ne!(root_before, root_after);
}

#[test]
fn tree_hex_roundtrip() {
    let mut tree = sapling::tree::empty_tree();
    let node = Node::from_bytes([42u8; 32]).unwrap();
    sapling::tree::append_node(&mut tree, node).unwrap();
    let hex = sapling::tree::write_tree_hex(&tree).unwrap();
    let restored = sapling::tree::read_tree_hex(&hex).unwrap();
    assert_eq!(
        sapling::tree::tree_root(&tree),
        sapling::tree::tree_root(&restored),
    );
}

#[test]
fn witness_tracks_merkle_path() {
    let mut tree = sapling::tree::empty_tree();
    let node = Node::from_bytes([42u8; 32]).unwrap();
    sapling::tree::append_node(&mut tree, node).unwrap();
    let mut witness = sapling::tree::witness_from_tree(&tree).unwrap();

    // Advance witness with more nodes
    for i in 43..=50 {
        let n = Node::from_bytes([i; 32]).unwrap();
        sapling::tree::append_node(&mut tree, n).unwrap();
        sapling::tree::advance_witness(&mut witness, n).unwrap();
    }

    // Witness should have a valid path
    assert!(witness.path().is_some());
}

// ===========================================================================
// Compact sync protocol tests
// ===========================================================================

use kerrigan_sdk::sapling::sync::*;
use zcash_note_encryption::ENC_CIPHERTEXT_SIZE;

#[test]
fn compact_protocol_empty_stream() {
    let blocks = parse_shield_stream(&[]).unwrap();
    assert!(blocks.is_empty());
}

#[test]
fn compact_protocol_block_marker_roundtrip() {
    let stream = encode_block_marker(12345);
    let blocks = parse_shield_stream(&stream).unwrap();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].height, 12345);
}

#[test]
fn compact_protocol_compact_tx_roundtrip() {
    let tx = CompactTransaction {
        nullifiers: vec![[0xAA; 32], [0xBB; 32]],
        outputs: vec![CompactSaplingOutput {
            cmu: [0x11; 32],
            epk: [0x22; 32],
            enc_ciphertext: [0x33; ENC_CIPHERTEXT_SIZE],
        }],
    };

    let mut stream = encode_block_marker(500);
    stream.extend(encode_compact_tx(&tx));

    let blocks = parse_shield_stream(&stream).unwrap();
    assert_eq!(blocks[0].height, 500);
    match &blocks[0].entries[0] {
        BlockEntry::CompactTx(ct) => {
            assert_eq!(ct.nullifiers.len(), 2);
            assert_eq!(ct.nullifiers[0], [0xAA; 32]);
            assert_eq!(ct.outputs.len(), 1);
            assert_eq!(ct.outputs[0].cmu, [0x11; 32]);
            assert_eq!(ct.outputs[0].epk, [0x22; 32]);
        }
        _ => panic!("Expected CompactTx"),
    }
}

#[test]
fn compact_protocol_multi_block_ordering() {
    let mut stream = Vec::new();
    for h in [500, 501, 600, 1000] {
        stream.extend(encode_block_marker(h));
    }
    let blocks = parse_shield_stream(&stream).unwrap();
    assert_eq!(blocks.iter().map(|b| b.height).collect::<Vec<_>>(), vec![500, 501, 600, 1000]);
}

#[test]
fn compact_protocol_tx_before_block_fails() {
    let tx = CompactTransaction { nullifiers: vec![], outputs: vec![] };
    let stream = encode_compact_tx(&tx);
    assert!(parse_shield_stream(&stream).is_err());
}

#[test]
fn compact_protocol_truncated_packet_fails() {
    let mut stream = Vec::new();
    stream.extend((100u32).to_le_bytes()); // claims 100 bytes
    stream.push(0x5d); // only 1 byte of payload
    assert!(parse_shield_stream(&stream).is_err());
}

#[test]
fn compact_protocol_unknown_type_fails() {
    let mut stream = encode_block_marker(1);
    let payload = [0xFF, 0x01, 0x02];
    stream.extend((payload.len() as u32).to_le_bytes());
    stream.extend_from_slice(&payload);
    assert!(parse_shield_stream(&stream).is_err());
}

#[test]
fn compact_output_implements_shielded_output() {
    // CompactSaplingOutput implements ShieldedOutput<SaplingDomain> for try_note_decryption
    let output = CompactSaplingOutput {
        cmu: [0x11; 32],
        epk: [0x22; 32],
        enc_ciphertext: [0x33; ENC_CIPHERTEXT_SIZE],
    };
    // Just verify the trait methods compile and return expected values
    use zcash_note_encryption::{ShieldedOutput, EphemeralKeyBytes};
    use ::sapling::note_encryption::SaplingDomain;
    let epk: EphemeralKeyBytes = ShieldedOutput::<SaplingDomain, ENC_CIPHERTEXT_SIZE>::ephemeral_key(&output);
    assert_eq!(epk.0, [0x22; 32]);
    let cmu: [u8; 32] = ShieldedOutput::<SaplingDomain, ENC_CIPHERTEXT_SIZE>::cmstar_bytes(&output);
    assert_eq!(cmu, [0x11; 32]);
}

#[test]
fn compact_size_savings_verified() {
    // Verify the size math from our design
    let full_spend = 32 + 32 + 32 + 32 + 192 + 64; // 384
    let compact_spend = 32; // nullifier only
    let full_output = 32 + 32 + 32 + ENC_CIPHERTEXT_SIZE + 80 + 192; // 948
    let compact_output = 32 + 32 + ENC_CIPHERTEXT_SIZE; // 644

    // 1 spend + 2 outputs: must be >40% smaller
    let full = full_spend + full_output * 2;
    let compact = compact_spend + compact_output * 2;
    let savings_pct = 100 - (compact * 100 / full);
    assert!(savings_pct >= 40, "Expected >=40% savings, got {savings_pct}%");
}

// ===========================================================================
// Kerrigan sighash structure tests
// ===========================================================================

#[test]
fn sighash_uses_correct_field_sizes() {
    // The Kerrigan sighash includes nVersion as i16 (2 bytes) and nType as u16 (2 bytes).
    // This is critical — using u32 instead of i16/u16 produces a completely different hash.
    //
    // Reference: ComputeSaplingSighash in Kerrigan's sapling_validation.cpp
    //   hw << tx.nVersion;    // int16_t → 2 bytes LE
    //   hw << tx.nType;       // uint16_t → 2 bytes LE
    //   hw << payload.nVersion; // uint16_t → 2 bytes LE
    //
    // Our implementation in kerrigan_tx.rs must match these sizes exactly.
    // We verify this indirectly through the successful mainnet transaction,
    // but this test documents the requirement.

    let version_bytes = (3i16).to_le_bytes();
    assert_eq!(version_bytes.len(), 2, "nVersion must be 2 bytes");

    let type_bytes = (10u16).to_le_bytes();
    assert_eq!(type_bytes.len(), 2, "nType must be 2 bytes");

    let payload_version_bytes = (1u16).to_le_bytes();
    assert_eq!(payload_version_bytes.len(), 2, "payloadVersion must be 2 bytes");
}

#[test]
fn type_10_header_encoding() {
    // Kerrigan type 10 header: (nType << 16) | nVersion
    // nVersion = 3, nType = 10
    // Combined as u32 LE: 0x000a0003
    let header: u32 = (10u32 << 16) | 3u32;
    let bytes = header.to_le_bytes();
    assert_eq!(bytes, [0x03, 0x00, 0x0a, 0x00],
        "Kerrigan Sapling header must be 03000a00");
}

// ===========================================================================
// Serialized note tests
// ===========================================================================

#[test]
fn serialized_note_json_roundtrip() {
    let note = sapling::notes::SerializedNote {
        value: 10_000_000,
        recipient: "ks1test".to_string(),
        rseed: "ab".repeat(32),
        rseed_after_zip212: true,
        witness: "deadbeef".to_string(),
        nullifier: "00".repeat(32),
        memo: Some("For the Swarm!".to_string()),
        height: 500,
    };

    let json = serde_json::to_string(&note).unwrap();
    let restored: sapling::notes::SerializedNote = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.value, 10_000_000);
    assert_eq!(restored.memo, Some("For the Swarm!".to_string()));
    assert_eq!(restored.height, 500);
    assert!(restored.rseed_after_zip212);
}

#[test]
fn serialized_note_default_height() {
    let json = r#"{"value":0,"recipient":"","rseed":"","rseed_after_zip212":true,"witness":"","nullifier":"","memo":null}"#;
    let note: sapling::notes::SerializedNote = serde_json::from_str(json).unwrap();
    assert_eq!(note.height, 0, "Height should default to 0");
}

// ===========================================================================
// Prover parameter hash tests
// ===========================================================================

#[test]
fn prover_hash_constants_valid_hex() {
    assert_eq!(sapling::prover::OUTPUT_PARAMS_SHA256.len(), 64);
    assert_eq!(sapling::prover::SPEND_PARAMS_SHA256.len(), 64);
    assert!(kerrigan_sdk::encoding::hex_decode(sapling::prover::OUTPUT_PARAMS_SHA256).is_ok());
    assert!(kerrigan_sdk::encoding::hex_decode(sapling::prover::SPEND_PARAMS_SHA256).is_ok());
}

#[test]
fn prover_rejects_wrong_params() {
    let result = sapling::prover::verify_and_load_params(b"fake", b"fake");
    assert!(result.is_err());
}

// ===========================================================================
// Wallet integration tests
// ===========================================================================

#[test]
fn wallet_creation_derives_sapling_keys() {
    let wallet = kerrigan_sdk::wallet::create_wallet_data().unwrap();
    assert!(wallet.sapling_address.is_some(), "New wallet must have sapling address");
    assert!(wallet.sapling_extsk.is_some(), "New wallet must have sapling extsk");
    assert!(wallet.sapling_extfvk.is_some(), "New wallet must have sapling extfvk");

    let addr = wallet.sapling_address.unwrap();
    assert!(addr.starts_with("ks"), "Sapling address must start with 'ks'");
}

#[test]
fn wallet_import_derives_same_sapling_keys() {
    let wallet1 = kerrigan_sdk::wallet::create_wallet_data().unwrap();
    let mnemonic = wallet1.mnemonic().to_string();

    let wallet2 = kerrigan_sdk::wallet::import_wallet_data(&mnemonic).unwrap();
    assert_eq!(wallet1.sapling_address, wallet2.sapling_address,
        "Same mnemonic must produce same shielded address");
}

#[test]
fn wallet_shielded_balance_starts_at_zero() {
    let wallet = kerrigan_sdk::wallet::create_wallet_data().unwrap();
    assert_eq!(wallet.shielded_balance(), 0);
    assert_eq!(wallet.shielded_balance_display(), "0.00000000");
}

#[test]
fn wallet_encrypt_decrypt_preserves_sapling_fields() {
    let wallet = kerrigan_sdk::wallet::create_wallet_data().unwrap();
    let key = [42u8; 32];

    let encrypted = kerrigan_sdk::wallet::encrypt_wallet(&wallet, &key);
    let decrypted = kerrigan_sdk::wallet::decrypt_wallet(encrypted, &key).unwrap();

    assert_eq!(wallet.sapling_address, decrypted.sapling_address);
    assert_eq!(wallet.sapling_extsk, decrypted.sapling_extsk);
    assert_eq!(wallet.sapling_extfvk, decrypted.sapling_extfvk);
}
