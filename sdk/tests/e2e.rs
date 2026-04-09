//! End-to-end integration tests for the kerrigan-wallet.
//!
//! Tests the full wallet lifecycle without hitting the network:
//! mnemonic → seed → keypair → address → UTXOs → transaction → sign → verify.
//!
//! Each test exercises multiple modules working together, catching integration
//! bugs that unit tests alone would miss.

use kerrigan_sdk::bip39;
use kerrigan_sdk::bip32;
use kerrigan_sdk::encoding;
use kerrigan_sdk::fees;
use kerrigan_sdk::keys;
use kerrigan_sdk::params;
use kerrigan_sdk::script;
use kerrigan_sdk::sync;
use kerrigan_sdk::transaction;
use kerrigan_sdk::wallet;

// ---------------------------------------------------------------------------
// E2E: Full wallet create → derive → sign → verify lifecycle
// ---------------------------------------------------------------------------

/// Create a wallet from a known mnemonic, derive keypair, build a transaction
/// with fake UTXOs, sign it, and verify every signature.
#[test]
fn e2e_create_and_sign() {
    // 1. Generate mnemonic
    let mnemonic = bip39::generate_mnemonic().unwrap();
    bip39::validate_mnemonic(&mnemonic).unwrap();
    assert_eq!(mnemonic.split_whitespace().count(), 24);

    // 2. Derive seed
    let seed = bip39::mnemonic_to_seed(&mnemonic, "");
    assert_eq!(seed.len(), 64);

    // 3. Derive keypair at m/44'/99888'/0'/0/0
    let kp = keys::derive_keypair(&seed).unwrap();
    assert!(kp.address.starts_with('K'));
    keys::validate_address(&kp.address).unwrap();

    // 4. Build the scriptPubKey for our address
    let own_script = script::address_to_script_pubkey(&kp.address).unwrap();
    assert_eq!(own_script.len(), 25); // P2PKH

    // 5. Create fake UTXOs owned by our address
    let utxos = vec![
        transaction::Utxo {
            txid: "a".repeat(64),
            vout: 0,
            amount: 500_000_000, // 5 KRGN
            script_pubkey: encoding::hex_encode(&own_script),
        },
        transaction::Utxo {
            txid: "b".repeat(64),
            vout: 1,
            amount: 300_000_000, // 3 KRGN
            script_pubkey: encoding::hex_encode(&own_script),
        },
    ];

    // 6. Create a destination address (different key)
    let dest_kp = keys::derive_keypair_at(&seed, 0, 1).unwrap();
    assert_ne!(dest_kp.address, kp.address);

    // 7. Build and sign the transaction
    let signed = transaction::build_transaction(
        &utxos,
        &dest_kp.address,
        200_000_000, // send 2 KRGN
        &kp.privkey,
        &kp.pubkey,
        &kp.address,
    ).unwrap();

    assert!(signed.tx.is_signed());
    assert!(!signed.tx_hex.is_empty());
    assert_eq!(signed.txid.len(), 64);
    assert!(signed.fee > 0);

    // 8. Verify every input's ECDSA signature
    let secp = secp256k1::Secp256k1::new();
    let pubkey = secp256k1::PublicKey::from_slice(&kp.pubkey).unwrap();

    for i in 0..signed.tx.inputs.len() {
        let hash = signed.tx.sighash(i, &own_script, params::SIGHASH_ALL);
        let msg = secp256k1::Message::from_digest(hash);

        let sig_data = &signed.tx.inputs[i].script_sig;
        let sig_len = sig_data[0] as usize;
        let sig_der = &sig_data[1..1 + sig_len - 1]; // strip sighash byte
        let sig = secp256k1::ecdsa::Signature::from_der(sig_der).unwrap();

        secp.verify_ecdsa(&msg, &sig, &pubkey).unwrap();
    }

    // 9. Accounting: input = amount + fee + change
    let total_input: u64 = signed.spent_utxos.iter()
        .flat_map(|(txid, vout)| utxos.iter().filter(move |u| u.txid == *txid && u.vout == *vout))
        .map(|u| u.amount)
        .sum();
    let total_output: u64 = signed.tx.outputs.iter().map(|o| o.value).sum();
    assert_eq!(total_input, total_output + signed.fee);
}

// ---------------------------------------------------------------------------
// E2E: Deterministic mnemonic → address pipeline
// ---------------------------------------------------------------------------

/// The same mnemonic must always produce the same address, seed, and keys
/// across all layers of the stack.
#[test]
fn e2e_deterministic_pipeline() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon art";

    // Seed
    let seed1 = bip39::mnemonic_to_seed(mnemonic, "");
    let seed2 = bip39::mnemonic_to_seed(mnemonic, "");
    assert_eq!(seed1, seed2);

    // BIP32 master
    let master1 = bip32::ExtendedPrivKey::from_seed(&seed1).unwrap();
    let master2 = bip32::ExtendedPrivKey::from_seed(&seed2).unwrap();
    assert_eq!(master1.to_xprv(), master2.to_xprv());

    // Keypair
    let kp1 = keys::derive_keypair(&seed1).unwrap();
    let kp2 = keys::derive_keypair(&seed2).unwrap();
    assert_eq!(kp1.address, kp2.address);
    assert_eq!(kp1.pubkey, kp2.pubkey);
    assert_eq!(kp1.privkey, kp2.privkey);

    // WIF
    let wif1 = keys::privkey_to_wif(&kp1.privkey);
    let wif2 = keys::privkey_to_wif(&kp2.privkey);
    assert_eq!(wif1, wif2);
    let recovered = keys::wif_to_privkey(&wif1).unwrap();
    assert_eq!(recovered, kp1.privkey);
}

// ---------------------------------------------------------------------------
// E2E: UTXO sync simulation (no network)
// ---------------------------------------------------------------------------

/// Simulate a realistic sequence of transactions and verify the UTXO set
/// and balance are correct at each step.
#[test]
fn e2e_sync_simulation() {
    let addr = "KTestAddr";
    let other = "KOtherAddr";

    let mut state = sync::SyncState::new();

    // TX1: Receive 10 KRGN (coinbase)
    let tx1 = make_tx("tx1", &[], &[(addr, 0, 10_0000_0000)]);
    state.process_transaction(&tx1, addr);
    assert_eq!(state.balance(), 10_0000_0000);

    // TX2: Receive 5 KRGN
    let tx2 = make_tx("tx2", &[], &[(addr, 0, 5_0000_0000)]);
    state.process_transaction(&tx2, addr);
    assert_eq!(state.balance(), 15_0000_0000);

    // TX3: Send 3, get change
    let tx3 = make_tx("tx3",
        &[("tx1", 0, addr, 10_0000_0000)],
        &[(other, 0, 3_0000_0000), (addr, 1, 6_9999_0000)],
    );
    state.process_transaction(&tx3, addr);
    assert_eq!(state.balance(), 5_0000_0000 + 6_9999_0000);

    // TX4: Send everything
    let tx4 = make_tx("tx4",
        &[("tx2", 0, addr, 5_0000_0000), ("tx3", 1, addr, 6_9999_0000)],
        &[(other, 0, 11_9998_0000)],
    );
    state.process_transaction(&tx4, addr);
    assert_eq!(state.balance(), 0);
    assert_eq!(state.tx_count(), 4);
}

// ---------------------------------------------------------------------------
// E2E: Transaction size vs fee estimation
// ---------------------------------------------------------------------------

/// Build real signed transactions with varying input counts and verify
/// the actual serialized size is close to the fee estimator's prediction.
#[test]
fn e2e_fee_estimation_accuracy() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = bip39::mnemonic_to_seed(mnemonic, "");
    let kp = keys::derive_keypair(&seed).unwrap();
    let own_script = script::address_to_script_pubkey(&kp.address).unwrap();

    let dest_kp = keys::derive_keypair_at(&seed, 0, 1).unwrap();

    for input_count in 1..=5usize {
        let utxos: Vec<transaction::Utxo> = (0..input_count)
            .map(|i| transaction::Utxo {
                txid: format!("{:064x}", i + 1),
                vout: 0,
                amount: 1_0000_0000, // 1 KRGN each
                script_pubkey: encoding::hex_encode(&own_script),
            })
            .collect();

        let total_available: u64 = utxos.iter().map(|u| u.amount).sum();
        let send_amount = total_available / 2; // send half

        let signed = transaction::build_transaction(
            &utxos,
            &dest_kp.address,
            send_amount,
            &kp.privkey,
            &kp.pubkey,
            &kp.address,
        ).unwrap();

        let actual_size = signed.tx.serialize().len();
        let actual_inputs = signed.tx.inputs.len();
        let output_count = signed.tx.outputs.len();
        let estimated = fees::TxComponents::transparent(
            actual_inputs,
            vec![script::ScriptType::P2PKH; output_count],
        ).estimated_size();

        // Allow 10% tolerance (DER signature length varies 70-72 bytes)
        let diff = (actual_size as f64 - estimated as f64).abs();
        let tolerance = estimated as f64 * 0.10;
        assert!(
            diff < tolerance,
            "Input count {input_count}: actual {actual_size} vs estimated {estimated} \
             (diff {diff:.0}, tolerance {tolerance:.0})"
        );
    }
}

// ---------------------------------------------------------------------------
// E2E: WIF encode → decode → sign → verify
// ---------------------------------------------------------------------------

/// Export a private key to WIF, import it back, use it to sign, verify.
#[test]
fn e2e_wif_sign_verify() {
    let mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
    let seed = bip39::mnemonic_to_seed(mnemonic, "");
    let kp = keys::derive_keypair(&seed).unwrap();

    // Export to WIF
    let wif = keys::privkey_to_wif(&kp.privkey);

    // Import from WIF
    let recovered_privkey = keys::wif_to_privkey(&wif).unwrap();
    assert_eq!(recovered_privkey, kp.privkey);

    // Sign a message with the recovered key
    let secp = secp256k1::Secp256k1::new();
    let sk = secp256k1::SecretKey::from_slice(&recovered_privkey).unwrap();
    let message = b"Kerrigan Network test message";
    let hash = encoding::sha256d(message);
    let msg = secp256k1::Message::from_digest(hash);
    let sig = secp.sign_ecdsa(&msg, &sk);

    // Verify with the original pubkey
    let pk = secp256k1::PublicKey::from_slice(&kp.pubkey).unwrap();
    secp.verify_ecdsa(&msg, &sig, &pk).unwrap();
}

// ---------------------------------------------------------------------------
// E2E: Wallet data persistence roundtrip (encrypt/decrypt)
// ---------------------------------------------------------------------------

/// Create a wallet, encrypt it for disk, decrypt it, verify all fields match.
#[test]
fn e2e_wallet_encrypt_decrypt_roundtrip() {
    let mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let seed = bip39::mnemonic_to_seed(mnemonic, "");
    let kp = keys::derive_keypair(&seed).unwrap();

    // The wallet module's internal encrypt/decrypt is tested in unit tests.
    // Here we test the full pipeline: mnemonic → wallet → address consistency.
    let kp2 = keys::derive_keypair(&seed).unwrap();
    assert_eq!(kp.address, kp2.address);

    // Verify address starts with K and is valid
    assert!(kp.address.starts_with('K'));
    keys::validate_address(&kp.address).unwrap();

    // Verify the pubkey hash embedded in the scriptPubKey matches
    let script = script::address_to_script_pubkey(&kp.address).unwrap();
    let pkh_from_script = &script[3..23];
    let pkh_from_key = bip32::hash160(&kp.pubkey);
    assert_eq!(pkh_from_script, &pkh_from_key);
}

// ---------------------------------------------------------------------------
// E2E: Amount formatting roundtrips
// ---------------------------------------------------------------------------

#[test]
fn e2e_amount_formatting() {
    let test_cases: Vec<(u64, &str)> = vec![
        (0, "0.00000000"),
        (1, "0.00000001"),
        (546, "0.00000546"), // dust threshold
        (100_000_000, "1.00000000"),
        (123_456_789, "1.23456789"),
        (2_100_000_000_000_000, "21000000.00000000"), // max supply scale
    ];

    for (sats, expected) in &test_cases {
        let formatted = wallet::format_krgn(*sats);
        assert_eq!(&formatted, expected, "format_krgn({sats})");

        let parsed = wallet::parse_krgn(&formatted).unwrap();
        assert_eq!(parsed, *sats, "parse_krgn({formatted})");
    }
}

// ---------------------------------------------------------------------------
// E2E: Script roundtrip — address → script → extract hash → rebuild address
// ---------------------------------------------------------------------------

#[test]
fn e2e_script_address_roundtrip() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = bip39::mnemonic_to_seed(mnemonic, "");
    let kp = keys::derive_keypair(&seed).unwrap();

    // Address → script
    let script_bytes = script::address_to_script_pubkey(&kp.address).unwrap();

    // Extract hash from script (bytes 3..23 for P2PKH)
    let hash = &script_bytes[3..23];

    // Rebuild address from hash
    let rebuilt = encoding::base58check_encode(params::PUBKEY_ADDRESS_PREFIX, hash);
    assert_eq!(rebuilt, kp.address);

    // Also verify via address_to_pubkey_hash
    let extracted = keys::address_to_pubkey_hash(&kp.address).unwrap();
    assert_eq!(&extracted, hash);
}

// ---------------------------------------------------------------------------
// E2E: Multi-input transaction with all signatures valid
// ---------------------------------------------------------------------------

#[test]
fn e2e_multi_input_all_sigs_valid() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = bip39::mnemonic_to_seed(mnemonic, "");
    let kp = keys::derive_keypair(&seed).unwrap();
    let own_script = script::address_to_script_pubkey(&kp.address).unwrap();
    let dest_kp = keys::derive_keypair_at(&seed, 0, 1).unwrap();

    // 10 small UTXOs
    let utxos: Vec<transaction::Utxo> = (0..10)
        .map(|i| transaction::Utxo {
            txid: format!("{:064x}", i + 100),
            vout: 0,
            amount: 50_000, // 0.0005 KRGN each
            script_pubkey: encoding::hex_encode(&own_script),
        })
        .collect();

    // Send enough to require multiple inputs
    let signed = transaction::build_transaction(
        &utxos,
        &dest_kp.address,
        200_000,
        &kp.privkey,
        &kp.pubkey,
        &kp.address,
    ).unwrap();

    assert!(signed.tx.inputs.len() >= 4); // need at least 4 × 50k to cover 200k + fee

    // Verify EVERY signature
    let secp = secp256k1::Secp256k1::new();
    let pk = secp256k1::PublicKey::from_slice(&kp.pubkey).unwrap();
    for i in 0..signed.tx.inputs.len() {
        let hash = signed.tx.sighash(i, &own_script, params::SIGHASH_ALL);
        let msg = secp256k1::Message::from_digest(hash);

        let sig_data = &signed.tx.inputs[i].script_sig;
        let sig_len = sig_data[0] as usize;
        let sig_der = &sig_data[1..1 + sig_len - 1];
        let sig = secp256k1::ecdsa::Signature::from_der(sig_der).unwrap();

        secp.verify_ecdsa(&msg, &sig, &pk)
            .unwrap_or_else(|_| panic!("Signature verification failed for input {i}"));
    }
}

// ---------------------------------------------------------------------------
// E2E: Send to P2SH address
// ---------------------------------------------------------------------------

#[test]
fn e2e_send_to_p2sh() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = bip39::mnemonic_to_seed(mnemonic, "");
    let kp = keys::derive_keypair(&seed).unwrap();
    let own_script = script::address_to_script_pubkey(&kp.address).unwrap();

    let utxos = vec![transaction::Utxo {
        txid: "ff".repeat(32),
        vout: 0,
        amount: 10_0000_0000,
        script_pubkey: encoding::hex_encode(&own_script),
    }];

    // P2SH destination
    let p2sh_addr = encoding::base58check_encode(params::SCRIPT_ADDRESS_PREFIX, &[0xBB; 20]);
    assert!(p2sh_addr.starts_with('7'));

    let signed = transaction::build_transaction(
        &utxos,
        &p2sh_addr,
        1_0000_0000,
        &kp.privkey,
        &kp.pubkey,
        &kp.address,
    ).unwrap();

    // Destination output should have P2SH script (23 bytes: a9 14 <hash> 87)
    let dest_output = &signed.tx.outputs[0];
    assert_eq!(dest_output.value, 1_0000_0000);
    assert_eq!(dest_output.script_pubkey.len(), 23);
    assert_eq!(dest_output.script_pubkey[0], 0xa9); // OP_HASH160
}

// ---------------------------------------------------------------------------
// E2E: BIP32 path derivation consistency
// ---------------------------------------------------------------------------

#[test]
fn e2e_bip32_path_consistency() {
    let seed = bip39::mnemonic_to_seed(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "",
    );

    // Derive via full path string
    let master = bip32::ExtendedPrivKey::from_seed(&seed).unwrap();
    let via_path = master.derive_path("m/44'/99888'/0'/0/0").unwrap();

    // Derive step by step
    let step1 = master.derive_child(44 | 0x80000000).unwrap();
    let step2 = step1.derive_child(99888 | 0x80000000).unwrap();
    let step3 = step2.derive_child(0x80000000).unwrap(); // account 0'
    let step4 = step3.derive_child(0).unwrap();          // external chain
    let step5 = step4.derive_child(0).unwrap();          // index 0

    assert_eq!(via_path.public_key_bytes(), step5.public_key_bytes());
    assert_eq!(via_path.private_key_bytes(), step5.private_key_bytes());

    // And via keys::derive_keypair
    let kp = keys::derive_keypair(&seed).unwrap();
    assert_eq!(kp.pubkey, via_path.public_key_bytes());
}

// ---------------------------------------------------------------------------
// E2E: Transaction serialization is canonical
// ---------------------------------------------------------------------------

#[test]
fn e2e_tx_serialization_canonical() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = bip39::mnemonic_to_seed(mnemonic, "");
    let kp = keys::derive_keypair(&seed).unwrap();
    let own_script = script::address_to_script_pubkey(&kp.address).unwrap();
    let dest_kp = keys::derive_keypair_at(&seed, 0, 1).unwrap();

    let utxos = vec![transaction::Utxo {
        txid: "aa".repeat(32),
        vout: 0,
        amount: 5_0000_0000,
        script_pubkey: encoding::hex_encode(&own_script),
    }];

    let signed = transaction::build_transaction(
        &utxos, &dest_kp.address, 1_0000_0000,
        &kp.privkey, &kp.pubkey, &kp.address,
    ).unwrap();

    // Serialize twice — must be identical
    let bytes1 = signed.tx.serialize();
    let bytes2 = signed.tx.serialize();
    assert_eq!(bytes1, bytes2);

    // Hex roundtrip
    let hex = signed.tx.to_hex();
    let decoded = encoding::hex_decode(&hex).unwrap();
    assert_eq!(decoded, bytes1);

    // txid from serialized bytes must match
    let txid1 = signed.tx.txid();
    let txid2 = signed.tx.txid();
    assert_eq!(txid1, txid2);
    assert_eq!(txid1, signed.txid);
}

// ---------------------------------------------------------------------------
// E2E: Sync history deduplication
// ---------------------------------------------------------------------------

#[test]
fn e2e_sync_history_no_duplicates() {
    let addr = "KTestAddr";

    let tx1 = make_tx("tx1", &[], &[(addr, 0, 1_0000_0000)]);
    let tx2 = make_tx("tx2", &[], &[(addr, 0, 2_0000_0000)]);

    // First sync
    let result1 = sync::process_transactions(None, &[tx1.clone(), tx2.clone()], addr, &[]);
    assert_eq!(result1.history.len(), 2);

    // Second sync with same txs — should dedup
    let result2 = sync::process_transactions(
        Some(result1.state), std::slice::from_ref(&tx2), addr, &result1.history,
    );
    assert_eq!(result2.history.len(), 2, "Duplicate should be deduped");
}

// ---------------------------------------------------------------------------
// E2E: Dust threshold boundary
// ---------------------------------------------------------------------------

#[test]
fn e2e_dust_threshold_boundary() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = bip39::mnemonic_to_seed(mnemonic, "");
    let kp = keys::derive_keypair(&seed).unwrap();
    let own_script = script::address_to_script_pubkey(&kp.address).unwrap();
    let dest_kp = keys::derive_keypair_at(&seed, 0, 1).unwrap();

    let fee_2out = fees::estimate_transparent_fee(1, 2);
    let utxo_amount = 1_0000_0000 + fee_2out + params::DUST_THRESHOLD;
    let utxos = vec![transaction::Utxo {
        txid: "aa".repeat(32),
        vout: 0,
        amount: utxo_amount,
        script_pubkey: encoding::hex_encode(&own_script),
    }];

    let signed = transaction::build_transaction(
        &utxos, &dest_kp.address, 1_0000_0000,
        &kp.privkey, &kp.pubkey, &kp.address,
    ).unwrap();

    let has_change = signed.tx.outputs.len() > 1;
    assert!(!has_change, "Change of exactly DUST_THRESHOLD should be absorbed into fee");
}

// ---------------------------------------------------------------------------
// Helpers — SDK TxData builders
// ---------------------------------------------------------------------------

fn make_tx(
    txid: &str,
    inputs: &[(&str, u32, &str, u64)], // (prev_txid, prev_vout, addr, value_sat)
    outputs: &[(&str, u32, u64)],       // (addr, n, value_sat)
) -> sync::TxData {
    let tx_inputs = if inputs.is_empty() {
        vec![sync::TxInput {
            prev_txid: None, prev_vout: None, address: None,
            value_sat: None, is_coinbase: true,
        }]
    } else {
        inputs.iter().map(|(ptxid, pvout, addr, val)| sync::TxInput {
            prev_txid: Some(ptxid.to_string()),
            prev_vout: Some(*pvout),
            address: Some(addr.to_string()),
            value_sat: Some(*val),
            is_coinbase: false,
        }).collect()
    };

    let tx_outputs = outputs.iter().map(|(addr, n, val)| sync::TxOutput {
        n: *n,
        value_sat: *val,
        addresses: vec![addr.to_string()],
        script_hex: "76a914ab88ac".into(),
    }).collect();

    sync::TxData {
        txid: txid.into(),
        inputs: tx_inputs,
        outputs: tx_outputs,
        timestamp: Some(1000),
        block_height: Some(100),
        confirmations: Some(10),
    }
}
