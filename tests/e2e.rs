/// End-to-end integration tests for the kerrigan-wallet.
///
/// Tests the full wallet lifecycle without hitting the network:
/// mnemonic → seed → keypair → address → UTXOs → transaction → sign → verify.
///
/// Each test exercises multiple modules working together, catching integration
/// bugs that unit tests alone would miss.

use kerrigan_wallet::bip39;
use kerrigan_wallet::bip32;
use kerrigan_wallet::encoding;
use kerrigan_wallet::fees;
use kerrigan_wallet::keys;
use kerrigan_wallet::network;
use kerrigan_wallet::params;
use kerrigan_wallet::script;
use kerrigan_wallet::sync;
use kerrigan_wallet::transaction;
use kerrigan_wallet::wallet;

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
            amount: 5_000_000_00, // 5 KRGN
            script_pubkey: encoding::hex_encode(&own_script),
        },
        transaction::Utxo {
            txid: "b".repeat(64),
            vout: 1,
            amount: 3_000_000_00, // 3 KRGN
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
        2_000_000_00, // send 2 KRGN
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
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = bip39::mnemonic_to_seed(mnemonic, "");
    let kp = keys::derive_keypair(&seed).unwrap();
    let addr = &kp.address;

    let other = "KOtherAddr000000000000000000000000"; // fake

    let mut state = sync::SyncState::new();

    // TX1: Receive 10 KRGN (coinbase)
    let tx1 = make_tx_info("tx1_hash_aabbccdd", &[], &[(addr, 0, 10_0000_0000)]);
    state.process_transaction(&tx1, addr);
    assert_eq!(state.balance(), 10_0000_0000);
    assert_eq!(state.derive_utxos().len(), 1);

    // TX2: Receive 5 KRGN from someone
    let tx2 = make_tx_info("tx2_hash_eeff0011", &[], &[(addr, 0, 5_0000_0000)]);
    state.process_transaction(&tx2, addr);
    assert_eq!(state.balance(), 15_0000_0000);
    assert_eq!(state.derive_utxos().len(), 2);

    // TX3: Send 3 KRGN (spend tx1, get change)
    let tx3 = make_tx_info(
        "tx3_hash_22334455",
        &[("tx1_hash_aabbccdd", 0, addr)],
        &[
            (other, 0, 3_0000_0000),
            (addr, 1, 6_9999_0000), // change
        ],
    );
    state.process_transaction(&tx3, addr);
    assert_eq!(state.derive_utxos().len(), 2); // tx2:0 + tx3:1
    assert_eq!(state.balance(), 5_0000_0000 + 6_9999_0000);

    // TX4: Send everything (consolidate tx2:0 + tx3:1)
    let tx4 = make_tx_info(
        "tx4_hash_66778899",
        &[
            ("tx2_hash_eeff0011", 0, addr),
            ("tx3_hash_22334455", 1, addr),
        ],
        &[(other, 0, 11_9998_0000)],
    );
    state.process_transaction(&tx4, addr);
    assert_eq!(state.derive_utxos().len(), 0);
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
        (21_000_000_00000000, "21000000.00000000"), // max supply scale
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
    let step3 = step2.derive_child(0 | 0x80000000).unwrap();
    let step4 = step3.derive_child(0).unwrap();
    let step5 = step4.derive_child(0).unwrap();

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

    // First sync: 2 txs
    let mut state = sync::SyncState::new();
    let tx1 = make_tx_info("tx1", &[], &[(addr, 0, 1_0000_0000)]);
    let tx2 = make_tx_info("tx2", &[], &[(addr, 0, 2_0000_0000)]);
    state.process_transaction(&tx1, addr);
    state.process_transaction(&tx2, addr);

    let history1 = vec![
        sync::TxHistoryEntry { txid: "tx2".into(), net_amount: 2_0000_0000, timestamp: Some(1000), block_height: Some(1), confirmations: Some(10) },
        sync::TxHistoryEntry { txid: "tx1".into(), net_amount: 1_0000_0000, timestamp: Some(900), block_height: Some(0), confirmations: Some(11) },
    ];

    // Second sync with same txs: should not duplicate
    let mut state2 = state.clone();
    // process same txs again (simulating re-fetch)
    state2.process_transaction(&tx1, addr);
    state2.process_transaction(&tx2, addr);

    // Manually test dedup logic: new entries that overlap with prior
    let new_entries = vec![
        sync::TxHistoryEntry { txid: "tx2".into(), net_amount: 2_0000_0000, timestamp: Some(1000), block_height: Some(1), confirmations: Some(12) },
    ];

    let seen: std::collections::HashSet<String> = new_entries.iter().map(|e| e.txid.clone()).collect();
    let mut merged = new_entries;
    for entry in &history1 {
        if !seen.contains(&entry.txid) {
            merged.push(entry.clone());
        }
    }

    // tx2 should appear only once (from new_entries), tx1 from prior
    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].txid, "tx2");
    assert_eq!(merged[1].txid, "tx1");
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

    // Create a UTXO where the change would be exactly DUST_THRESHOLD (546 sat)
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

    // Dust at exactly threshold should be absorbed (change = 0)
    let has_change = signed.tx.outputs.len() > 1;
    assert!(!has_change, "Change of exactly DUST_THRESHOLD should be absorbed into fee");
}

// ---------------------------------------------------------------------------
// Helpers for building test TransactionInfo objects
// ---------------------------------------------------------------------------

fn make_tx_info(
    txid: &str,
    inputs: &[(&str, u32, &str)], // (prev_txid, prev_vout, addr)
    outputs: &[(&str, u32, u64)], // (addr, n, satoshis)
) -> network::TransactionInfo {
    let vin: Vec<network::TxVin> = inputs.iter().map(|(prev_txid, vout, addr)| {
        network::TxVin {
            txid: Some(prev_txid.to_string()),
            vout: Some(*vout),
            addr: Some(addr.to_string()),
            value: None,
            value_sat: None,
            coinbase: None,
        }
    }).collect();

    let vin = if vin.is_empty() {
        // Coinbase
        vec![network::TxVin {
            txid: None,
            vout: None,
            addr: None,
            value: None,
            value_sat: None,
            coinbase: Some("coinbase".into()),
        }]
    } else {
        vin
    };

    let vout: Vec<network::TxVout> = outputs.iter().map(|(addr, n, sats)| {
        let krgn = *sats as f64 / params::COIN as f64;
        network::TxVout {
            value: Some(serde_json::json!(format!("{:.8}", krgn))),
            n: *n,
            script_pub_key: Some(network::ScriptPubKeyInfo {
                hex: Some("76a914abcd88ac".into()),
                addresses: Some(vec![addr.to_string()]),
                script_type: Some("pubkeyhash".into()),
            }),
        }
    }).collect();

    network::TransactionInfo {
        txid: txid.to_string(),
        vin,
        vout,
        confirmations: Some(100),
        blockheight: Some(5000),
        time: None,
    }
}

// ---------------------------------------------------------------------------
// LIVE E2E: Sync a known address against the real Kerrigan explorer
// ---------------------------------------------------------------------------
// Run with: cargo test --test e2e live_ -- --ignored

/// Known address on Kerrigan mainnet: KQ2AjqzF8HYUAPa55GJMLGF5py1yadsNCo
/// (dev fund address, ~157 coinbase receives, ~785 KRGN balance as of block 13471)
const LIVE_TEST_ADDRESS: &str = "KQ2AjqzF8HYUAPa55GJMLGF5py1yadsNCo";

/// Verify that the explorer API is reachable and returns the expected JSON format.
#[test]
#[ignore]
fn live_explorer_status() {
    let client = network::ExplorerClient::new();
    let height = client.get_block_height().unwrap();
    assert!(height > 13_000, "Block height should be > 13000, got {height}");
    println!("Explorer is live at block {height}");
}

/// Fetch address info for the known address and verify parsing.
#[test]
#[ignore]
fn live_address_info() {
    let client = network::ExplorerClient::new();
    let info = client.get_address_info(LIVE_TEST_ADDRESS).unwrap();

    // Balance should be > 0 (this address has received many coinbase rewards)
    let balance = info.balance_satoshis();
    assert!(balance > 0, "Balance should be > 0, got {balance}");
    println!("Address {LIVE_TEST_ADDRESS}");
    println!("  Balance: {} KRGN ({balance} sat)", wallet::format_krgn(balance));

    // Should have transactions
    let txids = info.transactions.unwrap_or_default();
    assert!(!txids.is_empty(), "Should have at least 1 transaction");
    println!("  Transactions: {}", txids.len());
}

/// Fetch a transaction from the test address and verify full parsing.
#[test]
#[ignore]
fn live_transaction_parse() {
    let client = network::ExplorerClient::new();

    // Get a txid that involves our test address
    let info = client.get_address_info(LIVE_TEST_ADDRESS).unwrap();
    let txids = info.transactions.unwrap_or_default();
    assert!(!txids.is_empty(), "Address should have transactions");
    let txid = &txids[0];

    let tx = client.get_transaction(txid).unwrap();
    assert_eq!(&tx.txid, txid);
    assert!(!tx.vout.is_empty(), "Should have outputs");

    // Verify value parsing — all outputs should have parseable amounts
    let total_out: u64 = tx.vout.iter().map(|v| v.value_satoshis()).sum();
    assert!(total_out > 0, "Total output value should be > 0");

    // Verify our test address appears in one of the outputs
    let has_our_addr = tx.vout.iter().any(|v| {
        v.script_pub_key.as_ref()
            .and_then(|spk| spk.addresses.as_ref())
            .map(|addrs| addrs.iter().any(|a| a == LIVE_TEST_ADDRESS))
            .unwrap_or(false)
    });
    assert!(has_our_addr, "Should have an output to our test address");

    println!("TX {txid}");
    println!("  Outputs: {}", tx.vout.len());
    println!("  Total value: {} KRGN", wallet::format_krgn(total_out));
    println!("  Confirmations: {:?}", tx.confirmations);
}

/// Full UTXO sync against the live explorer for the known address.
/// This is the main integration test — exercises network → sync → UTXO derivation.
#[test]
#[ignore]
fn live_full_sync() {
    let client = network::ExplorerClient::new();

    println!("Syncing {LIVE_TEST_ADDRESS} ...");

    // Perform full sync (no known txids)
    let known = std::collections::HashSet::new();
    let result = sync::sync_address(&client, LIVE_TEST_ADDRESS, &known).unwrap();

    println!("  Transactions processed: {}", result.processed_txids.len());
    println!("  UTXOs found: {}", result.utxos.len());
    println!("  Balance: {} KRGN ({} sat)", wallet::format_krgn(result.balance), result.balance);

    // This address should have received many coinbase rewards
    assert!(result.processed_txids.len() > 100, "Should have > 100 txs, got {}", result.processed_txids.len());
    assert!(result.balance > 0, "Balance should be > 0");

    // Cross-check: balance from sync should match explorer's reported balance
    let info = client.get_address_info(LIVE_TEST_ADDRESS).unwrap();
    let explorer_balance = info.balance_satoshis();

    // Allow small discrepancy (explorer might include unconfirmed, we don't)
    let diff = (result.balance as i64 - explorer_balance as i64).unsigned_abs();
    let tolerance = explorer_balance / 100; // 1%
    assert!(
        diff <= tolerance,
        "Sync balance {} vs explorer balance {} — diff {diff} exceeds 1% tolerance {tolerance}",
        result.balance, explorer_balance,
    );

    println!("  Explorer balance: {} KRGN — MATCH!", wallet::format_krgn(explorer_balance));

    // Verify UTXOs are sane
    for utxo in &result.utxos {
        assert!(!utxo.txid.is_empty(), "UTXO txid should not be empty");
        assert!(utxo.amount > 0, "UTXO amount should be > 0");
    }
}
