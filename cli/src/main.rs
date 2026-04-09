/// Kerrigan Network light wallet CLI.
///
/// "My stare alone would reduce you to ashes."
///   — Sarah Kerrigan, Queen of Blades
#[allow(dead_code)]
mod network;
mod sapling_params;
mod sapling_sync;
mod storage;
mod sync_service;
#[allow(dead_code)]
mod term;

use std::io::{self, Write};
use std::process;

use kerrigan_sdk::keys;
use kerrigan_sdk::sync::TxHistoryEntry;
use kerrigan_sdk::transaction::SignedTransaction;
use kerrigan_sdk::wallet::{self, WalletData, WalletError};
use term::Spinner;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(0);
    }

    let result = match args[1].as_str() {
        "create" => cmd_create(),
        "import" => cmd_import(),
        "export" => cmd_export(),
        "address" => cmd_address(),
        "balance" => cmd_balance(),
        "send" => cmd_send(&args[2..]),
        "history" => cmd_history(&args[2..]),
        "sync" => cmd_sync(),
        "help" | "--help" | "-h" => { print_usage(); Ok(()) }
        "version" | "--version" | "-V" => { print_version(); Ok(()) }
        other => {
            eprintln!("{}", term::red(&format!("Unknown command: {other}")));
            println!();
            print_usage();
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("{} {e}", term::red_bold("Error:"));
        process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Usage / version
// ---------------------------------------------------------------------------

fn print_usage() {
    println!("{}", term::purple_bold("kerrigan-wallet"));
    println!("{}", term::dim(&format!("v{} — Kerrigan Network light wallet", env!("CARGO_PKG_VERSION"))));
    println!();
    println!("{}", term::bold("Usage:"));
    println!("  kerrigan-wallet {}", term::dim("<command> [args]"));
    println!();
    println!("{}", term::bold("Commands:"));
    println!("  {}            Generate a new wallet", term::purple("create"));
    println!("  {}            Import wallet from mnemonic", term::purple("import"));
    println!("  {}            Display wallet mnemonic", term::purple("export"));
    println!("  {}           Show public + private addresses", term::purple("address"));
    println!("  {}           Sync and show balances", term::purple("balance"));
    println!("  {} {} {} {} Send KRGN", term::purple("send"), term::dim("<public|private>"), term::dim("<addr>"), term::dim("<amt|max>"));
    println!("  {} {}  Transaction history", term::purple("history"), term::dim("[page|all]"));
    println!("  {}              Force full resync", term::purple("sync"));
    println!("  {}           Show version", term::purple("version"));
}

fn print_version() {
    println!("{} v{}", term::purple_bold("kerrigan-wallet"), env!("CARGO_PKG_VERSION"));
}

// ---------------------------------------------------------------------------
// Interactive I/O helpers
// ---------------------------------------------------------------------------

fn read_line(prompt: &str) -> String {
    print!("{prompt}");
    let _ = io::stdout().flush();
    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);
    input.trim().to_string()
}

fn confirm(prompt: &str, expected: &str) -> bool {
    let input = read_line(prompt);
    input == expected
}

/// Run a sync with a spinner, save the wallet, and return the result.
fn sync_with_spinner(wallet_data: &mut wallet::WalletData) -> Result<kerrigan_sdk::sync::SyncResult, WalletError> {
    let spinner = Spinner::start("Syncing");

    // Fetch shield data in a background thread while transparent syncs on main thread
    let shield_fetch_handle = if wallet_data.sapling_extfvk.is_some() {
        let start_block = if wallet_data.sapling_last_block > 0 {
            wallet_data.sapling_last_block + 1
        } else {
            kerrigan_sdk::sapling::network::SAPLING_ACTIVATION_HEIGHT
        };
        Some(std::thread::spawn(move || {
            crate::sapling_sync::fetch_shield_stream(start_block)
        }))
    } else {
        None
    };

    // Transparent sync on main thread (in parallel with shield fetch)
    let spinner_ref = std::sync::Arc::new(spinner);
    let spinner_for_closure = spinner_ref.clone();

    let result = crate::sync_service::sync_wallet(wallet_data, move |done, total| {
        if total == 0 && done == 0 {
            spinner_for_closure.set_progress(0.0, Some("Fetching address"));
        } else if done == 0 {
            spinner_for_closure.set_progress(0.0, Some("Syncing"));
        } else {
            spinner_for_closure.set_progress(done as f64 / total as f64, Some("Syncing"));
        }
    });

    let spinner = std::sync::Arc::try_unwrap(spinner_ref).ok();

    match &result {
        Ok(r) => {
            if let Some(s) = spinner {
                if r.new_tx_count == 0 {
                    s.finish_with("No new transactions");
                } else {
                    s.finish_with(&format!("Synced {} new transaction{}", r.new_tx_count,
                        if r.new_tx_count == 1 { "" } else { "s" }));
                }
            }
        }
        Err(e) => {
            if let Some(s) = spinner {
                s.finish_err(&format!("Sync failed: {e}"));
            }
        }
    }

    // Apply shield data (fetch already completed in background)
    if let Some(handle) = shield_fetch_handle {
        let shield_spinner = Spinner::start("Processing shield");
        match handle.join() {
            Ok(Ok(stream_bytes)) => {
                match crate::sapling_sync::apply_shield_data(wallet_data, &stream_bytes) {
                    Ok(r) => {
                        if r.new_notes == 0 && r.spent == 0 && r.sent == 0 {
                            shield_spinner.finish_with("No new shield activity");
                        } else {
                            shield_spinner.finish_with(&format!(
                                "{} received, {} spent, {} sent",
                                r.new_notes, r.spent, r.sent,
                            ));
                        }
                    }
                    Err(e) => shield_spinner.finish_err(&format!("Shield sync: {e}")),
                }
            }
            Ok(Err(e)) => shield_spinner.finish_err(&format!("Shield fetch: {e}")),
            Err(_) => shield_spinner.finish_err("Shield fetch thread panicked"),
        }
    }

    crate::storage::save_wallet(wallet_data)?;
    result
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_create() -> Result<(), WalletError> {
    let wallet_data = crate::storage::create_wallet()?;

    println!();
    println!("  {}", term::purple_bold("⚡ Welcome to the Swarm. ⚡"));
    println!();
    println!("  {}", term::dim("Your 24-word recovery phrase:"));
    println!();

    let words: Vec<&str> = wallet_data.mnemonic().split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        print!("   {}{:<12}",
            term::dim(&format!("{:>2}. ", i + 1)),
            term::bold(word),
        );
        if (i + 1) % 4 == 0 { println!(); }
    }

    println!();
    println!("  {} Write these down. They are the {} way to recover your wallet.",
        term::yellow("⚠"),
        term::bold("ONLY"),
    );
    println!();
    term::divider(50);
    println!();
    println!("  {} {}",
        term::dim("Address:"),
        term::purple_bold(&wallet_data.address),
    );
    println!();

    Ok(())
}

fn cmd_import() -> Result<(), WalletError> {
    if crate::storage::wallet_exists() {
        return Err(WalletError::Other("Wallet already exists.".into()));
    }

    println!();
    println!("  {}", term::bold("Enter your 24-word recovery phrase:"));
    let mnemonic = read_line(&format!("  {} ", term::purple(">")));

    if mnemonic.is_empty() {
        return Err(WalletError::InvalidMnemonic("empty input".into()));
    }

    let wallet_data = crate::storage::import_wallet(&mnemonic)?;

    println!();
    println!("  {} Wallet imported.", term::green("✓"));
    println!("  {} {}", term::dim("Address:"), term::purple_bold(&wallet_data.address));
    println!();
    println!("  {} Run {} to scan for existing transactions.",
        term::dim("Tip:"),
        term::purple("kerrigan-wallet sync"),
    );
    println!();

    Ok(())
}

fn cmd_export() -> Result<(), WalletError> {
    let wallet_data = crate::storage::load_wallet()?;

    println!();
    println!("  {} Your recovery phrase grants {} access to your funds.",
        term::yellow("⚠"),
        term::red_bold("FULL"),
    );
    println!("  {}", term::dim("Never share it with anyone."));
    println!();

    if !confirm(&format!("  Type '{}' to continue: ", term::bold("I understand")), "I understand") {
        println!("  {}", term::dim("Cancelled."));
        return Ok(());
    }

    println!();
    let words: Vec<&str> = wallet_data.mnemonic().split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        print!("   {}{:<12}",
            term::dim(&format!("{:>2}. ", i + 1)),
            term::bold(word),
        );
        if (i + 1) % 4 == 0 { println!(); }
    }
    println!();

    Ok(())
}

fn cmd_address() -> Result<(), WalletError> {
    let wallet_data = crate::storage::load_wallet()?;
    println!();
    println!("  {} {}", term::dim("Public: "), term::purple_bold(&wallet_data.address));
    if let Some(ref addr) = wallet_data.sapling_address {
        println!("  {} {}", term::dim("Private:"), term::purple_bold(addr));
    }
    println!();
    Ok(())
}

fn cmd_balance() -> Result<(), WalletError> {
    let mut wallet_data = crate::storage::load_wallet()?;

    println!();
    let _ = sync_with_spinner(&mut wallet_data);

    let public_bal = wallet_data.balance_display();
    let private_bal = wallet_data.shielded_balance_display();
    let utxo_count = wallet_data.utxos.len();
    let note_count = wallet_data.unspent_notes.len();

    println!();
    println!("  {} {} KRGN {}",
        term::dim("Public: "),
        term::green_bold(&public_bal),
        term::dim(&format!("({utxo_count} UTXO{})", if utxo_count == 1 { "" } else { "s" })),
    );
    println!("  {} {} KRGN {}",
        term::dim("Private:"),
        term::green_bold(&private_bal),
        term::dim(&format!("({note_count} note{})", if note_count == 1 { "" } else { "s" })),
    );

    let total = wallet_data.balance().saturating_add(wallet_data.shielded_balance());
    if total != wallet_data.balance() && total != wallet_data.shielded_balance() {
        println!("  {} {} KRGN",
            term::dim("Total:  "),
            term::bold(&wallet::format_krgn(total)),
        );
    }

    println!();

    Ok(())
}

fn cmd_send(args: &[String]) -> Result<(), WalletError> {
    if args.len() < 3 {
        println!();
        println!("  {} kerrigan-wallet {} {} {} {}",
            term::bold("Usage:"),
            term::purple("send"),
            term::dim("<public|private>"),
            term::dim("<address>"),
            term::dim("<amount|max>"),
        );
        println!();
        println!("  {} kerrigan-wallet send {} KAddr... 1.5",
            term::dim("Public send: "),
            term::bold("public"),
        );
        println!("  {} kerrigan-wallet send {} ks1Addr... 1.5 \"memo\"",
            term::dim("Private send:"),
            term::bold("private"),
        );
        println!();
        return Ok(());
    }

    let source = args[0].to_lowercase();
    let to_address = &args[1];
    let amount_str = &args[2];
    let _memo = args.get(3).map(|s| s.as_str()).unwrap_or("");
    let is_max = amount_str.eq_ignore_ascii_case("max");

    // Determine the flow
    let from_private = match source.as_str() {
        "private" => true,
        "public" => false,
        _ => return Err(WalletError::Transaction(
            format!("first argument must be 'public' or 'private', got '{source}'")
        )),
    };

    let to_shielded = to_address.starts_with("ks");
    let to_transparent = !to_shielded;

    // Validate destination address
    if to_transparent {
        keys::validate_address(to_address)
            .map_err(|e| WalletError::Transaction(format!("invalid address: {e}")))?;
    }
    // Shielded address validation happens inside the SDK builder

    if !is_max {
        let amount = wallet::parse_krgn(amount_str)?;
        if amount == 0 {
            return Err(WalletError::Transaction("amount must be > 0".into()));
        }
    }

    let mut wallet_data = crate::storage::load_wallet()?;

    println!();
    let _ = sync_with_spinner(&mut wallet_data);

    // Route to the correct send flow
    match (from_private, to_shielded) {
        (false, false) => {
            // Public → Public (transparent send)
            send_transparent(&mut wallet_data, to_address, amount_str, is_max)
        }
        (false, true) => {
            // Public → Private (shielding)
            let amount = if is_max {
                let fee = kerrigan_sdk::sapling::fees::shield_fee(1);
                wallet_data.balance().saturating_sub(fee)
            } else {
                wallet::parse_krgn(amount_str)?
            };
            send_shield(&mut wallet_data, to_address, amount, _memo)
        }
        (true, false) => {
            // Private → Public (unshielding)
            let amount = if is_max {
                // Max: all notes consumed, builder uses unshield_fee (1 sapling change)
                let fee = kerrigan_sdk::sapling::fees::unshield_fee(
                    wallet_data.unspent_notes.len()
                );
                wallet_data.shielded_balance().saturating_sub(fee)
            } else {
                wallet::parse_krgn(amount_str)?
            };
            send_unshield(&mut wallet_data, to_address, amount)
        }
        (true, true) => {
            // Private → Private (shield-to-shield)
            let amount = if is_max {
                // Max: all notes consumed, builder uses shield_send_fee (2 outputs)
                let fee = kerrigan_sdk::sapling::fees::shield_send_fee(
                    wallet_data.unspent_notes.len()
                );
                wallet_data.shielded_balance().saturating_sub(fee)
            } else {
                wallet::parse_krgn(amount_str)?
            };
            send_sapling(&mut wallet_data, to_address, amount, _memo)
        }
    }
}

/// Transparent send — existing public-to-public flow.
fn send_transparent(
    wallet_data: &mut WalletData,
    to_address: &str,
    amount_str: &str,
    is_max: bool,
) -> Result<(), WalletError> {
    let (signed, amount) = if is_max {
        let signed = kerrigan_sdk::wallet::prepare_send_max(wallet_data, to_address)?;
        let amount = signed.tx.outputs.first()
            .map(|o| o.value)
            .unwrap_or(0);
        (signed, amount)
    } else {
        let amount = wallet::parse_krgn(amount_str)?;
        let signed = kerrigan_sdk::wallet::prepare_send(wallet_data, to_address, amount)?;
        (signed, amount)
    };

    println!();
    term::header("Transaction");
    println!();
    println!("   {}  {}", term::dim("Type:"), term::bold("Public"));
    println!("   {}  {}", term::dim("To:"), term::bold(to_address));
    println!("   {}  {} KRGN{}",
        term::dim("Amount:"),
        term::green_bold(&wallet::format_krgn(amount)),
        if is_max { term::dim(" (max)").to_string() } else { String::new() },
    );
    println!("   {}  {} KRGN",
        term::dim("Fee:"),
        term::yellow(&wallet::format_krgn(signed.fee)),
    );
    println!("   {}  {} KRGN",
        term::dim("Total:"),
        term::bold(&wallet::format_krgn(amount + signed.fee)),
    );
    println!();

    if !confirm(&format!("  Confirm send? ({}/no): ", term::green("yes")), "yes") {
        println!("  {}", term::dim("Cancelled."));
        return Ok(());
    }

    let spinner = Spinner::start("Broadcasting");
    let txid = crate::broadcast_and_finalize(wallet_data, &signed);
    match txid {
        Ok(txid) => {
            spinner.finish_with("Transaction sent!");
            println!();
            println!("  {} {}", term::dim("TXID:"), term::purple(&txid));
            println!();
        }
        Err(e) => {
            spinner.finish_err(&format!("Broadcast failed: {e}"));
            return Err(e);
        }
    }

    Ok(())
}

/// Shielding send — transparent UTXOs → sapling output.
fn send_shield(
    wallet_data: &mut WalletData,
    to_address: &str,
    amount: u64,
    memo: &str,
) -> Result<(), WalletError> {
    // Decode shielded destination
    let to_shielded = kerrigan_sdk::sapling::keys::decode_payment_address(to_address)
        .map_err(|e| WalletError::Transaction(format!("invalid shielded address: {e}")))?;

    // Derive keypair for transparent signing
    let kp = wallet_data.derive_keypair()?;

    // Check we have enough transparent balance
    let fee = kerrigan_sdk::sapling::fees::shield_fee(1);
    if wallet_data.balance() < amount + fee {
        return Err(WalletError::Transaction(format!(
            "insufficient public balance: have {} sat, need {} sat (amount) + {} sat (fee)",
            wallet_data.balance(), amount, fee
        )));
    }

    // Get block height from bridge
    let block_height = get_bridge_block_height()?;

    // Show transaction details
    println!();
    term::header("Shield Transaction");
    println!();
    println!("   {}  {}", term::dim("Type:"), term::bold("Public → Private"));
    println!("   {}  {}", term::dim("To:"), term::bold(&to_address[..20]));
    println!("   {}  {} KRGN",
        term::dim("Amount:"),
        term::green_bold(&wallet::format_krgn(amount)),
    );
    println!("   {}  {} KRGN",
        term::dim("Fee:"),
        term::yellow(&wallet::format_krgn(fee)),
    );
    println!();

    if !confirm(&format!("  Confirm shield? ({}/no): ", term::green("yes")), "yes") {
        println!("  {}", term::dim("Cancelled."));
        return Ok(());
    }

    // Download/load sapling params
    let spinner = Spinner::start("Loading Sapling parameters");
    let prover = crate::sapling_params::ensure_params(|msg| {
        spinner.set_progress(0.0, Some(msg));
    })?;
    spinner.finish_with("Parameters loaded");

    // Build the shielding transaction
    let spinner = Spinner::start("Building shield transaction");
    let memo_bytes = if memo.is_empty() {
        None
    } else {
        let mut m = [0u8; 512];
        let bytes = memo.as_bytes();
        m[..bytes.len().min(512)].copy_from_slice(&bytes[..bytes.len().min(512)]);
        Some(m)
    };
    let result = kerrigan_sdk::sapling::builder::build_shield(
        &wallet_data.utxos,
        &kp.privkey,
        &kp.pubkey,
        &wallet_data.address,
        &to_shielded,
        amount,
        memo_bytes,
        block_height,
        &prover,
    ).map_err(|e| WalletError::Transaction(format!("{e}")))?;
    spinner.finish_with("Transaction built");

    // Debug: show tx header for format verification
    eprintln!("  [debug] TX hex ({} bytes): {}...", result.tx_hex.len() / 2, &result.tx_hex[..16]);

    // Broadcast via bridge
    let spinner = Spinner::start("Broadcasting");
    let txid = broadcast_via_bridge(&result.tx_hex)?;
    spinner.finish_with("Transaction sent!");

    println!();
    println!("  {} {}", term::dim("TXID:"), term::purple(&txid));
    println!("  {} {} KRGN shielded",
        term::dim("Shielded:"),
        term::green_bold(&wallet::format_krgn(amount)),
    );
    println!();

    // Log to history
    wallet_data.history.insert(0, TxHistoryEntry {
        txid: txid.clone(),
        net_amount: -(amount as i64),
        timestamp: None,
        block_height: None,
        confirmations: None,
        tx_type: "shield".to_string(),
        memo: if memo.is_empty() { None } else { Some(memo.to_string()) },
    });

    // Update wallet state — remove spent UTXOs
    let spent_amount = amount + fee;
    let mut remaining = spent_amount;
    wallet_data.utxos.retain(|u| {
        if remaining > 0 && u.amount <= remaining {
            remaining -= u.amount;
            false // remove this UTXO
        } else {
            true
        }
    });
    crate::storage::save_wallet(wallet_data)?;

    Ok(())
}

/// Shield-to-shield send — private → private.
fn send_sapling(
    wallet_data: &mut WalletData,
    to_address: &str,
    amount: u64,
    memo: &str,
) -> Result<(), WalletError> {
    let to_shielded = kerrigan_sdk::sapling::keys::decode_payment_address(to_address)
        .map_err(|e| WalletError::Transaction(format!("invalid shielded address: {e}")))?;

    let extsk_encoded = wallet_data.sapling_extsk.as_ref()
        .ok_or(WalletError::Other("no shielded spending key".into()))?;
    let extsk = kerrigan_sdk::sapling::keys::decode_extsk(extsk_encoded)
        .map_err(|e| WalletError::Other(format!("decode extsk: {e}")))?;

    let fee = kerrigan_sdk::sapling::fees::shield_send_fee(1); // minimum estimate
    if wallet_data.shielded_balance() < amount + fee {
        return Err(WalletError::Transaction(format!(
            "insufficient private balance: have {} sat, need {} sat",
            wallet_data.shielded_balance(), amount + fee
        )));
    }

    // Load notes
    let notes: Vec<kerrigan_sdk::sapling::notes::SpendableNote> = wallet_data.unspent_notes.iter()
        .map(kerrigan_sdk::sapling::notes::SpendableNote::from_serialized)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| WalletError::Other(format!("load notes: {e}")))?;

    let memo_bytes = if memo.is_empty() {
        None
    } else {
        let mut m = [0u8; 512];
        let bytes = memo.as_bytes();
        m[..bytes.len().min(512)].copy_from_slice(&bytes[..bytes.len().min(512)]);
        Some(m)
    };

    println!();
    term::header("Shield Send");
    println!();
    println!("   {}  {}", term::dim("Type:"), term::bold("Private → Private"));
    println!("   {}  {}", term::dim("To:"), term::bold(&to_address[..20]));
    println!("   {}  {} KRGN", term::dim("Amount:"), term::green_bold(&wallet::format_krgn(amount)));
    println!();

    if !confirm(&format!("  Confirm send? ({}/no): ", term::green("yes")), "yes") {
        println!("  {}", term::dim("Cancelled."));
        return Ok(());
    }

    let spinner = Spinner::start("Loading Sapling parameters");
    let prover = crate::sapling_params::ensure_params(|msg| {
        spinner.set_progress(0.0, Some(msg));
    })?;
    spinner.finish_with("Parameters loaded");

    let spinner = Spinner::start("Building shield transaction");
    let result = kerrigan_sdk::sapling::builder::build_sapling_send(
        &notes, &extsk, &to_shielded, amount, memo_bytes, &prover,
    ).map_err(|e| WalletError::Transaction(format!("{e}")))?;
    spinner.finish_with("Transaction built");

    let spinner = Spinner::start("Broadcasting");
    let txid = broadcast_via_bridge(&result.tx_hex)?;
    spinner.finish_with("Transaction sent!");

    println!();
    println!("  {} {}", term::dim("TXID:"), term::purple(&txid));
    println!();

    // Log to history + mark spent notes
    wallet_data.history.insert(0, TxHistoryEntry {
        txid: txid.clone(),
        net_amount: -(amount as i64),
        timestamp: None,
        block_height: None,
        confirmations: None,
        tx_type: "private".to_string(),
        memo: if memo.is_empty() { None } else { Some(memo.to_string()) },
    });
    wallet_data.unspent_notes.retain(|n| !result.nullifiers.contains(&n.nullifier));
    crate::storage::save_wallet(wallet_data)?;

    Ok(())
}

/// Unshield send — private → public.
fn send_unshield(
    wallet_data: &mut WalletData,
    to_address: &str,
    amount: u64,
) -> Result<(), WalletError> {
    let extsk_encoded = wallet_data.sapling_extsk.as_ref()
        .ok_or(WalletError::Other("no shielded spending key".into()))?;
    let extsk = kerrigan_sdk::sapling::keys::decode_extsk(extsk_encoded)
        .map_err(|e| WalletError::Other(format!("decode extsk: {e}")))?;

    let fee = kerrigan_sdk::sapling::fees::unshield_fee(1);
    if wallet_data.shielded_balance() < amount + fee {
        return Err(WalletError::Transaction(format!(
            "insufficient private balance: have {} sat, need {} sat",
            wallet_data.shielded_balance(), amount + fee
        )));
    }

    let notes: Vec<kerrigan_sdk::sapling::notes::SpendableNote> = wallet_data.unspent_notes.iter()
        .map(kerrigan_sdk::sapling::notes::SpendableNote::from_serialized)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| WalletError::Other(format!("load notes: {e}")))?;

    println!();
    term::header("Unshield Transaction");
    println!();
    println!("   {}  {}", term::dim("Type:"), term::bold("Private → Public"));
    println!("   {}  {}", term::dim("To:"), term::bold(to_address));
    println!("   {}  {} KRGN", term::dim("Amount:"), term::green_bold(&wallet::format_krgn(amount)));
    println!();

    if !confirm(&format!("  Confirm unshield? ({}/no): ", term::green("yes")), "yes") {
        println!("  {}", term::dim("Cancelled."));
        return Ok(());
    }

    let spinner = Spinner::start("Loading Sapling parameters");
    let prover = crate::sapling_params::ensure_params(|msg| {
        spinner.set_progress(0.0, Some(msg));
    })?;
    spinner.finish_with("Parameters loaded");

    let spinner = Spinner::start("Building unshield transaction");
    let result = kerrigan_sdk::sapling::builder::build_unshield(
        &notes, &extsk, to_address, amount, &prover,
    ).map_err(|e| WalletError::Transaction(format!("{e}")))?;
    spinner.finish_with("Transaction built");

    let spinner = Spinner::start("Broadcasting");
    let txid = broadcast_via_bridge(&result.tx_hex)?;
    spinner.finish_with("Transaction sent!");

    println!();
    println!("  {} {}", term::dim("TXID:"), term::purple(&txid));
    println!();

    wallet_data.history.insert(0, TxHistoryEntry {
        txid: txid.clone(),
        net_amount: amount as i64, // positive — funds coming back to transparent
        timestamp: None,
        block_height: None,
        confirmations: None,
        tx_type: "unshield".to_string(),
        memo: None,
    });
    wallet_data.unspent_notes.retain(|n| !result.nullifiers.contains(&n.nullifier));
    crate::storage::save_wallet(wallet_data)?;

    Ok(())
}

/// Get block height from the bridge.
fn get_bridge_block_height() -> Result<u32, WalletError> {
    let url = format!("{}/getblockcount", kerrigan_sdk::params::BRIDGE_URL);
    let resp = ureq::get(&url)
        .call()
        .map_err(|e| WalletError::Other(format!("bridge getblockcount: {e}")))?;
    let body = resp.into_string()
        .map_err(|e| WalletError::Other(format!("read response: {e}")))?;
    body.trim().parse::<u32>()
        .map_err(|e| WalletError::Other(format!("parse block height: {e}")))
}

/// Broadcast a raw transaction via the bridge.
fn broadcast_via_bridge(tx_hex: &str) -> Result<String, WalletError> {
    let url = format!("{}/sendrawtransaction", kerrigan_sdk::params::BRIDGE_URL);
    match ureq::post(&url).send_string(tx_hex) {
        Ok(resp) => {
            let txid = resp.into_string()
                .map_err(|e| WalletError::Other(format!("read txid: {e}")))?;
            Ok(txid.trim().to_string())
        }
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            Err(WalletError::Other(format!("broadcast rejected (HTTP {code}): {body}")))
        }
        Err(e) => Err(WalletError::Other(format!("broadcast failed: {e}"))),
    }
}

fn cmd_history(args: &[String]) -> Result<(), WalletError> {
    let mut wallet_data = crate::storage::load_wallet()?;

    println!();

    // Sync if no history cached
    if wallet_data.history.is_empty() {
        let _ = sync_with_spinner(&mut wallet_data);
    }

    // Derive chain height from local data (no network call)
    let chain_height = wallet_data.history.iter()
        .filter_map(|e| e.block_height)
        .max()
        .unwrap_or(0);

    // Recalculate confirmations from block_height (stored confs go stale)
    for entry in &mut wallet_data.history {
        entry.confirmations = entry.block_height
            .map(|h| if chain_height >= h { chain_height - h + 1 } else { 0 });
    }

    // Sort: pending first, then by block height descending (newest first)
    wallet_data.history.sort_by(|a, b| {
        let a_pending = a.block_height.is_none();
        let b_pending = b.block_height.is_none();
        b_pending.cmp(&a_pending)
            .then_with(|| b.block_height.unwrap_or(0).cmp(&a.block_height.unwrap_or(0)))
    });

    let history = &wallet_data.history;
    if history.is_empty() {
        println!("  {}", term::dim("No transactions yet."));
        println!();
        return Ok(());
    }

    // Parse pagination: "all", a page number, or default (page 1)
    let page_size = 10usize;
    let (entries, page_info): (&[TxHistoryEntry], String) = if args.first().map(|s| s.as_str()) == Some("all") {
        (history, format!("all {} transactions", history.len()))
    } else {
        let page: usize = args.first()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1)
            .max(1);
        let total_pages = history.len().div_ceil(page_size);
        let page = page.min(total_pages);
        let start = (page - 1) * page_size;
        let end = (start + page_size).min(history.len());
        (&history[start..end], format!("page {page}/{total_pages}"))
    };

    // Decide txid display width based on terminal width
    // Full txid (64 chars) needs ~108 cols total: 2 + 64 + 2 + 15 + 2 + 8 + 2 + 10 + padding
    let term_width = term::terminal_width();
    let full_txid = term_width >= 108;
    let txid_width = if full_txid { 64 } else { 16 };
    let divider_width = if full_txid { 108 } else { 60 };

    println!("  {} {} {}",
        term::purple_bold("▸"),
        term::bold("Transaction History"),
        term::dim(&format!("({})", page_info)),
    );
    println!();

    // Header (pad BEFORE coloring to avoid ANSI alignment issues)
    println!("  {}  {}  {}  {}",
        term::dim(&format!("{:<txid_width$}", "TXID")),
        term::dim(&format!("{:>12}", "Amount")),
        term::dim(&format!("{:>7}", "Confs")),
        term::dim("Date"),
    );
    term::divider(divider_width);

    for entry in entries {
        let txid_display = if full_txid {
            entry.txid.clone()
        } else if entry.txid.len() >= 16 {
            entry.txid[..16].to_string()
        } else {
            entry.txid.clone()
        };

        // Format amount with fixed width BEFORE applying color
        // (ANSI codes break Rust's {:>width} padding)
        let amount_raw = if entry.net_amount >= 0 {
            format!("+{}", wallet::format_krgn(entry.net_amount as u64))
        } else {
            format!("-{}", wallet::format_krgn((-entry.net_amount) as u64))
        };
        let amount_padded = format!("{:>12}", amount_raw);
        let amount_str = if entry.net_amount >= 0 {
            term::green(&amount_padded)
        } else {
            term::red(&amount_padded)
        };

        let confs = entry.confirmations
            .map(|c| format!("{c}"))
            .unwrap_or_else(|| "pending".into());
        let confs_padded = format!("{:>7}", confs);

        let date = entry.timestamp
            .map(format_timestamp)
            .unwrap_or_else(|| "—".into());

        let type_label = match entry.tx_type.as_str() {
            "shield" => term::yellow("SH"),
            "unshield" => term::yellow("UN"),
            "private" => term::purple("PR"),
            _ => term::dim("TX"),
        };

        println!("  {} {}  {}  {}  {}",
            type_label,
            term::purple(&format!("{:<txid_width$}", txid_display)),
            amount_str,
            term::dim(&confs_padded),
            date,
        );

        // Show memo on its own line, indented, if present
        if let Some(memo) = &entry.memo {
            let display = if memo.len() > 60 { format!("{}...", &memo[..57]) } else { memo.clone() };
            println!("     {}", term::dim(&format!("\"{}\"", display)));
        }
    }

    term::divider(divider_width);
    println!();

    // Pagination hint
    let total_pages = history.len().div_ceil(page_size);
    if total_pages > 1 && args.first().map(|s| s.as_str()) != Some("all") {
        println!("  {} {} or {}",
            term::dim("Tip:"),
            term::purple("history <page>"),
            term::purple("history all"),
        );
        println!();
    }

    Ok(())
}

fn cmd_sync() -> Result<(), WalletError> {
    let mut wallet_data = crate::storage::load_wallet()?;

    // Force full resync — clear all cached state (transparent + shield)
    wallet_data.processed_txids.clear();
    wallet_data.utxos.clear();
    wallet_data.history.clear();
    wallet_data.sync_state = None;
    wallet_data.last_sync_height = 0;

    // Reset shield state — rebuild tree from activation
    wallet_data.commitment_tree = None;
    wallet_data.unspent_notes.clear();
    wallet_data.sapling_last_block = 0;

    println!();
    let _result = sync_with_spinner(&mut wallet_data)?;

    let total = wallet_data.balance() + wallet_data.shielded_balance();
    println!();
    println!("  {} {} KRGN  {} {} KRGN  {} {} KRGN",
        term::dim("Public:"),
        term::green_bold(&wallet::format_krgn(wallet_data.balance())),
        term::dim("│ Private:"),
        term::green_bold(&wallet::format_krgn(wallet_data.shielded_balance())),
        term::dim("│ Total:"),
        term::bold(&wallet::format_krgn(total)),
    );
    println!();

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format a unix timestamp into a human-readable date.
fn format_timestamp(ts: u64) -> String {
    // Simple formatting without chrono: days since epoch → date
    let secs_per_day: u64 = 86400;
    let days = ts / secs_per_day;

    // Days since 1970-01-01 → year/month/day (simplified Gregorian)
    let mut y = 1970u64;
    let mut remaining = days;

    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }

    let months_days: [u64; 12] = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut m = 0;
    for (i, &md) in months_days.iter().enumerate() {
        if remaining < md {
            m = i + 1;
            break;
        }
        remaining -= md;
    }
    let d = remaining + 1;

    format!("{y}-{m:02}-{d:02}")
}

#[allow(clippy::manual_is_multiple_of)]
fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Broadcast a signed transaction and update the wallet.
fn broadcast_and_finalize(
    wallet: &mut WalletData,
    signed: &SignedTransaction,
) -> Result<String, WalletError> {
    let client = network::ExplorerClient::new();
    let txid = client.broadcast(&signed.tx_hex)
        .map_err(|e| WalletError::Transaction(e.to_string()))?;
    wallet.finalize_send(&signed.spent_utxos);
    storage::save_wallet(wallet)?;
    Ok(txid)
}
