/// Kerrigan Network light wallet CLI.
///
/// A minimal, transparent-only wallet for the Kerrigan Network (KRGN).
/// All key derivation (BIP39, BIP32) is implemented from scratch with
/// zero external BIP crates.
///
/// # Commands
///
/// ```text
/// kerrigan-wallet create            Generate new wallet, display 24-word mnemonic
/// kerrigan-wallet import            Import wallet from mnemonic (interactive stdin)
/// kerrigan-wallet export            Display mnemonic (requires confirmation)
/// kerrigan-wallet address           Show receiving address
/// kerrigan-wallet balance           Sync UTXOs and show balance
/// kerrigan-wallet send <addr> <amt> Send KRGN (shows fee, requires confirmation)
/// kerrigan-wallet history           Show transaction history (synced txids)
/// kerrigan-wallet sync              Force full UTXO resync
/// ```

use std::io::{self, Write};
use std::process;

use kerrigan_wallet::keys;
use kerrigan_wallet::wallet::{self, WalletError};

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
        "history" => cmd_history(),
        "sync" => cmd_sync(),
        "help" | "--help" | "-h" => { print_usage(); Ok(()) }
        "version" | "--version" | "-V" => { print_version(); Ok(()) }
        other => {
            eprintln!("Unknown command: {other}");
            print_usage();
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Usage / version
// ---------------------------------------------------------------------------

fn print_usage() {
    println!("kerrigan-wallet v{}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Usage: kerrigan-wallet <command> [args]");
    println!();
    println!("Commands:");
    println!("  create            Generate a new wallet");
    println!("  import            Import wallet from mnemonic");
    println!("  export            Display wallet mnemonic");
    println!("  address           Show receiving address");
    println!("  balance           Sync and show balance");
    println!("  send <addr> <amt> Send KRGN to an address");
    println!("  history           Show synced transaction count");
    println!("  sync              Force full UTXO resync");
    println!("  version           Show version");
}

fn print_version() {
    println!("kerrigan-wallet v{}", env!("CARGO_PKG_VERSION"));
}

// ---------------------------------------------------------------------------
// Interactive I/O helpers
// ---------------------------------------------------------------------------

/// Read a line from stdin, trimmed.
fn read_line(prompt: &str) -> String {
    print!("{prompt}");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

/// Ask for confirmation. Returns true if user types the expected string.
fn confirm(prompt: &str, expected: &str) -> bool {
    let input = read_line(prompt);
    input == expected
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_create() -> Result<(), WalletError> {
    let wallet_data = wallet::create_wallet()?;

    println!("Wallet created successfully!");
    println!();
    println!("Your 24-word recovery phrase:");
    println!();

    // Display words in a numbered grid
    let words: Vec<&str> = wallet_data.mnemonic().split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        print!("  {:>2}. {:<12}", i + 1, word);
        if (i + 1) % 4 == 0 {
            println!();
        }
    }
    println!();

    println!("IMPORTANT: Write down these words and store them safely.");
    println!("They are the ONLY way to recover your wallet.");
    println!();
    println!("Receiving address: {}", wallet_data.address);

    Ok(())
}

fn cmd_import() -> Result<(), WalletError> {
    if wallet::wallet_exists() {
        return Err(WalletError::AlreadyExists);
    }

    println!("Enter your 24-word recovery phrase:");
    let mnemonic = read_line("> ");

    if mnemonic.is_empty() {
        return Err(WalletError::InvalidMnemonic("empty input".into()));
    }

    let wallet_data = wallet::import_wallet(&mnemonic)?;

    println!();
    println!("Wallet imported successfully!");
    println!("Address: {}", wallet_data.address);
    println!();
    println!("Run 'kerrigan-wallet sync' to scan for existing transactions.");

    Ok(())
}

fn cmd_export() -> Result<(), WalletError> {
    let wallet_data = wallet::load_wallet()?;

    println!("WARNING: Your recovery phrase gives FULL access to your funds.");
    println!("Never share it with anyone.");
    println!();

    if !confirm("Type 'I understand' to continue: ", "I understand") {
        println!("Cancelled.");
        return Ok(());
    }

    println!();
    let words: Vec<&str> = wallet_data.mnemonic().split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        print!("  {:>2}. {:<12}", i + 1, word);
        if (i + 1) % 4 == 0 {
            println!();
        }
    }
    println!();

    Ok(())
}

fn cmd_address() -> Result<(), WalletError> {
    let wallet_data = wallet::load_wallet()?;
    println!("{}", wallet_data.address);
    Ok(())
}

fn cmd_balance() -> Result<(), WalletError> {
    let mut wallet_data = wallet::load_wallet()?;

    eprint!("Syncing...");
    match wallet::sync_wallet(&mut wallet_data) {
        Ok(result) => {
            wallet::save_wallet(&wallet_data)?;
            eprintln!(" done ({} txs processed).", result.processed_txids.len());
        }
        Err(e) => {
            eprintln!(" sync failed: {e}");
            eprintln!("Showing cached balance.");
        }
    }

    println!();
    println!("Balance: {} KRGN", wallet_data.balance_display());

    if wallet_data.utxos.len() > 1 {
        println!("  ({} UTXOs)", wallet_data.utxos.len());
    }

    Ok(())
}

fn cmd_send(args: &[String]) -> Result<(), WalletError> {
    if args.len() < 2 {
        eprintln!("Usage: kerrigan-wallet send <address> <amount>");
        eprintln!("  amount: in KRGN (e.g., 1.5 or 0.001)");
        return Ok(());
    }

    let to_address = &args[0];
    let amount_str = &args[1];

    // Validate destination address
    keys::validate_address(to_address)
        .map_err(|e| WalletError::Transaction(format!("invalid address: {e}")))?;

    // Parse amount
    let amount = wallet::parse_krgn(amount_str)?;
    if amount == 0 {
        return Err(WalletError::Transaction("amount must be > 0".into()));
    }

    let mut wallet_data = wallet::load_wallet()?;

    // Sync first to get latest UTXOs
    eprint!("Syncing...");
    match wallet::sync_wallet(&mut wallet_data) {
        Ok(_) => {
            wallet::save_wallet(&wallet_data)?;
            eprintln!(" done.");
        }
        Err(e) => {
            eprintln!(" sync failed: {e}");
            eprintln!("Proceeding with cached UTXOs.");
        }
    }

    // Build the transaction
    let signed = wallet::prepare_send(&wallet_data, to_address, amount)?;

    // Show details and confirm
    println!();
    println!("Transaction details:");
    println!("  To:     {to_address}");
    println!("  Amount: {} KRGN", wallet::format_krgn(amount));
    println!("  Fee:    {} KRGN", wallet::format_krgn(signed.fee));
    println!("  Total:  {} KRGN", wallet::format_krgn(amount + signed.fee));
    println!();

    let remaining = wallet_data.balance().saturating_sub(amount + signed.fee);
    println!("  Remaining balance: {} KRGN", wallet::format_krgn(remaining));
    println!();

    if !confirm("Confirm send? (yes/no): ", "yes") {
        println!("Cancelled.");
        return Ok(());
    }

    // Broadcast
    eprint!("Broadcasting...");
    let txid = wallet::broadcast_and_finalize(&mut wallet_data, &signed)?;
    eprintln!(" done.");

    println!();
    println!("Transaction sent!");
    println!("  TXID: {txid}");

    Ok(())
}

fn cmd_history() -> Result<(), WalletError> {
    let wallet_data = wallet::load_wallet()?;

    println!("Address: {}", wallet_data.address);
    println!("Transactions: {}", wallet_data.processed_txids.len());
    println!("UTXOs: {}", wallet_data.utxos.len());
    println!("Balance: {} KRGN", wallet_data.balance_display());

    if wallet_data.last_sync_height > 0 {
        println!("Last sync height: {}", wallet_data.last_sync_height);
    }

    if !wallet_data.utxos.is_empty() {
        println!();
        println!("Unspent outputs:");
        for utxo in &wallet_data.utxos {
            println!("  {}:{} — {} KRGN",
                &utxo.txid[..16], utxo.vout,
                wallet::format_krgn(utxo.amount)
            );
        }
    }

    Ok(())
}

fn cmd_sync() -> Result<(), WalletError> {
    let mut wallet_data = wallet::load_wallet()?;

    // Force full resync by clearing processed txids
    wallet_data.processed_txids.clear();
    wallet_data.utxos.clear();

    eprint!("Syncing from scratch...");
    let result = wallet::sync_wallet(&mut wallet_data)?;
    wallet::save_wallet(&wallet_data)?;
    eprintln!(" done.");

    println!();
    println!("Synced {} transactions.", result.processed_txids.len());
    println!("Balance: {} KRGN", wallet_data.balance_display());
    println!("UTXOs: {}", wallet_data.utxos.len());

    Ok(())
}
