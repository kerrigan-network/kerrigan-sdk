/// Kerrigan Network light wallet CLI.
///
/// "My stare alone would reduce you to ashes."
///   — Sarah Kerrigan, Queen of Blades

use std::io::{self, Write};
use std::process;

use kerrigan_wallet::keys;
use kerrigan_wallet::params;
use kerrigan_wallet::sync::TxHistoryEntry;
use kerrigan_wallet::term::{self, Spinner};
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
    println!("  {}           Show receiving address", term::purple("address"));
    println!("  {}           Sync and show balance", term::purple("balance"));
    println!("  {} {} {} Send KRGN to an address", term::purple("send"), term::dim("<addr>"), term::dim("<amt>"));
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
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn confirm(prompt: &str, expected: &str) -> bool {
    let input = read_line(prompt);
    input == expected
}

/// Run a sync with a spinner, save the wallet, and return the result.
fn sync_with_spinner(wallet_data: &mut wallet::WalletData) -> Result<kerrigan_wallet::sync::SyncResult, WalletError> {
    let spinner = Spinner::start("Syncing");

    // We need to move the spinner into the closure, but the closure is called
    // from sync_wallet_with_progress. Use a shared reference via Arc.
    let spinner_ref = std::sync::Arc::new(spinner);
    let spinner_for_closure = spinner_ref.clone();

    let result = wallet::sync_wallet_with_progress(wallet_data, move |done, total| {
        if total == 0 && done == 0 {
            // Phase 1: fetching address info
            spinner_for_closure.set_progress(0.0, Some("Fetching address"));
        } else if done == 0 {
            // Phase 2: address info fetched, about to start tx fetches
            spinner_for_closure.set_progress(0.0, Some("Syncing"));
        } else {
            // Phase 3: fetching transactions
            spinner_for_closure.set_progress(done as f64 / total as f64, Some("Syncing"));
        }
    });

    // Unwrap the Arc to get the spinner back
    let spinner = std::sync::Arc::try_unwrap(spinner_ref).ok();

    match &result {
        Ok(r) => {
            if let Some(s) = spinner {
                s.finish_with(&format!("Synced {} transactions", r.processed_txids.len()));
            }
            wallet::save_wallet(wallet_data)?;
        }
        Err(e) => {
            if let Some(s) = spinner {
                s.finish_err(&format!("Sync failed: {e}"));
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_create() -> Result<(), WalletError> {
    let wallet_data = wallet::create_wallet()?;

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
    if wallet::wallet_exists() {
        return Err(WalletError::AlreadyExists);
    }

    println!();
    println!("  {}", term::bold("Enter your 24-word recovery phrase:"));
    let mnemonic = read_line(&format!("  {} ", term::purple(">")));

    if mnemonic.is_empty() {
        return Err(WalletError::InvalidMnemonic("empty input".into()));
    }

    let wallet_data = wallet::import_wallet(&mnemonic)?;

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
    let wallet_data = wallet::load_wallet()?;

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
    let wallet_data = wallet::load_wallet()?;
    println!("{}", term::purple_bold(&wallet_data.address));
    Ok(())
}

fn cmd_balance() -> Result<(), WalletError> {
    let mut wallet_data = wallet::load_wallet()?;

    println!();
    let sync_ok = sync_with_spinner(&mut wallet_data).is_ok();

    println!();
    println!("  {} {}",
        term::dim("Balance:"),
        term::green_bold(&format!("{} KRGN", wallet_data.balance_display())),
    );

    if wallet_data.utxos.len() > 1 {
        println!("  {} {} UTXOs",
            term::dim("Coins: "),
            wallet_data.utxos.len(),
        );
    }
    println!();

    Ok(())
}

fn cmd_send(args: &[String]) -> Result<(), WalletError> {
    if args.len() < 2 {
        println!();
        println!("  {} kerrigan-wallet {} {} {}",
            term::bold("Usage:"),
            term::purple("send"),
            term::dim("<address>"),
            term::dim("<amount>"),
        );
        println!("  {} amount in KRGN (e.g., {} or {})",
            term::dim("       "),
            term::bold("1.5"),
            term::bold("0.001"),
        );
        println!();
        return Ok(());
    }

    let to_address = &args[0];
    let amount_str = &args[1];

    keys::validate_address(to_address)
        .map_err(|e| WalletError::Transaction(format!("invalid address: {e}")))?;

    let amount = wallet::parse_krgn(amount_str)?;
    if amount == 0 {
        return Err(WalletError::Transaction("amount must be > 0".into()));
    }

    let mut wallet_data = wallet::load_wallet()?;

    println!();
    let _ = sync_with_spinner(&mut wallet_data);

    let signed = wallet::prepare_send(&wallet_data, to_address, amount)?;

    println!();
    term::header("Transaction");
    println!();
    println!("   {}  {}", term::dim("To:"), term::bold(to_address));
    println!("   {}  {} KRGN", term::dim("Amount:"), term::green_bold(&wallet::format_krgn(amount)));
    println!("   {}  {} KRGN", term::dim("Fee:"), term::yellow(&wallet::format_krgn(signed.fee)));
    println!("   {}  {} KRGN",
        term::dim("Total:"),
        term::bold(&wallet::format_krgn(amount + signed.fee)),
    );
    println!();

    let remaining = wallet_data.balance().saturating_sub(amount + signed.fee);
    println!("   {}  {} KRGN",
        term::dim("Remaining:"),
        wallet::format_krgn(remaining),
    );
    println!();

    if !confirm(&format!("  Confirm send? ({}/no): ", term::green("yes")), "yes") {
        println!("  {}", term::dim("Cancelled."));
        return Ok(());
    }

    let spinner = Spinner::start("Broadcasting");
    let txid = wallet::broadcast_and_finalize(&mut wallet_data, &signed);
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

fn cmd_history(args: &[String]) -> Result<(), WalletError> {
    let mut wallet_data = wallet::load_wallet()?;

    println!();

    // Sync if no history cached
    if wallet_data.history.is_empty() {
        let _ = sync_with_spinner(&mut wallet_data);
    }

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
        let total_pages = (history.len() + page_size - 1) / page_size;
        let page = page.min(total_pages);
        let start = (page - 1) * page_size;
        let end = (start + page_size).min(history.len());
        (&history[start..end], format!("page {page}/{total_pages}"))
    };

    println!("  {} {} {}",
        term::purple_bold("▸"),
        term::bold("Transaction History"),
        term::dim(&format!("({})", page_info)),
    );
    println!();

    // Header
    println!("  {}  {}  {}  {}",
        term::dim(&format!("{:<16}", "TXID")),
        term::dim(&format!("{:>15}", "Amount")),
        term::dim(&format!("{:>8}", "Confs")),
        term::dim("Date"),
    );
    term::divider(60);

    for entry in entries {
        let txid_short = if entry.txid.len() >= 16 {
            &entry.txid[..16]
        } else {
            &entry.txid
        };

        let amount_str = if entry.net_amount >= 0 {
            term::green(&format!("+{}", wallet::format_krgn(entry.net_amount as u64)))
        } else {
            term::red(&format!("-{}", wallet::format_krgn((-entry.net_amount) as u64)))
        };

        let confs = entry.confirmations
            .map(|c| format!("{c}"))
            .unwrap_or_else(|| "pending".into());

        let date = entry.timestamp
            .map(|ts| format_timestamp(ts))
            .unwrap_or_else(|| term::dim("—"));

        println!("  {}  {:>15}  {:>8}  {}",
            term::purple(txid_short),
            amount_str,
            term::dim(&confs),
            date,
        );
    }

    term::divider(60);
    println!("  {} {} KRGN  {} {} UTXOs",
        term::dim("Balance:"),
        term::green_bold(&wallet_data.balance_display()),
        term::dim("│"),
        wallet_data.utxos.len(),
    );

    if wallet_data.last_sync_height > 0 {
        println!("  {} block {}",
            term::dim("Synced: "),
            wallet_data.last_sync_height,
        );
    }
    println!();

    // Pagination hint
    let total_pages = (history.len() + page_size - 1) / page_size;
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
    let mut wallet_data = wallet::load_wallet()?;

    // Force full resync
    wallet_data.processed_txids.clear();
    wallet_data.utxos.clear();
    wallet_data.history.clear();

    println!();
    let result = sync_with_spinner(&mut wallet_data)?;

    println!();
    println!("  {} {} KRGN  {} {} UTXOs  {} {} txs",
        term::dim("Balance:"),
        term::green_bold(&wallet_data.balance_display()),
        term::dim("│"),
        wallet_data.utxos.len(),
        term::dim("│"),
        result.processed_txids.len(),
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

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
