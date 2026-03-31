fn main() {
    println!("kerrigan-wallet v{}", env!("CARGO_PKG_VERSION"));
    println!("Usage: kerrigan-wallet <command>");
    println!();
    println!("Commands:");
    println!("  create   Create a new wallet");
    println!("  import   Import wallet from mnemonic");
    println!("  export   Export wallet mnemonic");
    println!("  address  Show receiving address");
    println!("  balance  Show wallet balance");
    println!("  send     Send KRGN");
    println!("  history  Transaction history");
    println!("  sync     Force resync");
}
