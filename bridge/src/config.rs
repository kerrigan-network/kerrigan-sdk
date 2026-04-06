/// Bridge configuration — CLI args and defaults.
use clap::Parser;

#[derive(Parser, Clone, Debug)]
#[command(name = "kerrigan-bridge")]
#[command(about = "Kerrigan shield sync bridge — serves compact Sapling data to light wallets")]
pub struct Config {
    /// Kerrigan node RPC URL (e.g. http://127.0.0.1:9998)
    #[arg(long, env = "KERRIGAN_RPC_URL", default_value = "http://127.0.0.1:9998")]
    pub rpc_url: String,

    /// RPC username
    #[arg(long, env = "KERRIGAN_RPC_USER", default_value = "rpc")]
    pub rpc_user: String,

    /// RPC password
    #[arg(long, env = "KERRIGAN_RPC_PASS", default_value = "rpc")]
    pub rpc_pass: String,

    /// HTTP listen port for the bridge API
    #[arg(long, env = "KERRIGAN_BRIDGE_PORT", default_value_t = 3000)]
    pub port: u16,

    /// Start scanning from this block height (0 = Sapling activation)
    #[arg(long, default_value_t = 500)]
    pub start_height: u32,

    /// Path to persist the shield block index (JSON)
    #[arg(long, default_value = "shield_index.json")]
    pub index_path: String,
}
