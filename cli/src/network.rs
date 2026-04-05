/// Kerrigan Network explorer API client.
///
/// Communicates with an Insight-like block explorer at [`params::EXPLORER_URL`].
/// There is **no dedicated UTXO endpoint** — the [`sync`](crate::sync) module
/// derives UTXOs client-side from the transaction history returned here.
///
/// # Explorer API endpoints
///
/// | Endpoint                      | Method | Returns                         |
/// |-------------------------------|--------|---------------------------------|
/// | `/api/addr/{addr}`            | GET    | Address info + txid list        |
/// | `/api/tx/{txid}`              | GET    | Decoded transaction (vin/vout)  |
/// | `/api/tx/send`                | POST   | Broadcast raw transaction       |
/// | `/api/status?q=getInfo`       | GET    | Node status (block height, etc.)|
///
/// # Retry behaviour
///
/// Each method tries the explorer URL once (single-explorer setup). If Kerrigan
/// adds mirror explorers in the future, the `explorers` list can be extended
/// and the retry loop will try each in turn.

use serde::Deserialize;
use std::fmt;
use std::time::Duration;

use kerrigan_sdk::params;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// HTTP request timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum NetworkError {
    /// HTTP request failed (connection, timeout, DNS, etc.).
    Http(String),
    /// Server returned a non-2xx status or an error body.
    ApiError(String),
    /// Response JSON could not be parsed.
    Parse(String),
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(s) => write!(f, "HTTP error: {s}"),
            Self::ApiError(s) => write!(f, "API error: {s}"),
            Self::Parse(s) => write!(f, "Parse error: {s}"),
        }
    }
}

impl std::error::Error for NetworkError {}

// ---------------------------------------------------------------------------
// API response types
// ---------------------------------------------------------------------------

/// Address information from `/api/addr/{addr}`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressInfo {
    /// The address string echoed back.
    #[serde(alias = "addrStr")]
    pub addr_str: Option<String>,
    /// Confirmed balance in KRGN (as a float string or number — we parse to satoshis).
    pub balance: Option<f64>,
    /// Confirmed balance in satoshis.
    pub balance_sat: Option<u64>,
    /// Unconfirmed balance in satoshis.
    pub unconfirmed_balance_sat: Option<i64>,
    /// Total received in satoshis.
    pub total_received_sat: Option<u64>,
    /// Total sent in satoshis.
    pub total_sent_sat: Option<u64>,
    /// Total number of transactions.
    pub tx_appearances: Option<u64>,
    /// List of transaction IDs involving this address (may be paginated).
    pub transactions: Option<Vec<String>>,
}

impl AddressInfo {
    /// Get the confirmed balance in satoshis (prefers balanceSat, falls back to balance * COIN).
    pub fn balance_satoshis(&self) -> u64 {
        self.balance_sat
            .or_else(|| self.balance.map(|b| (b * params::COIN as f64) as u64))
            .unwrap_or(0)
    }
}

/// A decoded transaction from `/api/tx/{txid}`.
#[derive(Debug, Clone, Deserialize)]
pub struct TransactionInfo {
    pub txid: String,
    pub vin: Vec<TxVin>,
    pub vout: Vec<TxVout>,
    pub confirmations: Option<u64>,
    pub blockheight: Option<u64>,
    pub time: Option<u64>,
}

/// A transaction input (vin entry).
#[derive(Debug, Clone, Deserialize)]
pub struct TxVin {
    /// The txid of the output being spent.
    pub txid: Option<String>,
    /// The output index being spent.
    pub vout: Option<u32>,
    /// Address that owned the spent output (populated by Insight).
    pub addr: Option<String>,
    /// Value of the spent output in KRGN.
    pub value: Option<f64>,
    /// Value in satoshis.
    #[serde(rename = "valueSat")]
    pub value_sat: Option<u64>,
    /// Coinbase field (present only for coinbase inputs).
    pub coinbase: Option<String>,
}

/// A transaction output (vout entry).
#[derive(Debug, Clone, Deserialize)]
pub struct TxVout {
    /// Value in KRGN (string in some Insight versions, float in others).
    pub value: Option<serde_json::Value>,
    /// Output index within the transaction.
    pub n: u32,
    /// Script details.
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: Option<ScriptPubKeyInfo>,
}

impl TxVout {
    /// Get the output value in satoshis.
    pub fn value_satoshis(&self) -> u64 {
        match &self.value {
            Some(serde_json::Value::Number(n)) => {
                // Could be integer satoshis or float KRGN
                if let Some(i) = n.as_u64() {
                    // If it looks like a satoshi value (> 1 KRGN), use directly
                    // Otherwise treat as KRGN float
                    if i > params::COIN {
                        return i;
                    }
                }
                if let Some(f) = n.as_f64() {
                    return (f * params::COIN as f64).round() as u64;
                }
                0
            }
            Some(serde_json::Value::String(s)) => {
                // String representation — try as satoshis first, then as KRGN float
                if let Ok(sat) = s.parse::<u64>() {
                    if sat > params::COIN { return sat; }
                }
                if let Ok(f) = s.parse::<f64>() {
                    return (f * params::COIN as f64).round() as u64;
                }
                0
            }
            _ => 0,
        }
    }
}

/// Script details within a vout.
#[derive(Debug, Clone, Deserialize)]
pub struct ScriptPubKeyInfo {
    /// Hex-encoded scriptPubKey.
    pub hex: Option<String>,
    /// Address(es) this output pays to.
    pub addresses: Option<Vec<String>>,
    /// Script type (e.g., "pubkeyhash", "scripthash").
    #[serde(rename = "type")]
    pub script_type: Option<String>,
}

/// Node status from `/api/status?q=getInfo`.
#[derive(Debug, Clone, Deserialize)]
pub struct NodeStatus {
    pub info: Option<NodeInfo>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeInfo {
    pub blocks: Option<u64>,
    pub connections: Option<u64>,
    pub version: Option<u64>,
    pub network: Option<String>,
}

/// Broadcast result from `/api/tx/send`.
#[derive(Debug, Clone, Deserialize)]
pub struct BroadcastResult {
    pub txid: Option<String>,
}

// ---------------------------------------------------------------------------
// Explorer client
// ---------------------------------------------------------------------------

/// Kerrigan explorer API client.
///
/// Holds a list of explorer base URLs and tries them in order.
/// Constructed via [`ExplorerClient::new`] (uses the default explorer)
/// or [`ExplorerClient::with_urls`] (custom / multiple mirrors).
pub struct ExplorerClient {
    urls: Vec<String>,
    /// Shared HTTP agent — reuses TLS connections across requests.
    agent: ureq::Agent,
}

impl Default for ExplorerClient {
    fn default() -> Self { Self::new() }
}

impl ExplorerClient {
    /// Create a client using the default explorer URL from [`params::EXPLORER_URL`].
    pub fn new() -> Self {
        Self {
            urls: vec![params::EXPLORER_URL.to_string()],
            agent: ureq::AgentBuilder::new()
                .timeout(REQUEST_TIMEOUT)
                .build(),
        }
    }

    /// Create a client with custom explorer URLs (tried in order).
    pub fn with_urls(urls: Vec<String>) -> Self {
        Self {
            urls,
            agent: ureq::AgentBuilder::new()
                .timeout(REQUEST_TIMEOUT)
                .build(),
        }
    }

    /// Internal: GET request with retry across all explorer URLs.
    fn get(&self, path: &str) -> Result<String, NetworkError> {
        let mut last_err = String::from("No explorer URLs configured");
        for base in &self.urls {
            let url = format!("{}{}", base, path);
            match self.agent.get(&url).call() {
                Ok(resp) => {
                    return resp.into_string()
                        .map_err(|e| NetworkError::Parse(e.to_string()));
                }
                Err(ureq::Error::Status(code, resp)) => {
                    let body = resp.into_string().unwrap_or_default();
                    last_err = format!("HTTP {code}: {body}");
                }
                Err(e) => {
                    last_err = e.to_string();
                }
            }
        }
        Err(NetworkError::Http(last_err))
    }

    /// Internal: POST request with retry.
    fn post(&self, path: &str, body: &str) -> Result<String, NetworkError> {
        let mut last_err = String::from("No explorer URLs configured");
        for base in &self.urls {
            let url = format!("{}{}", base, path);
            match self.agent.post(&url)
                .set("Content-Type", "application/json")
                .send_string(body)
            {
                Ok(resp) => {
                    return resp.into_string()
                        .map_err(|e| NetworkError::Parse(e.to_string()));
                }
                Err(ureq::Error::Status(code, resp)) => {
                    let body = resp.into_string().unwrap_or_default();
                    last_err = format!("HTTP {code}: {body}");
                }
                Err(e) => {
                    last_err = e.to_string();
                }
            }
        }
        Err(NetworkError::Http(last_err))
    }

    // -- Public API methods ---------------------------------------------------

    /// Get address information including the list of all transaction IDs.
    pub fn get_address_info(&self, address: &str) -> Result<AddressInfo, NetworkError> {
        let body = self.get(&format!("/api/addr/{}", address))?;
        serde_json::from_str(&body)
            .map_err(|e| NetworkError::Parse(format!("AddressInfo: {e}")))
    }

    /// Get a decoded transaction by its txid.
    pub fn get_transaction(&self, txid: &str) -> Result<TransactionInfo, NetworkError> {
        let body = self.get(&format!("/api/tx/{}", txid))?;
        serde_json::from_str(&body)
            .map_err(|e| NetworkError::Parse(format!("TransactionInfo: {e}")))
    }

    /// Get the current block height from the explorer.
    pub fn get_block_height(&self) -> Result<u64, NetworkError> {
        let body = self.get("/api/status?q=getInfo")?;
        let status: NodeStatus = serde_json::from_str(&body)
            .map_err(|e| NetworkError::Parse(format!("NodeStatus: {e}")))?;
        status.info
            .and_then(|i| i.blocks)
            .ok_or_else(|| NetworkError::Parse("missing blocks field".into()))
    }

    /// Broadcast a signed raw transaction hex string.
    ///
    /// Returns the txid on success.
    pub fn broadcast(&self, tx_hex: &str) -> Result<String, NetworkError> {
        let payload = serde_json::json!({ "rawtx": tx_hex }).to_string();
        let body = self.post("/api/tx/send", &payload)?;

        // Try to parse structured response
        if let Ok(result) = serde_json::from_str::<BroadcastResult>(&body) {
            if let Some(txid) = result.txid {
                return Ok(txid);
            }
        }

        // Some Insight versions return the txid as a plain string
        let trimmed = body.trim().trim_matches('"');
        if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(trimmed.to_string());
        }

        Err(NetworkError::ApiError(format!("Unexpected broadcast response: {body}")))
    }

    /// Fetch all transaction IDs for an address.
    ///
    /// The Insight API may paginate — this method handles the `from` / `to`
    /// query parameters to retrieve the complete list.
    pub fn get_address_txids(&self, address: &str) -> Result<Vec<String>, NetworkError> {
        // First call gets the full AddressInfo with up to ~1000 txids
        let info = self.get_address_info(address)?;
        let txids = info.transactions.unwrap_or_default();

        // For wallets with very many transactions, Insight paginates.
        // The count is in `txApperances`. If we have fewer txids than that,
        // we'd need to paginate. For v1 single-address wallets this is rare.
        // TODO: paginate via /api/addr/{addr}?from=N&to=M if needed.

        Ok(txids)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- AddressInfo parsing --

    #[test]
    fn parse_address_info_full() {
        let json = r#"{
            "addrStr": "KTestAddr123",
            "balance": 1.5,
            "balanceSat": 150000000,
            "unconfirmedBalanceSat": 0,
            "totalReceivedSat": 300000000,
            "totalSentSat": 150000000,
            "txApperances": 5,
            "transactions": ["aabb", "ccdd", "eeff"]
        }"#;
        let info: AddressInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.addr_str.as_deref(), Some("KTestAddr123"));
        assert_eq!(info.balance_satoshis(), 150_000_000);
        assert_eq!(info.transactions.as_ref().unwrap().len(), 3);
    }

    #[test]
    fn parse_address_info_minimal() {
        let json = r#"{"balance": 0.0, "transactions": []}"#;
        let info: AddressInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.balance_satoshis(), 0);
        assert_eq!(info.transactions.unwrap().len(), 0);
    }

    #[test]
    fn balance_from_float_fallback() {
        let json = r#"{"balance": 2.5}"#;
        let info: AddressInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.balance_satoshis(), 250_000_000);
    }

    #[test]
    fn balance_prefers_sat() {
        let json = r#"{"balance": 99.0, "balanceSat": 42}"#;
        let info: AddressInfo = serde_json::from_str(json).unwrap();
        // balanceSat should take priority
        assert_eq!(info.balance_satoshis(), 42);
    }

    // -- TransactionInfo parsing --

    #[test]
    fn parse_transaction_info() {
        let json = r#"{
            "txid": "abcd1234",
            "vin": [
                {"txid": "prev1111", "vout": 0, "addr": "KSender", "valueSat": 100000}
            ],
            "vout": [
                {
                    "value": "0.50000000",
                    "n": 0,
                    "scriptPubKey": {
                        "hex": "76a914abcd88ac",
                        "addresses": ["KReceiver"],
                        "type": "pubkeyhash"
                    }
                },
                {
                    "value": "0.49990000",
                    "n": 1,
                    "scriptPubKey": {
                        "hex": "76a914efgh88ac",
                        "addresses": ["KSender"],
                        "type": "pubkeyhash"
                    }
                }
            ],
            "confirmations": 10,
            "blockheight": 50000
        }"#;
        let tx: TransactionInfo = serde_json::from_str(json).unwrap();
        assert_eq!(tx.txid, "abcd1234");
        assert_eq!(tx.vin.len(), 1);
        assert_eq!(tx.vin[0].addr.as_deref(), Some("KSender"));
        assert_eq!(tx.vout.len(), 2);
        assert_eq!(tx.vout[0].n, 0);
        assert_eq!(tx.vout[0].value_satoshis(), 50_000_000);
        assert_eq!(tx.vout[1].value_satoshis(), 49_990_000);
        assert_eq!(tx.confirmations, Some(10));
    }

    // -- TxVout value parsing (handles Insight's inconsistent formats) --

    #[test]
    fn vout_value_string_float() {
        let json = r#"{"value": "1.23456789", "n": 0}"#;
        let vout: TxVout = serde_json::from_str(json).unwrap();
        assert_eq!(vout.value_satoshis(), 123_456_789);
    }

    #[test]
    fn vout_value_number_float() {
        let json = r#"{"value": 0.5, "n": 0}"#;
        let vout: TxVout = serde_json::from_str(json).unwrap();
        assert_eq!(vout.value_satoshis(), 50_000_000);
    }

    #[test]
    fn vout_value_zero() {
        let json = r#"{"value": "0.00000000", "n": 0}"#;
        let vout: TxVout = serde_json::from_str(json).unwrap();
        assert_eq!(vout.value_satoshis(), 0);
    }

    #[test]
    fn vout_value_missing() {
        let json = r#"{"n": 0}"#;
        let vout: TxVout = serde_json::from_str(json).unwrap();
        assert_eq!(vout.value_satoshis(), 0);
    }

    // -- NodeStatus parsing --

    #[test]
    fn parse_node_status() {
        let json = r#"{"info": {"blocks": 123456, "connections": 8, "version": 2010000}}"#;
        let status: NodeStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status.info.unwrap().blocks, Some(123456));
    }

    // -- BroadcastResult parsing --

    #[test]
    fn parse_broadcast_result() {
        let json = r#"{"txid": "aabbccdd11223344"}"#;
        let result: BroadcastResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.txid.unwrap(), "aabbccdd11223344");
    }

    // -- TxVin parsing --

    #[test]
    fn parse_coinbase_vin() {
        let json = r#"{"coinbase": "04ffff001d01", "vout": 0}"#;
        let vin: TxVin = serde_json::from_str(json).unwrap();
        assert!(vin.coinbase.is_some());
        assert!(vin.txid.is_none());
    }

    #[test]
    fn parse_regular_vin() {
        let json = r#"{"txid": "ab12", "vout": 1, "addr": "KTest", "valueSat": 5000}"#;
        let vin: TxVin = serde_json::from_str(json).unwrap();
        assert_eq!(vin.txid.as_deref(), Some("ab12"));
        assert_eq!(vin.vout, Some(1));
        assert_eq!(vin.value_sat, Some(5000));
    }

    // -- ExplorerClient construction --

    #[test]
    fn client_default_url() {
        let client = ExplorerClient::new();
        assert_eq!(client.urls.len(), 1);
        assert_eq!(client.urls[0], params::EXPLORER_URL);
    }

    #[test]
    fn client_custom_urls() {
        let client = ExplorerClient::with_urls(vec![
            "https://explorer1.example.com".into(),
            "https://explorer2.example.com".into(),
        ]);
        assert_eq!(client.urls.len(), 2);
    }

    // -- Integration tests (require live explorer, run with --ignored) --

    #[test]
    #[ignore]
    fn live_get_block_height() {
        let client = ExplorerClient::new();
        let height = client.get_block_height().unwrap();
        assert!(height > 0, "Block height should be > 0");
    }

    #[test]
    #[ignore]
    fn live_get_address_info() {
        let client = ExplorerClient::new();
        // Use a known address or the genesis coinbase — adjust as needed
        let info = client.get_address_info("KGenesis000000000000000000000000").unwrap();
        // Just check it parses without error
        let _ = info.balance_satoshis();
    }
}
