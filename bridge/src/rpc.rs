/// JSON-RPC 1.0 client for the Kerrigan full node.
use serde_json::{json, Value};

/// Kerrigan node RPC client with connection pooling.
pub struct RpcClient {
    url: String,
    user: String,
    pass: String,
    agent: ureq::Agent,
    auth: String, // base64-encoded "user:pass"
}

impl RpcClient {
    pub fn new(url: &str, user: &str, pass: &str) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(120))
            .build();
        let auth = base64_encode(format!("{user}:{pass}"));
        Self {
            url: url.to_string(),
            user: user.to_string(),
            pass: pass.to_string(),
            agent,
            auth,
        }
    }

    #[allow(dead_code)]
    pub fn url(&self) -> &str { &self.url }
    #[allow(dead_code)]
    pub fn user(&self) -> &str { &self.user }
    #[allow(dead_code)]
    pub fn pass(&self) -> &str { &self.pass }

    /// Send a JSON-RPC 1.0 request and return the "result" field.
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let body = json!({
            "jsonrpc": "1.0",
            "id": "kerrigan-bridge",
            "method": method,
            "params": params,
        });

        let resp = match self
            .agent
            .post(&self.url)
            .set("Content-Type", "application/json")
            .set("Authorization", &format!("Basic {}", self.auth))
            .send_json(&body)
        {
            Ok(resp) => resp,
            Err(ureq::Error::Status(code, resp)) => {
                // Non-2xx response — extract the body for error details
                let body = resp.into_string().unwrap_or_default();
                return Err(RpcError::Node(format!("HTTP {code}: {body}")));
            }
            Err(e) => return Err(RpcError::Transport(format!("{e}"))),
        };

        let json: Value = resp
            .into_json()
            .map_err(|e| RpcError::Parse(format!("{e}")))?;

        if let Some(err) = json.get("error").filter(|e| !e.is_null()) {
            return Err(RpcError::Node(err.to_string()));
        }

        json.get("result")
            .cloned()
            .ok_or(RpcError::Parse("missing 'result' field".into()))
    }

    /// Get the current block count (chain height).
    pub fn get_block_count(&self) -> Result<u32, RpcError> {
        let result = self.call("getblockcount", json!([]))?;
        result
            .as_u64()
            .map(|n| n as u32)
            .ok_or(RpcError::Parse("blockcount not a number".into()))
    }

    /// Get block hash at the given height.
    pub fn get_block_hash(&self, height: u32) -> Result<String, RpcError> {
        let result = self.call("getblockhash", json!([height]))?;
        result
            .as_str()
            .map(String::from)
            .ok_or(RpcError::Parse("blockhash not a string".into()))
    }

    /// Get a decoded block (verbosity 2 = includes full decoded txs).
    pub fn get_block(&self, hash: &str, verbosity: u32) -> Result<Value, RpcError> {
        self.call("getblock", json!([hash, verbosity]))
    }

    /// Get a raw transaction as hex (verbose=0) or decoded JSON (verbose=1).
    pub fn get_raw_transaction(&self, txid: &str, verbose: bool) -> Result<Value, RpcError> {
        self.call("getrawtransaction", json!([txid, verbose as u32]))
    }

    /// Broadcast a raw transaction hex. Returns the txid.
    pub fn send_raw_transaction(&self, hex: &str) -> Result<String, RpcError> {
        let result = self.call("sendrawtransaction", json!([hex]))?;
        result
            .as_str()
            .map(String::from)
            .ok_or(RpcError::Parse("txid not a string".into()))
    }
}

// ---------------------------------------------------------------------------
// Base64 helper (avoid pulling in a full crate for this)
// ---------------------------------------------------------------------------

fn base64_encode(input: String) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum RpcError {
    Transport(String),
    Parse(String),
    Node(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "RPC transport error: {e}"),
            Self::Parse(e) => write!(f, "RPC parse error: {e}"),
            Self::Node(e) => write!(f, "Node error: {e}"),
        }
    }
}

impl std::error::Error for RpcError {}
