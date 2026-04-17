/** Network clients — Bridge (HTTP) + ElectrumX (WebSocket JSON-RPC). */

import { base58Decode } from './utils.js';

const BRIDGE_URL = 'https://kerrigan-bridge.jskitty.cat';
const ELECTRUMX_URL = 'wss://electrum-kerrigan.jskitty.cat:50003';

// ---------------------------------------------------------------------------
// Bridge (HTTP)
// ---------------------------------------------------------------------------

/** Get the current block count from the bridge. */
export async function getBlockCount() {
  const res = await fetch(`${BRIDGE_URL}/getblockcount`);
  if (!res.ok) throw new Error(`Bridge error: ${res.status}`);
  return parseInt(await res.text(), 10);
}

/** Fetch compact shield data as binary ArrayBuffer. */
export async function getShieldData(startBlock = 0) {
  const res = await fetch(`${BRIDGE_URL}/getshielddata?startBlock=${startBlock}&format=compact`);
  if (!res.ok) throw new Error(`Shield data error: ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

/** Broadcast a raw transaction hex via the bridge. */
export async function sendRawTransaction(hexTx) {
  const res = await fetch(`${BRIDGE_URL}/sendrawtransaction`, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: hexTx,
  });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Broadcast failed: ${errText}`);
  }
  return res.text();
}

// ---------------------------------------------------------------------------
// ElectrumX (WebSocket JSON-RPC)
// ---------------------------------------------------------------------------

let ws = null;
let reqId = 0;
const pending = new Map();
const subscriptions = new Map();
let onConnected = null;
let onDisconnected = null;
let reconnectTimer = null;

/** Connect to ElectrumX via WSS. */
export function connectElectrumX({ onConnect, onDisconnect } = {}) {
  onConnected = onConnect || null;
  onDisconnected = onDisconnect || null;
  openSocket();
}

function openSocket() {
  if (ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) return;

  ws = new WebSocket(ELECTRUMX_URL);

  ws.onopen = async () => {
    clearTimeout(reconnectTimer);
    try {
      await electrumRequest('server.version', ['KerriganWallet', '1.4']);
    } catch { /* ignore version response */ }
    onConnected?.();
  };

  ws.onmessage = (event) => {
    let msg;
    try { msg = JSON.parse(event.data); } catch { return; }

    // Subscription notification (no id)
    if (msg.method && !msg.id) {
      const cbs = subscriptions.get(msg.method);
      if (cbs) cbs.forEach(cb => cb(msg.params));
      return;
    }

    // RPC response
    const resolver = pending.get(msg.id);
    if (resolver) {
      pending.delete(msg.id);
      if (msg.error) resolver.reject(new Error(msg.error.message || JSON.stringify(msg.error)));
      else resolver.resolve(msg.result);
    }
  };

  ws.onclose = () => {
    // Drop subscription callbacks on disconnect. Caller's `onConnect` will
    // re-register them on the new socket; without this, each reconnect
    // stacks a fresh anonymous callback onto the Set and every new block
    // fires N duplicate refreshes.
    subscriptions.clear();
    // Reject outstanding requests so callers don't hang forever.
    for (const { reject } of pending.values()) {
      reject(new Error('ElectrumX connection closed'));
    }
    pending.clear();
    onDisconnected?.();
    scheduleReconnect();
  };

  ws.onerror = () => {
    ws?.close();
  };
}

function scheduleReconnect() {
  clearTimeout(reconnectTimer);
  reconnectTimer = setTimeout(openSocket, 5000);
}

/** Send a JSON-RPC request and return a promise for the result. */
export function electrumRequest(method, params = []) {
  return new Promise((resolve, reject) => {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      return reject(new Error('ElectrumX not connected'));
    }
    const id = ++reqId;
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
    // Timeout after 30s
    setTimeout(() => {
      if (pending.has(id)) {
        pending.delete(id);
        reject(new Error(`ElectrumX timeout: ${method}`));
      }
    }, 30000);
  });
}

/** Subscribe to an ElectrumX notification method. */
export function electrumSubscribe(method, params, callback) {
  if (!subscriptions.has(method)) subscriptions.set(method, new Set());
  subscriptions.get(method).add(callback);
  // Send the subscribe request
  return electrumRequest(method, params);
}

/** Close the ElectrumX connection. */
export function disconnectElectrumX() {
  clearTimeout(reconnectTimer);
  onConnected = null;
  onDisconnected = null;
  if (ws) {
    ws.onclose = null;
    ws.close();
    ws = null;
  }
}

// ---------------------------------------------------------------------------
// ElectrumX high-level helpers
// ---------------------------------------------------------------------------

/** Convert a transparent address to a scripthash for ElectrumX queries. */
export async function addressToScripthash(address) {
  // P2PKH: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
  // We need to decode the base58check address to get the pubkey hash,
  // then build the script, then SHA256 and reverse.
  // For now, we use the SDK's hex utilities and do it in JS.
  const raw = base58Decode(address);
  // raw = [version(1)] [pubkeyhash(20)] [checksum(4)]
  const pubkeyHash = raw.slice(1, 21);
  const script = new Uint8Array([0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac]);
  const hashBuffer = await crypto.subtle.digest('SHA-256', script);
  const hashArray = new Uint8Array(hashBuffer);
  // Reverse byte order for ElectrumX
  const reversed = hashArray.slice().reverse();
  return Array.from(reversed).map(b => b.toString(16).padStart(2, '0')).join('');
}


/** Get UTXOs for a transparent address. */
export async function getUTXOs(address) {
  const scripthash = await addressToScripthash(address);
  return electrumRequest('blockchain.scripthash.listunspent', [scripthash]);
}

/** Get transaction history for a transparent address. */
export async function getHistory(address) {
  const scripthash = await addressToScripthash(address);
  return electrumRequest('blockchain.scripthash.get_history', [scripthash]);
}

/** Get a raw transaction hex by txid. */
export async function getRawTransaction(txid) {
  return electrumRequest('blockchain.transaction.get', [txid]);
}

/** Subscribe to new block headers. */
export function subscribeHeaders(callback) {
  return electrumSubscribe('blockchain.headers.subscribe', [], callback);
}
