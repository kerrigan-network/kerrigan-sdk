/** Network clients — Bridge (HTTP) + ElectrumX (WebSocket JSON-RPC). */

import { base58Decode } from './utils.js';

const BRIDGE_URL = 'https://kerrigan-bridge.jskitty.cat';
const ELECTRUMX_URL = 'wss://electrum-kerrigan.jskitty.cat:50003';
const COORDINATOR_URL = 'https://coordinator.jskitty.cat';
const PRICE_URL = 'https://vote.kerrigan.network/api/price';

// ---------------------------------------------------------------------------
// Market price (HTTP)
// ---------------------------------------------------------------------------

/** Fetch the aggregate KRGN→USD spot price plus per-exchange detail.
 *  Returns { usd, fetchedAt, perExchange } where `usd` is a finite Number or
 *  throws on transport / parse / no-data. Callers should treat any rejection
 *  as "keep the cached value, retry later". */
export async function getKrgnPriceUsd() {
  const res = await fetch(PRICE_URL, { cache: 'no-store' });
  if (!res.ok) throw new Error(`price ${res.status}`);
  const body = await res.json();
  const usd = Number(body?.last);
  if (!isFinite(usd) || usd <= 0) throw new Error('price payload missing finite `last`');
  return {
    usd,
    fetchedAt: Number(body?.fetchedAt) || Date.now(),
    perExchange: Array.isArray(body?.perExchange) ? body.perExchange : [],
  };
}

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
// Inference network (coordinator proxy — HTTP/JSON)
//
// The webwallet hits two endpoints on the coordinator. The coordinator
// VRF-picks a provider from its Iroh-connected relay pool and proxies
// request/response over that tunnel — neither provider URLs nor NAT
// holes are our problem.
//
//   1. POST /v1/invoice  { model, max_tokens }
//      → { amount_sat, rate_sat_per_token, max_tokens, pay_to_address,
//          expires_block, model_hash, drone_pubkey, drone_pubkey_hash }
//
//   2. POST /v1/chat     { drone_pubkey_hash, payment_txid,
//                          prompt, model, max_tokens, temperature,
//                          top_p, seed, k }
//      → { response, token_count, commitment: {...} }
// ---------------------------------------------------------------------------

/** Ask the coordinator to pick a provider and relay back its invoice.
 *  `messages` is the full `[{role, content}, ...]` history the client intends
 *  to submit; the drone tokenises it + checks its KV cache to quote a
 *  cache-hit discount upfront. `droneHash` pins to a specific provider
 *  (session affinity across turns); omit to let the coordinator VRF-select. */
export async function requestInferenceInvoice({ model, messages, maxTokens, droneHash }) {
  const body = { model, messages, max_tokens: maxTokens };
  if (droneHash) body.drone_pubkey_hash = droneHash;
  const res = await fetch(`${COORDINATOR_URL}/v1/invoice`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`invoice ${res.status}: ${text.slice(0, 400)}`);
  }
  return res.json();
}

/** Submit a paid inference request to the coordinator relay.
 *  `invoice` is the object returned by `requestInferenceInvoice`; `messages`
 *  is the full conversation.
 *
 *  Auto-retries on transient relay-layer failures — drone↔coordinator iroh
 *  is UDP-over-NAT and can drop streams when the path flaps. The drone
 *  stores each inference's result keyed by `payment_txid`, so retries
 *  are idempotent: if the first attempt already served the request, the
 *  cached response comes back; if it never reached the drone, a fresh
 *  one runs on the retry. */
export async function submitInferenceChat({ invoice, paymentTxid, messages, model, maxTokens, temperature, topP, seed, k }) {
  const body = JSON.stringify({
    drone_pubkey_hash: invoice.drone_pubkey_hash,
    payment_txid: paymentTxid,
    messages, model,
    max_tokens: maxTokens,
    temperature, top_p: topP,
    seed, k,
  });

  const MAX_ATTEMPTS = 3;
  let lastErr;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      const res = await fetch(`${COORDINATOR_URL}/v1/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      if (!res.ok) {
        const text = await res.text().catch(() => '');
        const msg = text.slice(0, 400);
        const isTransient = res.status >= 500 && (
          msg.includes('connection lost') ||
          msg.includes('relay pool is empty') ||
          msg.includes('drone not connected') ||
          msg.includes('provider not connected') // pre-rename coordinators
        );
        if (isTransient && attempt < MAX_ATTEMPTS) {
          lastErr = new Error(`chat ${res.status}: ${msg}`);
          await new Promise((r) => setTimeout(r, 1500 * attempt));
          continue;
        }
        throw new Error(`chat ${res.status}: ${msg}`);
      }
      const parsed = await res.json();
      if (parsed.error) throw new Error(`provider: ${parsed.error}`);
      return parsed;
    } catch (err) {
      lastErr = err;
      const msg = String(err?.message || err);
      const isNetwork = msg.startsWith('TypeError') || msg.includes('Failed to fetch') || msg.includes('NetworkError');
      if (isNetwork && attempt < MAX_ATTEMPTS) {
        await new Promise((r) => setTimeout(r, 1500 * attempt));
        continue;
      }
      throw err;
    }
  }
  throw lastErr || new Error('chat: exhausted retries');
}

/** Streaming variant of submitInferenceChat. Same paid-inference flow,
 *  but the coordinator returns Server-Sent Events in OpenAI
 *  `chat.completion.chunk` format — every generated token becomes a
 *  delta the caller can render live, and the final chunk carries the
 *  Kerrigan commitment in the `x_kerrigan` extension field for
 *  verification.
 *
 *  Callbacks fire as the stream advances:
 *    - `onDelta(text)`       — one piece of newly-generated text
 *    - `onDone({ commitment, drone_pubkey_hash, token_count, ... })`
 *                             — generation completed cleanly; verification
 *                               metadata in the argument
 *    - `onError(message)`    — generation aborted server-side (drone or
 *                               coord error). Stream terminates.
 *
 *  Returns a Promise that resolves when the stream closes (after the
 *  final [DONE] sentinel) or rejects on transport failure. NO retry
 *  logic — streaming retries would require careful idempotency handling
 *  on the rendered tokens, and the drone's payment_txid cache already
 *  protects against double-billing on a fresh manual retry. */
export async function submitInferenceChatStream({
  invoice, paymentTxid, messages, model, maxTokens, temperature, topP, seed, k,
  onDelta, onDone, onError,
}) {
  const body = JSON.stringify({
    drone_pubkey_hash: invoice.drone_pubkey_hash,
    payment_txid: paymentTxid,
    messages, model,
    max_tokens: maxTokens,
    temperature, top_p: topP,
    seed, k,
    stream: true,
  });

  const res = await fetch(`${COORDINATOR_URL}/v1/chat`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'text/event-stream',
    },
    body,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`chat ${res.status}: ${text.slice(0, 400)}`);
  }
  if (!res.body) {
    throw new Error('chat stream: no response body');
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  let lastKerriganMeta = null;

  // SSE framing: each event is one or more `data: ...` lines terminated
  // by a blank line (`\n\n`). Inside a multi-line data block, lines are
  // joined with `\n`. We chunk-by-chunk decode, accumulate, and split
  // on the blank-line boundary.
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });

    let frameEnd;
    while ((frameEnd = buf.indexOf('\n\n')) !== -1) {
      const frame = buf.slice(0, frameEnd);
      buf = buf.slice(frameEnd + 2);

      // Concat all `data:` lines in this frame (per SSE spec).
      const dataLines = frame
        .split('\n')
        .filter((l) => l.startsWith('data:'))
        .map((l) => l.slice(5).trimStart());
      if (dataLines.length === 0) continue; // comment/keep-alive
      const dataStr = dataLines.join('\n');

      if (dataStr === '[DONE]') {
        onDone?.(lastKerriganMeta);
        return;
      }

      let chunk;
      try { chunk = JSON.parse(dataStr); }
      catch (err) {
        console.warn('SSE chunk parse failed', err, dataStr);
        continue;
      }

      const choice = chunk.choices?.[0];
      const delta = choice?.delta?.content;
      const finish = choice?.finish_reason;
      if (chunk.x_kerrigan) lastKerriganMeta = chunk.x_kerrigan;

      if (delta) onDelta?.(delta);

      if (finish === 'error') {
        onError?.(chunk.x_kerrigan?.error || 'stream error');
        return;
      }
      // finish === 'stop' is the signal that the next event is [DONE];
      // we capture x_kerrigan above and let the [DONE] handler fire onDone.
    }
  }
  // Stream ended without a [DONE] — treat as a clean close anyway, with
  // whatever metadata we did capture.
  onDone?.(lastKerriganMeta);
}

/** List currently registered providers (for model picker hints etc.). */
export async function listDrones() {
  const res = await fetch(`${COORDINATOR_URL}/v1/drones`);
  if (!res.ok) throw new Error(`providers ${res.status}`);
  const body = await res.json();
  return body.drones || [];
}

/** Count of providers actually connected to the coordinator's relay pool
 *  RIGHT NOW (i.e. serving requests this second), not the on-chain
 *  registration count. Driven by the coordinator's heartbeat-aware pool —
 *  registration alone doesn't put you in here, you have to be online
 *  with an active iroh connection. Returns null on error. */
export async function getLiveDroneCount() {
  try {
    const res = await fetch(`${COORDINATOR_URL}/v1/node-id`);
    if (!res.ok) return null;
    const body = await res.json();
    const n = body.connected_drones;
    return typeof n === 'number' ? n : null;
  } catch {
    return null;
  }
}

/** Aggregated list of inference models offered across the network.
 *
 *  Hits the coordinator's `/v1/models` aggregator, which fans out a relay
 *  RPC to every connected provider and dedupes by `gguf_hash`. Each
 *  entry shape:
 *    { id, name, gguf_hash, quant, vram_required_mb, context_length,
 *      providers: [bls_pubkey_hash hex, …],
 *      rate_sat_per_token, in_rate_sat_per_token, cached_rate_sat_per_token }
 *  Returns `[]` when the relay pool is empty or the coordinator is offline. */
export async function listInferenceModels() {
  try {
    const res = await fetch(`${COORDINATOR_URL}/v1/models`);
    if (!res.ok) return [];
    const body = await res.json();
    return body.models || [];
  } catch {
    return [];
  }
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

/** Subscribe to balance/mempool events for a transparent address.
 *
 *  ElectrumX fires the notification on EVERY state change for the
 *  scripthash — new confirmed tx, new mempool tx, reorg, RBF, whatever.
 *  The callback receives `[scripthash, statusHash]`; `statusHash` changes
 *  with state, so a simple "re-fetch UTXOs + history" on each call keeps
 *  the wallet current without having to diff anything ourselves.
 *
 *  The initial subscribe response IS the current status hash — fire the
 *  callback with it once so the caller treats first-sub the same as
 *  any later notification. */
export async function subscribeScripthash(address, callback) {
  const scripthash = await addressToScripthash(address);
  electrumSubscribe('blockchain.scripthash.subscribe', [scripthash], callback)
    .then((initial) => callback([scripthash, initial]))
    .catch(() => {});
}
