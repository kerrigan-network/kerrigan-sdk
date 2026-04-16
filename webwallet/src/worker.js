/** Web Worker for heavy WASM operations (Sapling proof generation).
 *
 * Follows pivx-shield pattern: WASM lives only in the worker.
 * Params are downloaded + cached directly in the worker — never transferred via postMessage.
 */

let wasm = null;
let paramsLoaded = false;

const BRIDGE = 'https://kerrigan-bridge.jskitty.cat';
const OUTPUT_URL = `${BRIDGE}/params/sapling-output.params`;
const SPEND_URL = `${BRIDGE}/params/sapling-spend.params`;
const OUTPUT_HASH = '2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4';
const SPEND_HASH = '8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13';

const DB_NAME = 'kerrigan-wallet';
const DB_VERSION = 2;

async function initWasm() {
  if (wasm) return;
  const mod = await import('../pkg/kerrigan_sdk.js');
  await mod.default();
  wasm = mod;
}

// ── IndexedDB helpers (worker has its own connection) ──

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('wallet')) db.createObjectStore('wallet');
      if (!db.objectStoreNames.contains('params')) db.createObjectStore('params');
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function dbGet(store, key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).get(key);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
  });
}

async function dbSet(store, key, value) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    const req = tx.objectStore(store).put(value, key);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

// ── Params loading (download + verify + cache) ──

async function ensureParams(onProgress) {
  if (paramsLoaded) return;

  // Try cache first
  const cachedOutput = await dbGet('params', 'sapling-output');
  const cachedSpend = await dbGet('params', 'sapling-spend');

  let outputBytes, spendBytes;

  if (cachedOutput && cachedSpend) {
    outputBytes = new Uint8Array(cachedOutput);
    spendBytes = new Uint8Array(cachedSpend);
    // Skip SHA-256 — already verified on download
    onProgress?.('Loading prover...');
    wasm.load_sapling_params_unchecked(outputBytes, spendBytes);
  } else {
    // Download
    onProgress?.('Downloading output params...');
    const outResp = await fetch(OUTPUT_URL);
    outputBytes = new Uint8Array(await outResp.arrayBuffer());

    onProgress?.('Downloading spend params...');
    const spdResp = await fetch(SPEND_URL);
    spendBytes = new Uint8Array(await spdResp.arrayBuffer());

    // Verify + load (SHA-256 check on first download)
    onProgress?.('Verifying & loading prover...');
    wasm.load_sapling_params(outputBytes, spendBytes);

    // Cache only after verification passes
    onProgress?.('Caching params...');
    await dbSet('params', 'sapling-output', outputBytes.buffer);
    await dbSet('params', 'sapling-spend', spendBytes.buffer);
  }
  paramsLoaded = true;
}

// ── Deserialize base64 params from main thread ──

function deser(obj) {
  if (obj == null) return obj;
  if (obj.__b64 !== undefined) {
    const bin = atob(obj.__b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  if (Array.isArray(obj)) return obj.map(deser);
  if (typeof obj === 'object') {
    const out = {};
    for (const k in obj) out[k] = deser(obj[k]);
    return out;
  }
  return obj;
}

// ── Message handler ──

self.onmessage = async (e) => {
  const { id, type } = e.data;
  const p = deser(e.data.params);
  try {
    await initWasm();

    let jsonStr;
    switch (type) {
      case 'ensureParams': {
        const t0 = performance.now();
        await ensureParams((msg) => {
          self.postMessage({ id: -1, json: `{"status":"${msg}"}` });
        });
        const ms = (performance.now() - t0).toFixed(0);
        jsonStr = `{"ok":true,"ms":${ms}}`;
        break;
      }

      case 'buildShieldTx': {
        await ensureParams();
        const t0 = performance.now();
        jsonStr = wasm.build_shield_tx(
          p.utxos, p.toAddress, BigInt(p.amount), p.memo, p.seed, p.account, p.index
        );
        const ms = (performance.now() - t0).toFixed(0);
        jsonStr = jsonStr.replace('}', `,"proofMs":${ms}}`);
        break;
      }

      case 'buildSaplingSendTx': {
        await ensureParams();
        jsonStr = wasm.build_sapling_send_tx(
          p.notes, p.toAddress, BigInt(p.amount), p.memo, p.seed
        );
        break;
      }

      case 'buildUnshieldTx': {
        await ensureParams();
        jsonStr = wasm.build_unshield_tx(
          p.notes, p.toTransparent, BigInt(p.amount), p.seed
        );
        break;
      }

      default:
        throw new Error(`Unknown task: ${type}`);
    }

    self.postMessage({ id, json: jsonStr });
  } catch (err) {
    self.postMessage({ id, json: null, error: String(err?.message || err) });
  }
};
