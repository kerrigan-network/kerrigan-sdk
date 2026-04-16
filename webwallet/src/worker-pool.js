/** Worker pool — pivx-shield pattern: WASM lives only in the worker. */

let worker = null;
let nextId = 0;
const pending = new Map();

function getWorker() {
  if (!worker) {
    worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
    worker.onmessage = (e) => {
      const { id, json, error } = e.data;
      if (id < 0) return; // worker init status messages
      const resolver = pending.get(id);
      if (!resolver) return;
      pending.delete(id);
      if (error) resolver.reject(new Error(error));
      else resolver.resolve(json ? JSON.parse(json) : {});
    };
    worker.onerror = (e) => {
      for (const [, resolver] of pending) resolver.reject(new Error(`Worker error: ${e.message}`));
      pending.clear();
    };
  }
  return worker;
}

/** Serialize params: Uint8Array → { __b64 } so nothing touches WASM memory. */
function ser(obj) {
  if (obj == null) return obj;
  if (ArrayBuffer.isView(obj)) {
    const bytes = new Uint8Array(obj.buffer, obj.byteOffset, obj.byteLength);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return { __b64: btoa(bin) };
  }
  if (obj instanceof ArrayBuffer) return ser(new Uint8Array(obj));
  if (Array.isArray(obj)) return obj.map(ser);
  if (typeof obj === 'object') {
    const out = {};
    for (const k in obj) if (Object.prototype.hasOwnProperty.call(obj, k)) out[k] = ser(obj[k]);
    return out;
  }
  return obj;
}

export function runInWorker(type, params) {
  return new Promise((resolve, reject) => {
    const id = ++nextId;
    pending.set(id, { resolve, reject });
    getWorker().postMessage({ id, type, params: ser(params) });
  });
}
