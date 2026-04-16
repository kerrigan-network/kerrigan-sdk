/** Reactive store — Proxy-based state with path subscriptions. */

const listeners = new Map();
let state = {};

function notify(path) {
  for (const [key, cbs] of listeners) {
    if (path.startsWith(key) || key.startsWith(path)) {
      cbs.forEach(cb => cb(get(key)));
    }
  }
}

function createProxy(obj, path = '') {
  return new Proxy(obj, {
    set(target, prop, value) {
      target[prop] = value;
      notify(path ? `${path}.${prop}` : prop);
      return true;
    },
    get(target, prop) {
      const val = target[prop];
      if (val && typeof val === 'object' && !ArrayBuffer.isView(val) && !(val instanceof Uint8Array)) {
        return createProxy(val, path ? `${path}.${prop}` : prop);
      }
      return val;
    },
  });
}

function get(path) {
  return path.split('.').reduce((o, k) => o?.[k], state);
}

/** Subscribe to state changes at a dot-delimited path. Returns unsubscribe fn. */
export function subscribe(path, cb) {
  if (!listeners.has(path)) listeners.set(path, new Set());
  listeners.get(path).add(cb);
  return () => listeners.get(path)?.delete(cb);
}

/** The reactive state object. Mutate directly to trigger updates. */
export const store = createProxy(state);

/** Initialize default state shape. */
export function initStore() {
  Object.assign(state, {
    wallet: {
      seed: null,           // Uint8Array (in memory only while unlocked)
      mnemonic: null,       // string (only during creation flow, then cleared)
      transparentAddr: '',
      shieldedAddr: '',
      extfvk: '',
      extsk: '',
    },
    balance: {
      transparent: 0,       // satoshis
      shielded: 0,          // satoshis
      pending: 0,           // satoshis
    },
    sync: {
      shieldHeight: 0,
      targetHeight: 0,
      progress: 0,
      status: 'idle',       // idle | syncing | synced | error
      electrumConnected: false,
    },
    history: [],             // { txid, type, amount, pool, confirmations, memo, timestamp, address }
    ui: {
      view: 'loading',      // loading | welcome | login | dashboard | activity | settings
      modal: null,          // null | 'send' | 'receive'
      toast: null,          // { message, type, id }
    },
  });
}

/** Get computed total balance. */
export function totalBalance() {
  return Number(state.balance.transparent) + Number(state.balance.shielded);
}

/**
 * Format satoshis to a display string with significant/dim digit split.
 * Returns HTML: significant digits at full opacity, lower digits dimmed.
 *
 * Rules:
 * - >= 100: integer part is significant, decimals are dim
 * - >= 1:   2 decimal places significant, rest dim
 * - >= 0.01: 4 decimal places significant, rest dim
 * - < 0.01:  all digits shown, first non-zero decimal cluster significant
 */
export function formatKRGN(sats) {
  const n = Number(sats);
  const val = Math.abs(n) / 1e8;

  // Total visible digits = 8, split between integer and decimal
  const intPart = Math.floor(val);
  const intDigits = intPart === 0 ? 1 : String(intPart).length;
  const decDigits = Math.max(2, 8 - intDigits); // at least 2 decimals

  let str = val.toFixed(decDigits);
  // Trim trailing zeros but keep at least 2 decimal places
  const dot = str.indexOf('.');
  let end = str.length;
  while (end > dot + 3 && str[end - 1] === '0') end--;
  str = str.slice(0, end);

  // Significant digit split: half the decimals are bright, rest dim
  const sigDecimals = Math.max(2, Math.ceil(decDigits / 2));
  let sigEnd = Math.min(dot + 1 + sigDecimals, str.length);

  sigEnd = Math.min(sigEnd, str.length);

  const sig = str.slice(0, sigEnd);
  const dim = str.slice(sigEnd);

  if (!dim) return sig;
  return `${sig}<span class="digits-dim">${dim}</span>`;
}

/** Short format — rounds to 2 decimal places, no dim digits. */
export function formatKRGNShort(sats) {
  const n = Number(sats);
  const val = Math.abs(n) / 1e8;
  if (val >= 1) return val.toFixed(2);
  if (val >= 0.01) return val.toFixed(4);
  return val.toFixed(8).replace(/0+$/, '');
}

/** Plain-text format (no HTML) for non-DOM contexts like clipboard. */
export function formatKRGNPlain(sats) {
  const n = Number(sats);
  const val = Math.abs(n) / 1e8;
  let str = val.toFixed(8);
  const dot = str.indexOf('.');
  let end = str.length;
  while (end > dot + 3 && str[end - 1] === '0') end--;
  return str.slice(0, end);
}
