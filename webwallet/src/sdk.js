/** Thin async wrapper around the Kerrigan WASM SDK. */

let wasm = null;

/** Initialize the WASM module. Must be called before any other function. */
export async function init() {
  if (wasm) return;
  const mod = await import('../pkg/kerrigan_sdk.js');
  await mod.default();
  wasm = mod;
}

/** Generate a fresh 24-word mnemonic. */
export function generateMnemonic() {
  return wasm.generate_mnemonic();
}

/** Generate a 12-word mnemonic. */
export function generateMnemonic12() {
  return wasm.generate_mnemonic_12();
}

/** Validate a mnemonic phrase. */
export function validateMnemonic(mnemonic) {
  return wasm.validate_mnemonic(mnemonic);
}

/** Derive seed bytes from mnemonic + passphrase. */
export function mnemonicToSeed(mnemonic, passphrase = '') {
  return wasm.mnemonic_to_seed(mnemonic, passphrase);
}

/** Derive a transparent address (K...) from seed at account/index. */
export function deriveAddress(seed, account = 0, index = 0) {
  return wasm.derive_address(seed, account, index);
}

/** Derive transparent WIF private key from seed. */
export function deriveWIF(seed, account = 0, index = 0) {
  return wasm.derive_wif(seed, account, index);
}

/** Derive the Sapling extended spending key (hex-encoded). */
export function deriveSaplingSpendingKey(seed) {
  return wasm.derive_sapling_spending_key(seed);
}

/** Derive the Sapling full viewing key from a spending key. */
export function deriveSaplingViewingKey(extsk) {
  return wasm.derive_sapling_viewing_key(extsk);
}

/** Derive a shielded payment address (ks1...) from a viewing key. */
export function deriveSaplingAddress(extfvk) {
  return wasm.derive_sapling_address(extfvk);
}

/** Derive all keys from seed in one call. */
export function deriveAllKeys(seed) {
  const transparentAddr = deriveAddress(seed, 0, 0);
  const extsk = deriveSaplingSpendingKey(seed);
  const extfvk = deriveSaplingViewingKey(extsk);
  const shieldedAddr = deriveSaplingAddress(extfvk);
  return { transparentAddr, extsk, extfvk, shieldedAddr };
}

/** Parse a binary compact shield stream into block objects. */
export function parseShieldStream(data) {
  return wasm.parse_shield_stream(data);
}

/** Process shield blocks against wallet state. */
export function processShieldBlocks(treeHex, blocks, extfvk, existingNotes) {
  const raw = wasm.process_shield_blocks(treeHex, blocks, extfvk, existingNotes);
  // serde_wasm_bindgen returns Maps — deep-convert to plain objects
  return mapToObject(raw);
}

/** Recursively convert Maps to plain objects. */
function mapToObject(val) {
  if (val instanceof Map) {
    const obj = {};
    for (const [k, v] of val) obj[k] = mapToObject(v);
    return obj;
  }
  if (Array.isArray(val)) return val.map(mapToObject);
  return val;
}

/** Hex encode bytes. */
export function hexEncode(bytes) {
  return wasm.hex_encode(bytes);
}

/** Hex decode string to bytes. */
export function hexDecode(hex) {
  return wasm.hex_decode(hex);
}

/** Debug: compute tree root from commitment tree hex. */
export function debugTreeRoot(treeHex) { return wasm.debug_tree_root(treeHex); }

/** Debug: compute anchor from witness hex. */
export function debugWitnessAnchor(witnessHex) { return wasm.debug_witness_anchor(witnessHex); }

/** Validate a Kerrigan address (transparent or shielded). */
export function validateAddress(address) {
  return wasm.validate_address(address);
}

/**
 * Build and sign a transparent transaction.
 * @param {Array} utxos - [{ txid, vout, amount, script_pubkey }]
 * @param {string} toAddress - destination address
 * @param {number} amount - satoshis (0 = send max)
 * @param {Uint8Array} seed - wallet seed
 * @param {number} account - BIP44 account
 * @param {number} index - BIP44 index
 * @returns {{ tx_hex, txid, fee, spent_utxos }}
 */
export function buildTransparentTx(utxos, toAddress, amount, seed, account = 0, index = 0) {
  return JSON.parse(wasm.build_transparent_tx(utxos, toAddress, BigInt(amount), seed, account, index));
}

/** Estimate transparent tx fee in satoshis. */
export function estimateTransparentFee(inputCount, outputCount) {
  return Number(wasm.estimate_transparent_fee(inputCount, outputCount));
}

/** Estimate shield fee in satoshis (transparent → sapling). */
export function estimateShieldFee() {
  return Number(wasm.estimate_shield_fee());
}

/** Estimate shield-to-shield send fee. */
export function estimateShieldSendFee(numSpends) {
  return Number(wasm.estimate_shield_send_fee(numSpends));
}

/** Estimate unshield fee (sapling → transparent). */
export function estimateUnshieldFee(numSpends) {
  return Number(wasm.estimate_unshield_fee(numSpends));
}

/**
 * Build a shielding transaction (transparent → sapling).
 * Requires Sapling proving params (output + spend).
 */
/**
 * Build a shielding tx via Web Worker (non-blocking).
 */
/**
 * Build a shielding tx via Web Worker (non-blocking).
 * Params must be loaded first via loadSaplingParamsInWorker().
 */
export async function buildShieldTx(utxos, toShieldedAddr, amount, memo, seed, account = 0, index = 0) {
  const { runInWorker } = await import('./worker-pool.js');
  return runInWorker('buildShieldTx', {
    utxos, toAddress: toShieldedAddr, amount, memo, seed, account, index,
  });
}

/** Build a shield-to-shield send via Web Worker (non-blocking). */
export async function buildSaplingSendTx(notes, toAddress, amount, memo, seed) {
  const { runInWorker } = await import('./worker-pool.js');
  return runInWorker('buildSaplingSendTx', { notes, toAddress, amount, memo, seed });
}

/** Build an unshield tx via Web Worker (non-blocking). */
export async function buildUnshieldTx(notes, toTransparent, amount, seed) {
  const { runInWorker } = await import('./worker-pool.js');
  return runInWorker('buildUnshieldTx', { notes, toTransparent, amount, seed });
}

/** Ensure Sapling params are loaded in the worker (downloads + caches automatically). */
export async function ensureWorkerParams() {
  const { runInWorker } = await import('./worker-pool.js');
  return runInWorker('ensureParams', {});
}
