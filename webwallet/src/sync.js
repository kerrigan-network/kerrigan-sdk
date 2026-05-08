/** Shield sync engine — fetches compact stream from bridge, processes via WASM. */

import { store } from './state.js';
import * as sdk from './sdk.js';
import * as net from './network.js';
import * as storage from './storage.js';

const BATCH_SIZE = 200;
const PERSIST_INTERVAL = 500; // persist every N blocks

let syncActive = false;

/** Start shield sync from last checkpoint. */
export async function startShieldSync() {
  if (syncActive) return;
  syncActive = true;
  store.sync.status = 'syncing';

  try {
    // Load saved state
    const saved = await storage.getItem('shield_state');
    let treeHex = saved?.treeHex || '';
    let notes = saved?.notes || [];
    let lastHeight = saved?.lastHeight || 499; // Sapling activates at block 500

    // Get target height
    const targetHeight = await net.getBlockCount();
    store.sync.targetHeight = targetHeight;
    store.sync.shieldHeight = lastHeight;

    if (lastHeight >= targetHeight) {
      store.sync.status = 'synced';
      updateShieldBalance(notes);
      syncActive = false;
      return;
    }

    // Fetch compact shield stream
    const data = await net.getShieldData(lastHeight + 1);
    if (data.length === 0) {
      store.sync.status = 'synced';
      updateShieldBalance(notes);
      syncActive = false;
      return;
    }

    // Parse into blocks
    const allBlocks = sdk.parseShieldStream(data);
    if (!allBlocks || allBlocks.length === 0) {
      store.sync.status = 'synced';
      syncActive = false;
      return;
    }

    // Process in batches
    let blocksSinceLastPersist = 0;
    for (let i = 0; i < allBlocks.length; i += BATCH_SIZE) {
      if (!syncActive) break;

      const batch = allBlocks.slice(i, i + BATCH_SIZE);
      const result = sdk.processShieldBlocks(treeHex, batch, store.wallet.extfvk, notes);

      treeHex = result.commitment_tree || treeHex;
      notes = result.updated_notes || notes;
      if (result.new_notes?.length) {
        for (const n of result.new_notes) notes.push(n);
      }

      // Merge new notes into history (skip duplicates)
      // Notes update balance via the notes array — history is NOT managed here.
      // Shielded history comes from local inserts on send (shield/unshield/sapling-send).
      // We only update existing pending entries with accurate amounts from shield sync.
      if (result.new_notes) {
        for (const note of result.new_notes) {
          const val = note.value || 0;
          const pendingShield = store.history.find(h =>
            h.type === 'shield' && h.confirmations === 0 && Math.abs(h.amount - val) < 100000
          );
          if (pendingShield) {
            pendingShield.amount = val;
            if (note.memo) pendingShield.memo = note.memo;
          }
        }
      }

      // Track spent nullifiers
      if (result.spent_nullifiers?.length) {
        notes = notes.filter(n => !result.spent_nullifiers.includes(n.nullifier));
      }

      const batchEnd = batch[batch.length - 1];
      lastHeight = batchEnd?.height || lastHeight;
      store.sync.shieldHeight = lastHeight;

      // Update progress
      const progress = (lastHeight - 499) / (targetHeight - 499);
      store.sync.progress = Math.min(progress, 1);

      blocksSinceLastPersist += batch.length;
      if (blocksSinceLastPersist >= PERSIST_INTERVAL) {
        await storage.setItem('shield_state', { treeHex, notes, lastHeight });
        blocksSinceLastPersist = 0;
      }
    }

    // Final persist
    await storage.setItem('shield_state', { treeHex, notes, lastHeight });
    await saveHistory();
    updateShieldBalance(notes);
    store.sync.status = 'synced';
  } catch (err) {
    console.error('Shield sync error:', err);
    store.sync.status = 'error';
  } finally {
    syncActive = false;
  }
}

function updateShieldBalance(notes) {
  const total = notes.reduce((sum, n) => sum + (n.value || 0), 0);
  store.balance.shielded = total;
}

/** Trigger a full refresh after a short delay (give bridge time to index). */
export function scheduleShieldSync(delayMs = 5000) {
  setTimeout(async () => {
    if (!syncActive) await startShieldSync();
    // Always refresh balances from persisted state after sync
    await loadPersistedState();
  }, delayMs);
}

/** Stop ongoing sync. */
export function stopSync() {
  syncActive = false;
}

// ── Price sync ─────────────────────────────────────────────────────────────
// Polls vote.kerrigan.network/api/price; persists the last good value to
// IndexedDB so reloads paint the cached USD figure synchronously rather than
// flashing "—" while the network round-trip is in flight.

const PRICE_REFRESH_MS = 5 * 60_000; // 5 minutes — exchanges aren't ticking faster than the wallet cares about
let priceTimer = null;

/** Kick off the price polling loop. Idempotent — calling more than once is
 *  a no-op. The first fetch runs immediately so a freshly-decrypted wallet
 *  picks up the live price even if no cached value was on disk. */
export function startPriceSync() {
  if (priceTimer) return;
  refreshPrice(); // fire-and-forget; updates store on success
  priceTimer = setInterval(refreshPrice, PRICE_REFRESH_MS);
}

/** Stop the price polling loop (e.g. on lock/logout). */
export function stopPriceSync() {
  if (priceTimer) {
    clearInterval(priceTimer);
    priceTimer = null;
  }
}

async function refreshPrice() {
  try {
    const { usd, fetchedAt } = await net.getKrgnPriceUsd();
    store.price.usd = usd;
    store.price.fetchedAt = fetchedAt;
    await storage.setItem('price_cache', { usd, fetchedAt });
  } catch (err) {
    // Swallow — the cached value (if any) stays in the store and the next
    // tick retries. A transient feed outage shouldn't surface as a UI error.
    console.warn('price refresh failed:', err?.message || err);
  }
}

/** Bitcoin / Dash heritage: coinbase outputs (mining + masternode rewards)
 *  cannot be spent until they reach `COINBASE_MATURITY` confirmations.
 *  Trying to spend earlier triggers `bad-txns-premature-spend-of-coinbase`
 *  at the node and the broadcast 500's. Kerrigan inherits the standard
 *  100-block window. */
export const COINBASE_MATURITY = 100;

/** In-memory + persisted cache of "is this txid a coinbase?" so we don't
 *  refetch the parent tx on every UTXO refresh. Keyed by txid; values
 *  are booleans. Coinbase status is immutable for any given tx so the
 *  cache never goes stale. */
let coinbaseTxCache = null;
async function getCoinbaseCache() {
  if (coinbaseTxCache) return coinbaseTxCache;
  coinbaseTxCache = (await storage.getItem('coinbase_txid_cache')) || {};
  return coinbaseTxCache;
}
async function persistCoinbaseCache() {
  if (coinbaseTxCache) await storage.setItem('coinbase_txid_cache', coinbaseTxCache);
}

/** Determine whether a Kerrigan tx is coinbase. Coinbase tx vin shape per
 *  the bitcoind RPC verbose form: a single entry with a `coinbase` field
 *  instead of `txid`/`vout`. Cached per txid. Returns `false` on any
 *  fetch / parse failure (treated as non-coinbase, which is the safe
 *  default — the broadcast still fail-louds at the node if the guess
 *  was wrong, matching pre-fix behavior rather than silently regressing). */
async function isCoinbaseTx(txid) {
  const cache = await getCoinbaseCache();
  if (txid in cache) return cache[txid];
  try {
    // `verbose=true` returns the decoded JSON (with `vin[0].coinbase`
    // for coinbase txs); the default `getRawTransaction` returns hex
    // which we'd have to parse ourselves.
    const tx = await net.electrumRequest('blockchain.transaction.get', [txid, true]);
    const vin0 = tx?.vin?.[0];
    cache[txid] = !!(vin0 && (vin0.coinbase !== undefined && vin0.coinbase !== null));
    await persistCoinbaseCache();
    return cache[txid];
  } catch (err) {
    console.warn(`coinbase check failed for ${txid}:`, err);
    return false; // treat as non-coinbase; broadcast will fail-loud at node if wrong
  }
}

/** Enrich a list of raw Electrum UTXOs with `coinbase` + `mature` flags.
 *  - `coinbase`: parent tx is a coinbase
 *  - `mature`: `!coinbase` OR (chainHeight - utxo.height + 1) >= COINBASE_MATURITY
 *  - `confirmations`: depth at the time of enrichment (informational)
 *  Cache hits make repeat refreshes O(0 RPCs); fresh UTXOs incur one
 *  `blockchain.transaction.get` per unique txid. */
async function enrichUtxosWithMaturity(utxos) {
  let chainHeight = store.sync.targetHeight;
  if (!chainHeight) {
    try { chainHeight = await net.getBlockCount(); } catch { chainHeight = 0; }
  }
  const uniqueTxids = [...new Set(utxos.map((u) => u.tx_hash))];
  const coinbaseFlags = {};
  for (const txid of uniqueTxids) {
    coinbaseFlags[txid] = await isCoinbaseTx(txid);
  }
  return utxos.map((u) => {
    const isCoinbase = !!coinbaseFlags[u.tx_hash];
    const height = Number(u.height) || 0;
    const confs = (height > 0 && chainHeight > 0) ? (chainHeight - height + 1) : 0;
    const mature = !isCoinbase || confs >= COINBASE_MATURITY;
    return { ...u, coinbase: isCoinbase, mature, confirmations: confs };
  });
}

/** Refresh transparent balance from ElectrumX UTXOs.
 *
 *  `listunspent` already returns mempool UTXOs (height = 0) alongside
 *  confirmed ones — the sum and UTXO cache both naturally include
 *  unconfirmed change, which is what lets the AI tab send back-to-back
 *  inference TXs without waiting for a block.
 *
 *  Coinbase maturity: each UTXO is tagged with `coinbase` and `mature`
 *  flags so downstream `loadFullUtxos` filters can skip immature
 *  masternode rewards. **`store.balance.transparent` represents the
 *  SPENDABLE balance only (mature UTXOs)** — that's what every other
 *  consumer means by "balance" (Send Max button, shield nudge,
 *  totalBalance(), etc.). Immature coinbase UTXOs are tracked
 *  separately in `transparentMaturing` so the dashboard can show
 *  "1.234 spendable + 0.5 maturing" without the user mistaking
 *  in-flight rewards for funds they can move right now. */
export async function refreshTransparentBalance() {
  const addr = store.wallet.transparentAddr;
  if (!addr) return;

  try {
    const raw = await net.getUTXOs(addr);
    const enriched = await enrichUtxosWithMaturity(raw);
    const spendable = enriched
      .filter((u) => u.mature !== false)
      .reduce((sum, u) => sum + Number(u.value), 0);
    const maturing = enriched
      .filter((u) => !u.mature)
      .reduce((sum, u) => sum + Number(u.value), 0);
    store.balance.transparent = spendable;
    store.balance.transparentMaturing = maturing;
    await storage.setItem('transparent_utxos', enriched);
  } catch (err) {
    console.error('UTXO fetch error:', err);
  }
}

/** One-shot combined refresh — balance (UTXOs) + history + any pending
 *  confirmation updates. Called from `subscribeHeaders` AND
 *  `subscribeScripthash` — both fire when a relevant tx lands in a new
 *  block, so concurrent invocations are routine. The mutex inside
 *  `refreshTransparentHistory` collapses overlapping calls; the
 *  balance + pending-confs paths are idempotent. */
export async function refreshTransparentState() {
  await Promise.all([
    refreshTransparentBalance(),
    refreshTransparentHistory(),
    refreshPendingTxs(),
  ]);
}

/** Load all persisted wallet data from IndexedDB into store. */
export async function loadPersistedState() {
  // History
  const saved = await storage.getItem('tx_history');
  if (saved && Array.isArray(saved) && saved.length > 0) {
    store.history.length = 0;
    // Heal duplicates accumulated under the pre-mutex code path. For
    // any txid seen more than once, keep the entry with the highest
    // confirmation count (the older, more-settled record). First pass
    // picks the winner per txid; second pass walks `saved` once to
    // preserve insertion order, emitting each txid the first time we
    // hit any of its rows.
    const winners = new Map();
    for (const tx of saved) {
      if (!tx?.txid) continue;
      const cur = winners.get(tx.txid);
      if (!cur || Number(tx.confirmations || 0) > Number(cur.confirmations || 0)) {
        winners.set(tx.txid, tx);
      }
    }
    const seen = new Set();
    for (const tx of saved) {
      if (!tx?.txid) {
        store.history.push(tx); // pre-fix entries without txid — preserve as-is
        continue;
      }
      if (seen.has(tx.txid)) continue;
      seen.add(tx.txid);
      store.history.push(winners.get(tx.txid));
    }
    if (store.history.length !== saved.length) {
      console.info(`history dedup: collapsed ${saved.length} entries to ${store.history.length}`);
      await saveHistory();
    }
  }

  // Transparent balance from cached UTXOs. `transparent` is the
  // SPENDABLE balance only (mature UTXOs); maturing coinbase outputs
  // are tracked separately. Pre-fix UTXOs lack the `mature` flag —
  // default to mature=true (`u.mature !== false`) so legacy data
  // counts normally; the next refresh re-enriches them.
  const utxos = await storage.getItem('transparent_utxos');
  if (utxos && Array.isArray(utxos)) {
    store.balance.transparent = utxos
      .filter((u) => u.mature !== false)
      .reduce((sum, u) => sum + Number(u.value), 0);
    store.balance.transparentMaturing = utxos
      .filter((u) => u.mature === false)
      .reduce((sum, u) => sum + Number(u.value), 0);
  }

  // Shielded balance from cached notes
  const shieldState = await storage.getItem('shield_state');
  if (shieldState?.notes && Array.isArray(shieldState.notes)) {
    store.balance.shielded = shieldState.notes.reduce((sum, n) => sum + (n.value || 0), 0);
  }

  // Cached spot price — populated synchronously so the dashboard's first
  // paint shows the last-known USD value instead of "—" while the live
  // fetch is in flight.
  const cachedPrice = await storage.getItem('price_cache');
  if (cachedPrice && isFinite(Number(cachedPrice.usd)) && Number(cachedPrice.usd) > 0) {
    store.price.usd = Number(cachedPrice.usd);
    store.price.fetchedAt = Number(cachedPrice.fetchedAt) || 0;
  }

  // One-shot background heal: re-check any history entries classified as
  // shield-sends from before the `txTouchesShieldedPool` fix landed.
  // Entries that pre-date the fix have `inferenceKind === undefined`; the
  // real shielding emitter (send.js + shield-sync) writes defined values.
  healMisclassifiedShieldEntries().catch(() => {});
}

/** Re-verify any history rows that the old netAmount-based heuristic
 *  tagged as shield sends but weren't actually shield txs — typically
 *  external transparent payments (AI inference, merchant sends) with a
 *  large non-fee netAmount.
 *
 *  Walks rows with `type: 'shield'` and `inferenceKind === undefined`
 *  (missing the newer marker field), fetches each tx, and if the decoded
 *  body doesn't touch the Sapling pool, reclassifies it as `sent`. Runs
 *  in the background after first load so it doesn't gate the UI. */
async function healMisclassifiedShieldEntries() {
  const addr = store.wallet.transparentAddr;
  if (!addr) return;
  const candidates = store.history.filter(h =>
    h.type === 'shield' && h.inferenceKind === undefined && h.txid,
  );
  if (candidates.length === 0) return;

  let changed = false;
  for (const entry of candidates) {
    try {
      const txData = await net.electrumRequest('blockchain.transaction.get', [entry.txid, true]);
      if (txTouchesShieldedPool(txData)) continue; // actually shielded, leave it

      // Figure out whether value flowed out or came in, and tag any
      // inference-protocol OP_RETURN we find.
      let received = 0;
      let externalTransparentOut = false;
      let inferenceKind = null;
      for (const out of (txData?.vout || [])) {
        const outAddr = out.scriptPubKey?.addresses?.[0] || out.scriptPubKey?.address || '';
        const valueSat = Math.round((out.value || 0) * 1e8);
        const marker = parseInferenceOpReturn(out.scriptPubKey?.hex);
        if (marker && !inferenceKind) inferenceKind = marker.kind;
        if (outAddr === addr) received += valueSat;
        else if (outAddr) externalTransparentOut = true;
      }
      // `entry.amount` on the old path was netAmount = sent - received.
      const netAmount = Number(entry.amount) || 0;
      const isSend = externalTransparentOut || netAmount > 0;

      entry.pool = 'transparent';
      entry.type = isSend ? 'sent' : 'received';
      entry.amount = isSend ? netAmount : received;
      entry.inferenceKind = inferenceKind;
      changed = true;
    } catch {
      // Skip — next refresh will re-attempt.
    }
  }
  if (changed) await saveHistory();
}

/**
 * Refresh confirmations for any pending (confs=0) history entries.
 *
 * Works for ALL tx types regardless of destination — queries each txid
 * directly via `blockchain.transaction.get` instead of relying on the
 * user's transparent-address history. Fixes the case where unshield /
 * sapling-send to a non-self address would stay "Pending" forever.
 */
export async function refreshPendingTxs() {
  // Two passes of work fold into this loop:
  //   1. confirmations=0 rows — check if they've confirmed yet.
  //   2. height=0 rows that ARE confirmed (legacy shield/unshield entries
  //      stamped with height=0 as a mempool placeholder and never
  //      backfilled). Without this heal, `orderedHistory` has to treat
  //      them specially forever.
  const needsRefresh = store.history.filter((h) => {
    if (!h.txid) return false;
    if (Number(h.confirmations) === 0) return true;
    if (!h.height || h.height <= 0) return true;
    return false;
  });
  if (needsRefresh.length === 0) return;

  let changed = false;
  for (const tx of needsRefresh) {
    try {
      const txData = await net.electrumRequest('blockchain.transaction.get', [tx.txid, true]);
      const confs = Number(txData?.confirmations) || 0;
      if (confs > 0 && tx.confirmations !== confs) {
        tx.confirmations = confs;
        changed = true;
      }
      // Backfill height so downstream sorting works. Electrum returns
      // either an explicit `blockheight` field OR just confirmations +
      // the chain tip — we use whichever is available, preferring the
      // authoritative one.
      if ((!tx.height || tx.height <= 0) && confs > 0) {
        let h = Number(txData?.blockheight) || 0;
        if (h <= 0) {
          const tip = Number(store.sync.targetHeight) || 0;
          if (tip > 0) h = tip - confs + 1;
        }
        if (h > 0 && h !== tx.height) {
          tx.height = h;
          changed = true;
        }
      }
    } catch {
      // Tx not yet known to the node/ElectrumX — leave pending, try next block.
    }
  }

  if (changed) await saveHistory();
}

/** Persist current history to IndexedDB. */
export async function saveHistory() {
  const plain = store.history.map(tx => ({ ...tx }));
  await storage.setItem('tx_history', JSON.parse(JSON.stringify(plain)));
}

/** Did this decoded transaction touch the Sapling (or Sprout) pool?
 *
 *  Zcash-style txs expose a handful of canonical fields for shielded IO;
 *  any of them being non-zero means value crossed between the transparent
 *  and shielded pools. This is the authoritative replacement for the old
 *  "netAmount > 50k sat" heuristic, which misclassified ordinary external
 *  transparent sends (like AI inference payments) as "Shielded". */
function txTouchesShieldedPool(txData) {
  if (!txData) return false;
  if (Number(txData.valueBalanceSapling || txData.valueBalance || 0) !== 0) return true;
  if ((txData.vShieldedSpend?.length || 0) > 0) return true;
  if ((txData.vShieldedOutput?.length || 0) > 0) return true;
  if ((txData.vJoinSplit?.length || 0) > 0) return true;
  return false;
}

/** Parse an OP_RETURN scriptPubKey hex into its inference-protocol marker,
 *  if any. Returns null for non-OP_RETURN outputs or unknown type bytes.
 *  Inference protocol uses 0x01..0x06 type markers — see spec §13 and
 *  `kerrigan-inference/crates/krgn-drone/src/wire`. */
function parseInferenceOpReturn(scriptHex) {
  const hex = String(scriptHex || '').toLowerCase();
  if (!hex.startsWith('6a')) return null; // not OP_RETURN
  let pos = 2;
  const op = parseInt(hex.slice(pos, pos + 2), 16);
  pos += 2;
  let len;
  if (op >= 0x01 && op <= 0x4b) {
    len = op;
  } else if (op === 0x4c) { // OP_PUSHDATA1
    len = parseInt(hex.slice(pos, pos + 2), 16);
    pos += 2;
  } else {
    return null;
  }
  const payloadHex = hex.slice(pos, pos + len * 2);
  if (payloadHex.length !== len * 2) return null;
  const typeByte = parseInt(payloadHex.slice(0, 2), 16);
  const KINDS = {
    0x01: 'register',
    0x02: 'payment',
    0x03: 'rep',
    0x04: 'escalation',
    0x05: 'verdict',
    0x06: 'refund',
  };
  const kind = KINDS[typeByte];
  if (!kind) return null;
  return { kind, typeByte, payloadHex };
}

// Mutex for `refreshTransparentHistory`. Prevents the race that
// otherwise duplicates entries: the function awaits an electrum
// fetch, then later awaits transaction.get for each new txid, and
// only pushes after those resolve. If a second invocation lands
// during any of those awaits, both can pass the `exists` check
// before either push, and both push the same txid — visible as
// duplicate "Masternode Reward" rows. The header + scripthash
// subscriptions both fire on every new block touching us, so
// overlap is the common case, not the edge case. New invocations
// while one is in-flight short-circuit; the in-flight call already
// reads the latest state when it resumes.
let _historyRefreshInFlight = false;

/** Refresh transparent transaction history — only fetches new txs. */
export async function refreshTransparentHistory() {
  const addr = store.wallet.transparentAddr;
  if (!addr) return;
  if (_historyRefreshInFlight) return;
  _historyRefreshInFlight = true;

  try {
    const scripthash = await net.addressToScripthash(addr);
    const historyItems = await net.electrumRequest('blockchain.scripthash.get_history', [scripthash]);
    if (!historyItems || historyItems.length === 0) return;

    // Get current chain height for confirmations
    let chainHeight = store.sync.targetHeight;
    if (!chainHeight) {
      try { chainHeight = await net.getBlockCount(); } catch { chainHeight = 0; }
    }

    let changed = false;

    for (const item of historyItems) {
      const exists = store.history.find(h => h.txid === item.tx_hash);
      if (exists) {
        // Update confirmations from height
        if (item.height > 0 && chainHeight > 0) {
          const confs = chainHeight - item.height + 1;
          if (exists.confirmations !== confs) {
            exists.confirmations = confs;
            changed = true;
          }
        }
        continue;
      }

      // New tx — fetch full details
      try {
        const txData = await net.electrumRequest('blockchain.transaction.get', [item.tx_hash, true]);
        let received = 0;
        let sent = 0;
        let inferenceKind = null;
        let externalTransparentOut = false;

        if (txData && txData.vout) {
          for (const out of txData.vout) {
            const outAddr = out.scriptPubKey?.addresses?.[0] || out.scriptPubKey?.address || '';
            const outScriptHex = out.scriptPubKey?.hex || '';
            const valueSat = Math.round((out.value || 0) * 1e8);

            // OP_RETURN — check for an inference-protocol marker.
            const marker = parseInferenceOpReturn(outScriptHex);
            if (marker && !inferenceKind) inferenceKind = marker.kind;

            if (outAddr === addr) {
              received += valueSat;
            } else if (outAddr) {
              // Any non-self transparent recipient makes this a genuine
              // external transparent send — not a shielding tx.
              externalTransparentOut = true;
            }
          }

          // Check inputs — ElectrumX may not include address, so look up prev tx
          for (const inp of txData.vin || []) {
            // Try direct fields first
            if (inp.address === addr) {
              sent += Math.round((inp.prevout?.value || inp.value || 0) * 1e8);
              continue;
            }
            if (inp.prevout?.scriptPubKey?.addresses?.includes(addr)) {
              sent += Math.round((inp.prevout.value || 0) * 1e8);
              continue;
            }
            // Fallback: fetch the previous tx to check the spent output
            if (inp.txid && inp.vout !== undefined) {
              try {
                const prevTx = await net.electrumRequest('blockchain.transaction.get', [inp.txid, true]);
                const spentOutput = prevTx?.vout?.[inp.vout];
                const spentAddr = spentOutput?.scriptPubKey?.addresses?.[0] || spentOutput?.scriptPubKey?.address || '';
                if (spentAddr === addr) {
                  sent += Math.round((spentOutput.value || 0) * 1e8);
                }
              } catch { /* skip if lookup fails */ }
            }
          }
        }

        const isSend = sent > 0;
        const netAmount = sent - received;
        // Shielding is determined by the tx actually touching the Sapling
        // pool — NOT by guessing from value flows. An AI inference payment
        // is (transparent in) → (transparent out to provider) + OP_RETURN
        // + (transparent change); no shielded fields, so it's a plain send.
        const likelyShield = isSend && txTouchesShieldedPool(txData) && !externalTransparentOut;
        const isSelf = isSend && received > 0 && !externalTransparentOut && !likelyShield;

        // Skip shielding txs — shield sync handles the history for these
        if (likelyShield) {
          // Just add a shield entry if not already present
          const existing = store.history.find(h => h.txid === item.tx_hash);
          if (!existing) {
            const confs = (item.height > 0 && chainHeight > 0) ? chainHeight - item.height + 1 : 0;
            store.history.push({
              txid: item.tx_hash,
              type: 'shield',
              amount: netAmount,
              pool: 'shielded',
              confirmations: confs,
              memo: '',
              timestamp: (txData?.time || 0) * 1000,
              address: '',
              height: item.height,
              inferenceKind,
            });
            changed = true;
          }
          continue;
        }

        // Coinbase tx → masternode/mining reward (categorise as 'reward'
        // rather than generic 'received' so the history view can render
        // a distinct label + icon and the user can see at a glance
        // which incoming UTXOs are reward-derived). Coinbase is the
        // canonical bitcoind/Dash signal: the single vin entry carries
        // a `coinbase` field instead of `txid`/`vout`. Outbound txs
        // can never be coinbase (coinbase has no spendable inputs), so
        // the override only matters for the `received` branch.
        const isCoinbase = !!(txData?.vin?.[0]?.coinbase !== undefined && txData?.vin?.[0]?.coinbase !== null);
        const type = isCoinbase && !isSend
          ? 'reward'
          : (isSelf ? 'self' : (isSend ? 'sent' : 'received'));
        const amount = isSelf ? netAmount : (isSend ? netAmount : received);
        const confs = (item.height > 0 && chainHeight > 0) ? chainHeight - item.height + 1 : 0;

        store.history.push({
          txid: item.tx_hash,
          type,
          amount,
          pool: 'transparent',
          confirmations: confs,
          memo: '',
          timestamp: (txData?.time || 0) * 1000,
          address: addr,
          height: item.height,
          inferenceKind,
          coinbase: isCoinbase,
        });
        changed = true;
      } catch {
        store.history.push({
          txid: item.tx_hash,
          type: 'received',
          amount: 0,
          pool: 'transparent',
          confirmations: item.height > 0 ? 1 : 0,
          memo: '',
          timestamp: 0,
          address: addr,
          height: item.height,
          inferenceKind: null,
        });
        changed = true;
      }
    }

    if (changed) await saveHistory();
  } catch (err) {
    console.error('History fetch error:', err);
  } finally {
    _historyRefreshInFlight = false;
  }
}
