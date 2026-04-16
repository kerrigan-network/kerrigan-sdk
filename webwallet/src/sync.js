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

/** Trigger a shield sync after a short delay (give bridge time to index). */
export function scheduleShieldSync(delayMs = 5000) {
  setTimeout(() => {
    if (!syncActive) startShieldSync();
  }, delayMs);
}

/** Stop ongoing sync. */
export function stopSync() {
  syncActive = false;
}

/** Refresh transparent balance from ElectrumX UTXOs. */
export async function refreshTransparentBalance() {
  const addr = store.wallet.transparentAddr;
  if (!addr) return;

  try {
    const utxos = await net.getUTXOs(addr);
    const total = utxos.reduce((sum, u) => sum + u.value, 0);
    store.balance.transparent = total;
    await storage.setItem('transparent_utxos', utxos);
  } catch (err) {
    console.error('UTXO fetch error:', err);
  }
}

/** Load all persisted wallet data from IndexedDB into store. */
export async function loadPersistedState() {
  // History
  const saved = await storage.getItem('tx_history');
  if (saved && Array.isArray(saved) && saved.length > 0) {
    store.history.length = 0;
    saved.forEach(tx => store.history.push(tx));
  }

  // Transparent balance from cached UTXOs
  const utxos = await storage.getItem('transparent_utxos');
  if (utxos && Array.isArray(utxos)) {
    store.balance.transparent = utxos.reduce((sum, u) => sum + Number(u.value), 0);
  }

  // Shielded balance from cached notes
  const shieldState = await storage.getItem('shield_state');
  if (shieldState?.notes && Array.isArray(shieldState.notes)) {
    store.balance.shielded = shieldState.notes.reduce((sum, n) => sum + (n.value || 0), 0);
  }
}

/** Persist current history to IndexedDB. */
export async function saveHistory() {
  const plain = store.history.map(tx => ({ ...tx }));
  await storage.setItem('tx_history', JSON.parse(JSON.stringify(plain)));
}

/** Refresh transparent transaction history — only fetches new txs. */
export async function refreshTransparentHistory() {
  const addr = store.wallet.transparentAddr;
  if (!addr) return;

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

        if (txData && txData.vout) {
          for (const out of txData.vout) {
            const outAddr = out.scriptPubKey?.addresses?.[0] || out.scriptPubKey?.address || '';
            if (outAddr === addr) {
              received += Math.round((out.value || 0) * 1e8);
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

        // Detect shielding tx: we sent more than we received back transparently,
        // meaning value went to a shielded output (invisible to ElectrumX).
        // A pure self-send has netAmount ≈ fee only. A shielding tx has netAmount >> fee.
        const likelyShield = isSend && received > 0 && netAmount > 50000; // > 0.0005 KRGN = not just fee
        const isSelf = isSend && received > 0 && netAmount < sent && !likelyShield;

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
            });
            changed = true;
          }
          continue;
        }

        const type = isSelf ? 'self' : (isSend ? 'sent' : 'received');
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
        });
        changed = true;
      }
    }

    if (changed) await saveHistory();
  } catch (err) {
    console.error('History fetch error:', err);
  }
}
