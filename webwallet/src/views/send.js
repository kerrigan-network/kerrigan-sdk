/** Send modal — address, amount, confirm, broadcast. */

import { store, formatKRGN, formatKRGNPlain, formatKRGNShort } from '../state.js';
import { createModal } from '../components/modal.js';
import { closeModal } from '../router.js';
import { icon } from '../components/icons.js';
import { showToast } from '../components/toast.js';
import { escapeHtml } from '../templates.js';
import * as sdk from '../sdk.js';
import * as net from '../network.js';
import * as storage from '../storage.js';
import { saveHistory, startShieldSync } from '../sync.js';
import { base58Decode } from '../utils.js';

let prefillAddress = null;
let prefillMax = false;
// Pay-from override for dual-pool sends (null = auto-select).
let forcedSourcePool = null;

/** Set prefill for the next modal open — skips address step. */
export function prefill(address, max = false) {
  prefillAddress = address;
  prefillMax = max;
}

export function render() {
  forcedSourcePool = null;
  if (prefillAddress) {
    const addr = prefillAddress;
    const max = prefillMax;
    prefillAddress = null;
    prefillMax = false;
    return createModal('Send KRGN', '<div id="send-content"></div>', () => {
      showAmountStep(addr, max);
    });
  }
  return createModal('Send KRGN', renderAddressStep(), () => mountAddressStep());
}

// ── Step 1: Address ──

function renderAddressStep() {
  return `
    <div id="send-content" style="display: flex; flex-direction: column; gap: var(--space-lg);">
      <div class="input-group">
        <label class="input-label">Recipient Address</label>
        <input id="send-address" type="text" class="input input-mono"
               placeholder="K... or ks1..." autocomplete="off" autocapitalize="none" spellcheck="false">
        <span id="send-addr-hint" class="input-hint"></span>
      </div>
      <button id="send-next" class="btn btn-primary btn-full" disabled>Continue</button>
    </div>
  `;
}

function mountAddressStep() {
  const input = document.getElementById('send-address');
  const hint = document.getElementById('send-addr-hint');
  const btn = document.getElementById('send-next');

  input?.addEventListener('input', () => {
    const addr = input.value.trim();
    if (addr.length < 10) {
      hint.textContent = '';
      btn.disabled = true;
      return;
    }

    const valid = sdk.validateAddress(addr);
    const isShielded = addr.startsWith('ks1');

    if (valid && isShielded) {
      hint.className = 'input-hint';
      hint.innerHTML = `<span class="badge badge-shielded" style="font-size: 11px;">Shielded</span>`;
      btn.disabled = false;
    } else if (valid) {
      hint.className = 'input-hint';
      hint.innerHTML = `<span class="badge badge-transparent" style="font-size: 11px;">Transparent</span>`;
      btn.disabled = false;
    } else {
      hint.className = 'input-error-text';
      hint.textContent = 'Invalid address';
      btn.disabled = true;
    }
  });

  btn?.addEventListener('click', () => {
    showAmountStep(input.value.trim());
  });

  input?.focus();
}

// ── Helpers ──

function isOwnAddress(address) {
  return address === store.wallet.transparentAddr || address === store.wallet.shieldedAddr;
}

function destinationLabel(address) {
  if (address === store.wallet.shieldedAddr) return 'Your Shielded Wallet';
  if (address === store.wallet.transparentAddr) return 'Your Transparent Wallet';
  return `${address.slice(0, 12)}...${address.slice(-8)}`;
}

// ── Tx type detection ──

function detectTxType(address) {
  const destShielded = address.startsWith('ks1');
  const source = forcedSourcePool || autoSourcePool(address);

  if (destShielded && source === 'transparent') return 'shield';
  if (destShielded && source === 'shielded') return 'sapling-send';
  if (!destShielded && source === 'shielded') return 'unshield';
  return 'transparent';
}

function autoSourcePool(address) {
  const destShielded = address.startsWith('ks1');
  const hasTrans = Number(store.balance.transparent) > 0;
  const hasShield = Number(store.balance.shielded) > 0;

  if (destShielded) return hasTrans ? 'transparent' : 'shielded';
  return hasTrans ? 'transparent' : (hasShield ? 'shielded' : 'transparent');
}

function hasBothPools() {
  return Number(store.balance.transparent) > 0 && Number(store.balance.shielded) > 0;
}

function availableForType(txType) {
  if (txType === 'sapling-send' || txType === 'unshield') return Number(store.balance.shielded);
  return Number(store.balance.transparent);
}

function feeForType(txType) {
  if (txType === 'shield') return sdk.estimateShieldFee();
  if (txType === 'sapling-send') return sdk.estimateShieldSendFee(1);
  if (txType === 'unshield') return sdk.estimateUnshieldFee(1);
  return sdk.estimateTransparentFee(1, 2);
}

/**
 * Exact fee a "send max" transaction will cost, matching what the Rust
 * builder prices internally. Depends on the actual number of inputs, so we
 * load utxos/notes lazily.
 *
 * NOTE: the sapling builder skips the change output when change == 0, but
 * its fee formula still reserves space for one. We must match the formula
 * (not the actual output count) or the builder will reject the tx.
 */
async function computeMaxFee(txType) {
  if (txType === 'shield') return sdk.estimateShieldFee();
  if (txType === 'transparent') {
    const utxos = await loadFullUtxos();
    return sdk.estimateTransparentFee(utxos.length, 1);
  }
  if (txType === 'sapling-send') {
    const notes = await loadShieldNotes();
    return sdk.estimateShieldSendFee(notes.length);
  }
  if (txType === 'unshield') {
    const notes = await loadShieldNotes();
    return sdk.estimateUnshieldFee(notes.length);
  }
  return feeForType(txType);
}

// ── Step 2: Amount ──

function showAmountStep(address, autoMax = false) {
  if (!forcedSourcePool) forcedSourcePool = null; // reset to auto on new flow
  const txType = detectTxType(address);
  const available = availableForType(txType);
  const estFee = feeForType(txType);
  const self = isOwnAddress(address);
  const isShielded = address.startsWith('ks1');
  const sourcePool = forcedSourcePool || autoSourcePool(address);

  const content = document.getElementById('send-content');
  if (!content) return;

  // Pool selector (only when both pools have balance)
  const poolToggle = hasBothPools() ? `
    <div style="margin-bottom: var(--space-xs);">
      <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 6px;">Pay from</div>
      <div class="pill-toggle" style="max-width: 260px;">
        <button class="pill-option ${sourcePool === 'transparent' ? 'active' : ''}" data-pool="transparent">Transparent</button>
        <button class="pill-option ${sourcePool === 'shielded' ? 'active' : ''}" data-pool="shielded">Shielded</button>
      </div>
    </div>
  ` : '';

  // Memo field — Sapling spec allows up to 512 bytes of payload per output, only
  // on sapling-destination txs (shield-in, sapling-send). Unshield has no sapling
  // output to attach a memo to.
  const memoField = isShielded ? `
    <div class="input-group">
      <label class="input-label">Memo <span style="color: var(--text-muted); font-weight: 400;">— optional, private</span></label>
      <textarea id="send-memo" class="input" rows="2" maxlength="512" spellcheck="false"
                placeholder="A note the recipient will see (or yourself, if sending to self)"
                style="resize: none; line-height: 1.4; font-size: 13px;"></textarea>
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <span class="input-hint">Encrypted inside the note — only you and the recipient can read it.</span>
        <span id="memo-bytes" class="input-hint font-mono">0 / 512</span>
      </div>
    </div>
  ` : '';

  content.innerHTML = `
    <div style="display: flex; flex-direction: column; gap: var(--space-lg);">
      <div style="text-align: center;">
        <div style="font-size: 13px; color: var(--text-muted); margin-bottom: 4px;">${self ? (txType === 'shield' ? 'Shielding to' : 'Sending to') : 'Sending to'}</div>
        <div style="font-size: 15px; font-weight: 600; color: ${self ? 'var(--purple-light)' : 'var(--text-primary)'};">${destinationLabel(address)}</div>
        <span class="badge ${isShielded ? 'badge-shielded' : 'badge-transparent'}" style="margin-top: 8px;">${isShielded ? 'Shielded' : 'Transparent'}</span>
      </div>
      ${poolToggle}
      <div class="input-group">
        <label class="input-label">Amount (KRGN)</label>
        <input id="send-amount" type="number" class="input input-mono" placeholder="0.00"
               min="0" step="0.00000001" autocomplete="off" inputmode="decimal">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span class="input-hint">Available: ${formatKRGNShort(available)} KRGN</span>
          <button id="send-max" class="btn btn-ghost" style="font-size: 12px; padding: 2px 8px;">MAX</button>
        </div>
      </div>
      ${memoField}
      <div id="fee-display" style="display: flex; justify-content: space-between; font-size: 13px; color: var(--text-muted);">
        <span>Network Fee</span>
        <span class="font-mono">${formatKRGNShort(estFee)} KRGN</span>
      </div>
      <button id="send-confirm-btn" class="btn btn-primary btn-full" disabled>Review Transaction</button>
      <button id="send-back" class="btn btn-ghost btn-full">Back</button>
    </div>
  `;

  const amountInput = document.getElementById('send-amount');
  const confirmBtn = document.getElementById('send-confirm-btn');
  const maxBtn = document.getElementById('send-max');
  const backBtn = document.getElementById('send-back');
  const memoInput = document.getElementById('send-memo');
  const memoBytesEl = document.getElementById('memo-bytes');
  // Fee that will actually be paid by the built tx. Starts at the display
  // estimate (1-in, 2-out shape) and gets replaced with a precise value
  // when the user picks MAX (no change output, actual input count).
  let currentFee = estFee;

  // Live memo byte counter. Memos are byte-bounded (512), not char-bounded —
  // emoji and other multi-byte chars eat more of the budget than their
  // displayed width suggests, so we show bytes and soft-warn near the limit.
  memoInput?.addEventListener('input', () => {
    const bytes = new TextEncoder().encode(memoInput.value).length;
    if (bytes > 512) {
      // Truncate at the last whole UTF-8 codepoint under 512 bytes.
      let truncated = memoInput.value;
      while (new TextEncoder().encode(truncated).length > 512) {
        truncated = truncated.slice(0, -1);
      }
      memoInput.value = truncated;
    }
    const actualBytes = new TextEncoder().encode(memoInput.value).length;
    memoBytesEl.textContent = `${actualBytes} / 512`;
    memoBytesEl.style.color = actualBytes > 480 ? 'var(--yellow)' : '';
  });

  // Pool toggle
  document.querySelectorAll('[data-pool]').forEach(btn => {
    btn.addEventListener('click', () => {
      forcedSourcePool = btn.dataset.pool;
      showAmountStep(address); // re-render with new pool
    });
  });

  amountInput?.addEventListener('input', () => {
    currentFee = estFee;
    const val = parseFloat(amountInput.value) || 0;
    const sats = Math.round(val * 1e8);
    confirmBtn.disabled = sats <= 0 || sats + currentFee > available;
  });

  maxBtn?.addEventListener('click', async () => {
    const maxFee = await computeMaxFee(txType);
    currentFee = maxFee;
    const maxSats = available - maxFee;
    if (maxSats > 0) {
      amountInput.value = formatKRGNPlain(maxSats);
      confirmBtn.disabled = false;
    }
  });

  confirmBtn?.addEventListener('click', () => {
    const val = parseFloat(amountInput.value) || 0;
    const sats = Math.round(val * 1e8);
    const memo = memoInput?.value?.trim() || '';
    showConfirmStep(address, sats, sats, currentFee, memo);
  });

  // Auto-fill max if prefilled (shield nudge)
  if (autoMax) maxBtn?.click();

  backBtn?.addEventListener('click', () => {
    content.innerHTML = renderAddressStep();
    mountAddressStep();
    document.getElementById('send-address').value = address;
    document.getElementById('send-address').dispatchEvent(new Event('input'));
  });

  amountInput?.focus();
}

// ── Step 3: Confirm ──

function showConfirmStep(address, amountSats, displayAmount, estFee, memo = '') {
  const content = document.getElementById('send-content');
  if (!content) return;

  const isSendMax = amountSats === 0;
  const self = isOwnAddress(address);

  // Memo preview row — only rendered when there's actually a memo. Escaped
  // before interpolation because users can type anything, including HTML.
  const memoRow = memo ? `
    <div class="divider" style="margin: 0;"></div>
    <div style="display: flex; justify-content: space-between; gap: var(--space-md); font-size: 14px;">
      <span style="color: var(--text-muted); flex-shrink: 0;">Memo</span>
      <span style="color: var(--text-primary); font-style: italic; text-align: right; word-break: break-word;">"${escapeHtml(memo)}"</span>
    </div>
  ` : '';

  content.innerHTML = `
    <div style="display: flex; flex-direction: column; gap: var(--space-lg);">
      <div style="text-align: center;">
        <div style="font-size: 36px; font-weight: 700; color: var(--text-bright);">
          ${formatKRGN(displayAmount)} <span style="font-size: 16px; color: var(--text-secondary);">KRGN</span>
        </div>
        ${isSendMax ? `<div style="font-size: 12px; color: var(--purple-light); margin-top: 4px;">${self ? 'Shielding entire balance' : 'Sending entire balance'}</div>` : ''}
      </div>
      <div class="card" style="display: flex; flex-direction: column; gap: var(--space-md);">
        <div style="display: flex; justify-content: space-between; font-size: 14px;">
          <span style="color: var(--text-muted);">To</span>
          <span style="color: ${self ? 'var(--purple-light)' : 'var(--text-primary)'}; font-weight: 500;">${destinationLabel(address)}</span>
        </div>
        ${memoRow}
        <div class="divider" style="margin: 0;"></div>
        <div style="display: flex; justify-content: space-between; font-size: 14px;">
          <span style="color: var(--text-muted);">Fee</span>
          <span class="font-mono">~${formatKRGN(estFee)} KRGN</span>
        </div>
        <div class="divider" style="margin: 0;"></div>
        <div style="display: flex; justify-content: space-between; font-size: 14px; font-weight: 600;">
          <span>Total</span>
          <span class="font-mono">${formatKRGN(displayAmount + estFee)} KRGN</span>
        </div>
      </div>
      <button id="send-broadcast" class="btn btn-primary btn-lg btn-full">Confirm & Send</button>
      <button id="send-back2" class="btn btn-ghost btn-full">Back</button>
    </div>
  `;

  document.getElementById('send-broadcast')?.addEventListener('click', () => {
    broadcastTx(address, amountSats, displayAmount, memo);
  });

  document.getElementById('send-back2')?.addEventListener('click', () => {
    showAmountStep(address);
  });
}

// ── Step 4: Broadcast ──

async function broadcastTx(address, amountSats, displayAmount, memo = '') {
  const content = document.getElementById('send-content');
  const btn = document.getElementById('send-broadcast');
  const txType = detectTxType(address);

  if (btn) { btn.disabled = true; btn.textContent = 'Building transaction...'; }

  try {
    let result;
    const needsParams = txType !== 'transparent';

    // For spending shielded notes, sync to tip first (fresh anchor required)
    if (txType === 'sapling-send' || txType === 'unshield') {
      if (btn) btn.textContent = 'Syncing shield data...';
      await startShieldSync();
    }

    // Worker downloads + caches + loads Sapling params automatically
    if (needsParams) {
      if (btn) btn.textContent = 'Preparing Sapling prover...';
      await sdk.ensureWorkerParams();
      if (btn) btn.textContent = 'Building zero-knowledge proof...';
    }

    if (txType === 'transparent') {
      const utxos = await loadFullUtxos();
      result = sdk.buildTransparentTx(utxos, address, amountSats, store.wallet.seed, 0, 0);

    } else if (txType === 'shield') {
      const utxos = await loadFullUtxos();
      result = await sdk.buildShieldTx(utxos, address, amountSats, memo, store.wallet.seed, 0, 0);

    } else if (txType === 'sapling-send') {
      const notes = await loadShieldNotes();
      result = await sdk.buildSaplingSendTx(notes, address, amountSats, memo, store.wallet.seed);

    } else if (txType === 'unshield') {
      const notes = await loadShieldNotes();
      result = await sdk.buildUnshieldTx(notes, address, amountSats, store.wallet.seed);
    }

    if (btn) btn.textContent = 'Broadcasting...';
    const txid = await net.sendRawTransaction(result.tx_hex);

    // Success screen
    const successLabel = txType === 'shield' ? 'Shielded!' : txType === 'unshield' ? 'Unshielded!' : 'Sent!';
    content.innerHTML = `
      <div style="display: flex; flex-direction: column; align-items: center; gap: var(--space-lg); text-align: center;">
        <div style="width: 56px; height: 56px; border-radius: 50%; background: var(--green-dim); display: flex; align-items: center; justify-content: center;">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
        </div>
        <div>
          <div style="font-size: 20px; font-weight: 700; margin-bottom: 4px;">${successLabel}</div>
          <div style="font-size: 14px; color: var(--text-secondary);">${formatKRGN(displayAmount)} KRGN</div>
        </div>
        <a href="https://explorer.kerrigan.network/#/tx/${result.txid || txid}" target="_blank" rel="noopener"
           class="btn btn-ghost" style="font-size: 13px; gap: 6px;">
          View on Explorer <span style="width: 14px; height: 14px; display: flex;">${icon('externalLink')}</span>
        </a>
        <button id="send-done" class="btn btn-primary btn-full">Done</button>
      </div>
    `;
    document.getElementById('send-done')?.addEventListener('click', closeModal);
    showToast(`${successLabel} ${formatKRGNShort(displayAmount)} KRGN`, 'success');

    // Update local state based on tx type
    await updateStateAfterSend(txType, address, displayAmount, result, memo);

  } catch (err) {
    showToast(`Send failed: ${err.message}`, 'error');
    if (btn) { btn.disabled = false; btn.textContent = 'Confirm & Send'; }
  }
}

/** Load transparent UTXOs with script_pubkey attached. */
async function loadFullUtxos() {
  const utxos = await storage.getItem('transparent_utxos') || [];
  if (utxos.length === 0) throw new Error('No transparent UTXOs available');
  const scriptPubkey = sdk.hexEncode(new Uint8Array(deriveScriptPubkey(store.wallet.transparentAddr)));
  return utxos.map(u => ({
    txid: u.tx_hash, vout: Number(u.tx_pos), amount: Number(u.value), script_pubkey: scriptPubkey,
  }));
}

/** Load shielded notes from IndexedDB shield_state. */
async function loadShieldNotes() {
  const state = await storage.getItem('shield_state');
  const notes = state?.notes;
  if (!notes || notes.length === 0) throw new Error('No shielded notes available');
  return notes;
}

/** Update balances, UTXOs, notes, and history after a successful send. */
async function updateStateAfterSend(txType, address, displayAmount, result, memo = '') {
  const fee = Number(result.fee);
  const self = isOwnAddress(address);
  const sentTxid = result.txid || '';

  if (txType === 'transparent') {
    // Remove spent UTXOs, add change
    const utxos = await storage.getItem('transparent_utxos') || [];
    const spentSet = new Set((result.spent_utxos || []).map(s => `${s[0]}:${s[1]}`));
    const remaining = utxos.filter(u => !spentSet.has(`${u.tx_hash}:${u.tx_pos}`));
    const inputTotal = utxos.reduce((s, u) => s + Number(u.value), 0);
    const changeAmount = inputTotal - displayAmount - fee;
    if (changeAmount > 0) remaining.push({ tx_hash: sentTxid, tx_pos: 1, value: changeAmount, height: 0 });
    await storage.setItem('transparent_utxos', remaining);
    store.balance.transparent = remaining.reduce((s, u) => s + Number(u.value), 0);

  } else if (txType === 'shield') {
    // Shield may be partial: remove only the UTXOs the builder actually
    // consumed, and if the input total exceeded `amount + fee`, record the
    // transparent change so the next ElectrumX refresh doesn't double-count.
    const utxos = await storage.getItem('transparent_utxos') || [];
    const spentSet = new Set((result.spent_utxos || []).map(s => `${s[0]}:${s[1]}`));
    const remaining = utxos.filter(u => !spentSet.has(`${u.tx_hash}:${u.tx_pos}`));
    const inputTotal = utxos
      .filter(u => spentSet.has(`${u.tx_hash}:${u.tx_pos}`))
      .reduce((s, u) => s + Number(u.value), 0);
    const changeAmount = inputTotal - displayAmount - fee;
    // Shield tx places transparent change as vout index 0 (the only
    // transparent output; sapling outputs are in the extra payload).
    if (changeAmount > 0) remaining.push({ tx_hash: sentTxid, tx_pos: 0, value: changeAmount, height: 0 });
    await storage.setItem('transparent_utxos', remaining);
    store.balance.transparent = remaining.reduce((s, u) => s + Number(u.value), 0);
    // Shielded balance won't show until next shield sync picks up the new note.

  } else if (txType === 'sapling-send') {
    // Decrement shielded balance by amount + fee
    store.balance.shielded = Math.max(0, Number(store.balance.shielded) - displayAmount - fee);
    // Remove spent notes by nullifier
    await removeSpentNotes(result.nullifiers);

  } else if (txType === 'unshield') {
    // Decrement shielded balance
    store.balance.shielded = Math.max(0, Number(store.balance.shielded) - displayAmount - fee);
    await removeSpentNotes(result.nullifiers);
    // Note: transparent balance won't show until ElectrumX picks up the new UTXO
  }

  // Insert history entry. Memo is only meaningful for shielded-destination
  // txs (shield, sapling-send) where we actually attached one — the sync
  // layer will also surface the memo on the recipient side when it processes
  // the tx, but for the sender we already know it so attach it now so the
  // UI doesn't flicker "no memo" → "memo" once sync lands.
  if (txType === 'shield') {
    // Shielding: single "Shielded" entry — shield sync will add the receive side
    // Store the txid so ElectrumX transparent history can mark it as a shield tx
    store.history.push({
      txid: sentTxid,
      type: 'shield',
      amount: displayAmount,
      pool: 'shielded',
      confirmations: 0,
      memo,
      timestamp: Date.now(),
      address,
      height: 0,
    });
  } else if (txType === 'unshield') {
    store.history.push({
      txid: sentTxid,
      type: 'unshield',
      amount: displayAmount,
      pool: 'transparent',
      confirmations: 0,
      memo: '',
      timestamp: Date.now(),
      address,
      height: 0,
    });
  } else {
    const pool = txType === 'sapling-send' ? 'shielded' : 'transparent';
    store.history.push({
      txid: sentTxid,
      type: self ? 'self' : 'sent',
      amount: self ? fee : displayAmount,
      pool,
      confirmations: 0,
      memo: pool === 'shielded' ? memo : '',
      timestamp: Date.now(),
      address,
      height: 0,
    });
  }
  await saveHistory();
}

/** Remove spent notes from IndexedDB shield_state by nullifier. */
async function removeSpentNotes(nullifiers) {
  if (!nullifiers || nullifiers.length === 0) return;
  const state = await storage.getItem('shield_state');
  if (!state?.notes) return;
  const nfSet = new Set(nullifiers);
  state.notes = state.notes.filter(n => !nfSet.has(n.nullifier));
  await storage.setItem('shield_state', state);
}

/** Derive P2PKH scriptPubkey bytes from a transparent address. */
function deriveScriptPubkey(address) {
  const raw = base58Decode(address);
  const pubkeyHash = raw.slice(1, 21);
  return [0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac];
}

