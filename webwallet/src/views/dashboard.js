/** Dashboard — balance, actions, sync status, recent activity. */

import { openModal, navigate } from '../router.js';
import { prefill as prefillSend } from './send.js';
import { setMemo } from './memo.js';
import { store, subscribe, formatKRGN, formatKRGNShort, formatUsd, totalBalance, totalBalanceUsd } from '../state.js';
import { icon } from '../components/icons.js';
import { startShieldSync, scheduleShieldSync, refreshTransparentBalance, refreshTransparentHistory, refreshPendingTxs, refreshTransparentState, loadPersistedState, startPriceSync } from '../sync.js';
import { appHeader, orderedHistory, txRow } from '../templates.js';
import * as net from '../network.js';

let unsubs = [];
let dashboardBooted = false;

/** Reset boot flag (call on lock/logout). */
export function resetDashboard() {
  dashboardBooted = false;
}

export function render() {
  return {
    html: `
      <div class="wallet-shell">
        <div class="wallet-content view-enter">
          ${appHeader(renderSyncBar())}
          ${renderBalanceCard()}
          ${renderActions()}
          <div id="shield-nudge-container">${renderShieldNudge()}</div>
          ${renderRecentTxs()}
        </div>
        ${renderNav('dashboard')}
      </div>
    `,
    onMount: () => {
      // Action buttons
      document.getElementById('btn-send')?.addEventListener('click', () => openModal('send'));
      document.getElementById('btn-receive')?.addEventListener('click', () => openModal('receive'));
      document.getElementById('balance-maturing-btn')?.addEventListener('click', () => openModal('maturity'));
      document.getElementById('shield-nudge-container')?.addEventListener('click', () => {
        if (Number(store.balance.transparent) <= 0) return;
        prefillSend(store.wallet.shieldedAddr, true);
        openModal('send');
      });

      // Nav
      mountNav();
      wireViewAllButton();
      wireMemoClicks();

      // Load persisted state (balance + history) + kick initial render
      loadPersistedState().then(() => {
        updateBalance();
        updateRecentTxs();
        updateSyncBar();
      });

      // Start sync + electrumx only once (not on every nav back)
      if (!dashboardBooted) {
        dashboardBooted = true;
        startShieldSync();
        startPriceSync();
        initElectrumX();
      }

      // Subscribe to state changes for live updates
      unsubs.push(
        subscribe('balance', () => { updateBalance(); updateShieldNudge(); }),
        subscribe('sync', updateSyncBar),
        subscribe('history', updateRecentTxs),
        subscribe('price', updateBalance),
      );

      return () => {
        unsubs.forEach(fn => fn());
        unsubs = [];
      };
    },
  };
}

function initElectrumX() {
  if (store.sync.electrumConnected) {
    // Already connected (e.g. after resync) — just refresh immediately
    refreshTransparentState();
    return;
  }
  net.connectElectrumX({
    onConnect: () => {
      store.sync.electrumConnected = true;
      refreshTransparentState();
      // Per-address subscription: fires on confirmed AND mempool events,
      // so change outputs from a just-broadcast tx are visible as soon as
      // ElectrumX relays them — essential for back-to-back AI inference
      // TXs that spend each other's unconfirmed change.
      const addr = store.wallet.transparentAddr;
      if (addr) {
        net.subscribeScripthash(addr, () => {
          refreshTransparentState();
        });
      }
      net.subscribeHeaders(() => {
        refreshTransparentState();
        // Try shield sync at 3s (optimistic) and 10s (safe fallback)
        scheduleShieldSync(3000);
        scheduleShieldSync(10000);
      });
    },
    onDisconnect: () => {
      store.sync.electrumConnected = false;
    },
  });
}

// ── Balance Card ──

function renderBalanceCard() {
  const total = formatKRGN(totalBalance());
  const transparent = formatKRGN(store.balance.transparent);
  const maturing = Number(store.balance.transparentMaturing) || 0;
  const maturingStr = maturing > 0 ? formatKRGN(maturing) : '';
  const shielded = formatKRGN(store.balance.shielded);
  const usdStr = renderUsdLine();

  // Maturing line lives in the DOM either way; CSS `display:none` when
  // there's nothing maturing keeps the markup stable for `updateBalance()`
  // to flip between empty / populated without re-rendering the card.
  const maturingLine =
    `<button id="balance-maturing-btn" type="button" class="balance-pool-maturing"
            ${maturing > 0 ? '' : 'style="display:none;"'}
            aria-label="What does maturing mean?">
      <span class="balance-pool-maturing-amt" id="balance-maturing">+ ${maturingStr || '0'} maturing</span>
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>
      </svg>
    </button>`;

  return `
    <div class="card balance-card" style="margin-bottom: var(--space-sm);">
      <div class="balance-label">Total Balance</div>
      <div class="balance-total" id="balance-total">
        ${total}<span class="ticker">KRGN</span>
      </div>
      <div class="balance-usd" id="balance-usd">${usdStr}</div>
      <div class="balance-breakdown">
        <div class="balance-pool">
          <span class="balance-pool-icon" style="color: var(--text-muted);"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M2.42012 12.7132C2.28394 12.4975 2.21584 12.3897 2.17772 12.2234C2.14909 12.0985 2.14909 11.9015 2.17772 11.7766C2.21584 11.6103 2.28394 11.5025 2.42012 11.2868C3.54553 9.50484 6.8954 5 12.0004 5C17.1054 5 20.4553 9.50484 21.5807 11.2868C21.7169 11.5025 21.785 11.6103 21.8231 11.7766C21.8517 11.9015 21.8517 12.0985 21.8231 12.2234C21.785 12.3897 21.7169 12.4975 21.5807 12.7132C20.4553 14.4952 17.1054 19 12.0004 19C6.8954 19 3.54553 14.4952 2.42012 12.7132Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M12.0004 15C13.6573 15 15.0004 13.6569 15.0004 12C15.0004 10.3431 13.6573 9 12.0004 9C10.3435 9 9.0004 10.3431 9.0004 12C9.0004 13.6569 10.3435 15 12.0004 15Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
          <div>
            <div class="balance-pool-amount" id="balance-transparent">${transparent}</div>
            <div class="balance-pool-label">Transparent</div>
            ${maturingLine}
          </div>
        </div>
        <div class="balance-pool">
          <span class="balance-pool-icon" style="color: var(--purple-light);"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M10.7429 5.09232C11.1494 5.03223 11.5686 5 12.0004 5C17.1054 5 20.4553 9.50484 21.5807 11.2868C21.7169 11.5025 21.785 11.6103 21.8231 11.7767C21.8518 11.9016 21.8517 12.0987 21.8231 12.2236C21.7849 12.3899 21.7164 12.4985 21.5792 12.7156C21.2793 13.1901 20.8222 13.8571 20.2165 14.5805M6.72432 6.71504C4.56225 8.1817 3.09445 10.2194 2.42111 11.2853C2.28428 11.5019 2.21587 11.6102 2.17774 11.7765C2.1491 11.9014 2.14909 12.0984 2.17771 12.2234C2.21583 12.3897 2.28393 12.4975 2.42013 12.7132C3.54554 14.4952 6.89541 19 12.0004 19C14.0588 19 15.8319 18.2676 17.2888 17.2766M3.00042 3L21.0004 21M9.8791 9.87868C9.3362 10.4216 9.00042 11.1716 9.00042 12C9.00042 13.6569 10.3436 15 12.0004 15C12.8288 15 13.5788 14.6642 14.1217 14.1213" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
          <div>
            <div class="balance-pool-amount" id="balance-shielded" style="color: var(--purple-light);">${shielded}</div>
            <div class="balance-pool-label">Shielded</div>
          </div>
        </div>
      </div>
    </div>
  `;
}

function updateBalance() {
  const totalEl = document.getElementById('balance-total');
  const transEl = document.getElementById('balance-transparent');
  const matBtn = document.getElementById('balance-maturing-btn');
  const matAmt = document.getElementById('balance-maturing');
  const shieldEl = document.getElementById('balance-shielded');
  const usdEl = document.getElementById('balance-usd');
  if (totalEl) totalEl.innerHTML = `${formatKRGN(totalBalance())}<span class="ticker">KRGN</span>`;
  if (transEl) transEl.innerHTML = formatKRGN(store.balance.transparent);
  if (matBtn) {
    const maturing = Number(store.balance.transparentMaturing) || 0;
    if (maturing > 0) {
      matBtn.style.display = '';
      if (matAmt) matAmt.innerHTML = `+ ${formatKRGN(maturing)} maturing`;
    } else {
      matBtn.style.display = 'none';
    }
  }
  if (shieldEl) shieldEl.innerHTML = formatKRGN(store.balance.shielded);
  if (usdEl) usdEl.textContent = renderUsdLine();
}

/** USD line content. Empty string until the first price load resolves —
 *  the .balance-usd container reserves vertical space via min-height so
 *  the layout doesn't jump when the value populates. */
function renderUsdLine() {
  const usd = totalBalanceUsd();
  return usd === null ? '' : `≈ ${formatUsd(usd)}`;
}

// ── Action Buttons ──

function renderActions() {
  const sendIcon = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M18 15L12 9L6 15" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  const receiveIcon = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M6 9L12 15L18 9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  return `
    <div class="actions-row section">
      <button id="btn-send" class="action-btn-slim">
        <div class="action-btn-icon">${sendIcon}</div>
        <span class="action-btn-label">Send</span>
      </button>
      <button id="btn-receive" class="action-btn-slim">
        <div class="action-btn-icon">${receiveIcon}</div>
        <span class="action-btn-label">Receive</span>
      </button>
    </div>
  `;
}

// ── Shield Nudge ──

function renderShieldNudge() {
  if (store.balance.transparent <= 0) return '';
  return `
    <div class="shield-nudge section" id="shield-nudge">
      <div class="shield-nudge-icon">${icon('shield')}</div>
      <div class="shield-nudge-text">
        <div class="shield-nudge-title">Shield your funds</div>
        <div class="shield-nudge-sub">${formatKRGNShort(store.balance.transparent)} KRGN available to shield</div>
      </div>
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2">
        <path d="M9 18l6-6-6-6"/>
      </svg>
    </div>
  `;
}

function updateShieldNudge() {
  const container = document.getElementById('shield-nudge-container');
  if (!container) return;
  container.innerHTML = renderShieldNudge();
  // Click handler is on container (event delegation), no re-bind needed
}

// ── Sync Bar ──

function renderSyncBar() {
  return `
    <div class="sync-bar" id="sync-bar">
      <div class="sync-dot" id="sync-dot"></div>
      <span id="sync-text" style="transition: opacity 200ms ease;">Connecting...</span>
      <div class="progress-bar" id="sync-progress-bar" style="opacity: 0; transition: opacity 300ms ease;">
        <div class="progress-fill" id="sync-progress" style="width: 0%;"></div>
      </div>
    </div>
  `;
}

function updateSyncBar() {
  const dot = document.getElementById('sync-dot');
  const text = document.getElementById('sync-text');
  const progressBar = document.getElementById('sync-progress-bar');
  const progressFill = document.getElementById('sync-progress');
  if (!dot || !text) return;

  const status = store.sync.status;
  const height = store.sync.shieldHeight;
  const target = store.sync.targetHeight;
  const pct = target > 0 ? Math.round((height / target) * 100) : 0;

  if (status === 'syncing') {
    dot.className = 'sync-dot syncing';
    text.textContent = `Syncing shield... ${pct}%`;
    if (progressBar) {
      progressBar.style.opacity = '1';
      progressFill.style.width = `${pct}%`;
    }
  } else if (status === 'synced') {
    dot.className = 'sync-dot';
    text.textContent = 'Synced';
    if (progressBar) {
      progressFill.style.width = '100%';
      setTimeout(() => { progressBar.style.opacity = '0'; }, 600);
    }
  } else if (status === 'error') {
    dot.className = 'sync-dot';
    dot.style.background = 'var(--red)';
    text.textContent = 'Sync error';
    if (progressBar) progressBar.style.opacity = '0';
  } else {
    dot.className = 'sync-dot syncing';
    text.textContent = 'Connecting...';
    if (progressBar) progressBar.style.opacity = '0';
  }
}

// ── Recent Activity ──

function renderRecentTxs() {
  // Same shared ordering + row markup as the full Activity tab — see
  // `orderedHistory` and `txRow` in templates.js. The dashboard just
  // takes the top 5 of the same list, so the two views can never
  // disagree on which entries exist or how they're sorted.
  const txs = orderedHistory(store.history).slice(0, 5);
  if (txs.length === 0) {
    return `
      <div id="recent-activity-section" class="section">
        <div class="section-header">
          <span class="section-title">Recent Activity</span>
        </div>
        <div class="empty-state">
          <div class="empty-state-icon">${icon('activity')}</div>
          <p class="empty-state-text">No transactions yet.<br>Receive some KRGN to get started.</p>
        </div>
      </div>
    `;
  }

  const rows = txs.map((tx) => txRow(tx, formatKRGN)).join('');
  return `
    <div id="recent-activity-section" class="section">
      <div class="section-header">
        <span class="section-title">Recent Activity</span>
        <button id="btn-view-all-activity" class="btn btn-ghost" style="font-size: 13px;">View All</button>
      </div>
      <div class="card" style="padding: var(--space-sm) var(--space-md);">
        ${rows}
      </div>
    </div>
  `;
}

function updateRecentTxs() {
  const el = document.getElementById('recent-activity-section');
  if (!el) return;
  const tmp = document.createElement('div');
  tmp.innerHTML = renderRecentTxs();
  el.replaceWith(tmp.firstElementChild);
  wireViewAllButton();
  wireMemoClicks();
}

function wireViewAllButton() {
  document.getElementById('btn-view-all-activity')?.addEventListener('click', () => {
    document.querySelector('[data-nav=activity]')?.click();
  });
}

/**
 * Bind click handlers on every memo preview in the current recent-activity
 * markup. Called on mount and after every re-render of that section — the
 * section's innerHTML is swapped wholesale (via replaceWith), so listeners
 * attached last render are gone and we always re-attach.
 */
function wireMemoClicks() {
  document.querySelectorAll('#recent-activity-section .tx-memo-click').forEach(el => {
    el.addEventListener('click', (e) => {
      e.stopPropagation();
      const text = el.dataset.memo;
      if (!text) return;
      setMemo(text);
      openModal('memo');
    });
  });
}


// ── Navigation ──

export function renderNav(active = 'dashboard') {
  return `
    <nav class="nav-bar">
      <button class="nav-item ${active === 'dashboard' ? 'active' : ''}" data-nav="dashboard">
        <span class="nav-icon">${icon('home')}</span>
        <span class="nav-label">Home</span>
      </button>
      <button class="nav-item ${active === 'activity' ? 'active' : ''}" data-nav="activity">
        <span class="nav-icon">${icon('activity')}</span>
        <span class="nav-label">Activity</span>
      </button>
      <button class="nav-item ${active === 'ai' ? 'active' : ''}" data-nav="ai">
        <span class="nav-icon">${icon('brain')}</span>
        <span class="nav-label">AI</span>
      </button>
      <button class="nav-item ${active === 'settings' ? 'active' : ''}" data-nav="settings">
        <span class="nav-icon">${icon('settings')}</span>
        <span class="nav-label">Settings</span>
      </button>
    </nav>
  `;
}

export function mountNav() {
  document.querySelectorAll('[data-nav]').forEach(btn => {
    btn.addEventListener('click', () => {
      const view = btn.dataset.nav;
      if (view !== store.ui.view) navigate(view);
    });
  });
}
