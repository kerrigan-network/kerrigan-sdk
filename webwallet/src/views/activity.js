/** Activity page — full transaction history. */

import { store, subscribe, formatKRGN } from '../state.js';
import { icon } from '../components/icons.js';
import { escapeHtml, classifyTx } from '../templates.js';
import { openModal } from '../router.js';
import { setMemo } from './memo.js';
import { renderNav, mountNav } from './dashboard.js';

let unsubs = [];

export function render() {
  return {
    html: `
      <div class="wallet-shell">
        <div class="wallet-content view-enter">
          <div class="section-header" style="margin-bottom: var(--space-lg);">
            <h1 style="font-size: 22px; font-weight: 700;">Activity</h1>
          </div>
          ${renderFilters()}
          <div id="activity-list">
            ${renderTxList(store.history)}
          </div>
        </div>
        ${renderNav('activity')}
      </div>
    `,
    onMount: () => {
      mountNav();
      mountFilters();

      // Event delegation on the list container (stable — its innerHTML gets
      // replaced, but the element itself persists). One listener covers:
      //   - Memo preview click → open memo modal (checked first; stops
      //     propagation so it doesn't also trigger the tx-row's explorer)
      //   - tx-row click → open the on-chain explorer for that txid
      // data-memo and data-txid are both escaped on render to block XSS
      // from hostile remote data (memos are attacker-controllable on
      // incoming shielded txs).
      const listEl = document.getElementById('activity-list');
      listEl?.addEventListener('click', (e) => {
        const memoEl = e.target.closest('.tx-memo-click');
        if (memoEl) {
          e.stopPropagation();
          const text = memoEl.dataset.memo;
          if (!text) return;
          setMemo(text);
          openModal('memo');
          return;
        }
        const row = e.target.closest('[data-txid]');
        const txid = row?.dataset.txid;
        if (!txid || !/^[0-9a-f]{64}$/i.test(txid)) return;
        window.open(`https://explorer.kerrigan.network/#/tx/${txid}`, '_blank', 'noopener');
      });

      unsubs.push(subscribe('history', () => {
        const el = document.getElementById('activity-list');
        if (el) el.innerHTML = renderTxList(getFilteredHistory());
      }));
      return () => { unsubs.forEach(fn => fn()); unsubs = []; };
    },
  };
}

let activeFilter = 'all';

function renderFilters() {
  return `
    <div class="pill-toggle" style="margin-bottom: var(--space-lg);">
      <button class="pill-option active" data-filter="all">All</button>
      <button class="pill-option" data-filter="transparent">Transparent</button>
      <button class="pill-option" data-filter="shielded">Shielded</button>
    </div>
  `;
}

function mountFilters() {
  document.querySelectorAll('[data-filter]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('[data-filter]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeFilter = btn.dataset.filter;
      const listEl = document.getElementById('activity-list');
      if (listEl) listEl.innerHTML = renderTxList(getFilteredHistory());
    });
  });
}

function getFilteredHistory() {
  if (activeFilter === 'all') return store.history;
  return store.history.filter(tx => tx.pool === activeFilter);
}

function renderTxList(txs) {
  if (!txs || txs.length === 0) {
    return `
      <div class="empty-state" style="margin-top: var(--space-2xl);">
        <div class="empty-state-icon">${icon('activity')}</div>
        <p class="empty-state-text">No transactions yet</p>
      </div>
    `;
  }

  const sorted = [...txs].sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
  const rows = sorted.map(tx => renderTxRow(tx)).join('');

  return `<div class="card" style="padding: var(--space-sm) var(--space-md);">${rows}</div>`;
}

function renderTxRow(tx) {
  const { iconName, iconClass, label, amountStr, amountClass } = classifyTx(tx, formatKRGN);

  const time = tx.timestamp > 0
    ? new Date(tx.timestamp).toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
    : '';

  const memoSafe = tx.memo
    ? escapeHtml(tx.memo.slice(0, 20)) + (tx.memo.length > 20 ? '...' : '')
    : '';

  return `
    <div class="tx-row" ${tx.txid ? `data-txid="${escapeHtml(tx.txid)}" style="cursor: pointer;"` : ''}>
      <div class="tx-icon ${iconClass}">
        <span style="width: 18px; height: 18px; display: flex;">${icon(iconName)}</span>
      </div>
      <div class="tx-details">
        <div class="tx-type">${label}</div>
        <div class="tx-meta">
          ${time ? `<span>${time}</span>` : ''}
          ${tx.memo ? `<span class="tx-memo-click" data-memo="${escapeHtml(tx.memo)}">"${memoSafe}"</span>` : ''}
        </div>
      </div>
      <div class="tx-amount">
        <div class="tx-amount-value ${amountClass}">${amountStr}</div>
        <div class="tx-confirmations">
          ${tx.confirmations > 0 ? `${tx.confirmations} conf` : '<span class="text-yellow">pending</span>'}
        </div>
      </div>
    </div>
  `;
}
