/** Activity page — full transaction history. */

import { store, subscribe, formatKRGN } from '../state.js';
import { icon } from '../components/icons.js';
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
      unsubs.push(subscribe('history', () => {
        const listEl = document.getElementById('activity-list');
        if (listEl) listEl.innerHTML = renderTxList(getFilteredHistory());
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
  const isReceive = tx.type === 'received';
  const isSelf = tx.type === 'self';
  const isShield = tx.type === 'shield';
  const isUnshield = tx.type === 'unshield';
  const isShielded = tx.pool === 'shielded';
  const iconName = isShield ? 'shieldFilled' : isUnshield ? 'unlock' :
                   isShielded ? 'shieldFilled' : isSelf ? 'refresh' :
                   (isReceive ? 'receive' : 'send');
  const iconClass = (isShield || isShielded) ? 'shielded' : isSelf ? 'sent' :
                    (isReceive ? 'received' : 'sent');

  const label = isShield ? 'Shielded' : isUnshield ? 'Unshielded' :
    isSelf ? 'Self Transfer'
    : isShielded ? (isReceive ? 'Shielded Receive' : 'Shielded Send')
    : (isReceive ? 'Received' : tx.type === 'sent' ? 'Sent' : 'Transaction');

  const amountStr = tx.amount > 0
    ? ((isShield || isUnshield) ? formatKRGN(tx.amount) :
       isSelf ? `-${formatKRGN(tx.amount)} fee` :
       isReceive ? `+${formatKRGN(tx.amount)}` : `-${formatKRGN(tx.amount)}`)
    : '';
  const amountClass = isReceive ? 'positive' : (isShield || isUnshield) ? '' : 'negative';

  const time = tx.timestamp > 0
    ? new Date(tx.timestamp).toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
    : '';

  const txidShort = tx.txid ? `${tx.txid.slice(0, 8)}...` : '';
  const explorerUrl = tx.txid ? `https://explorer.kerrigan.network/#/tx/${tx.txid}` : '';

  return `
    <div class="tx-row" ${explorerUrl ? `style="cursor: pointer;" onclick="window.open('${explorerUrl}', '_blank')"` : ''}>
      <div class="tx-icon ${iconClass}">
        <span style="width: 18px; height: 18px; display: flex;">${icon(iconName)}</span>
      </div>
      <div class="tx-details">
        <div class="tx-type">${label}</div>
        <div class="tx-meta">
          ${time ? `<span>${time}</span>` : ''}
          ${tx.memo ? `<span>"${tx.memo.slice(0, 20)}${tx.memo.length > 20 ? '...' : ''}"</span>` : ''}
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
