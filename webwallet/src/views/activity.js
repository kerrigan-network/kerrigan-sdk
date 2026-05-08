/** Activity page — full transaction history.
 *
 *  Two perf invariants this view depends on for wallets with thousands of
 *  transactions (otherwise: tab freezes, multi-GB RAM):
 *
 *  1. **Paged DOM.** Only `PAGE_SIZE` rows are rendered at a time; "Show
 *     more" appends another page. Without this, a 50k-tx wallet renders
 *     ~30 MB of HTML in one shot — hundreds of thousands of DOM nodes
 *     plus the browser's layout/render-tree overhead easily costs several
 *     gigabytes of RAM.
 *
 *  2. **Coalesced re-renders.** The `subscribe('history', …)` callback
 *     fires on every state mutation, and `loadPersistedState` pushes N
 *     entries one at a time during boot — that's N rapid-fire re-renders
 *     of the entire list, ~O(N²) work that freezes the tab before the
 *     load even completes. Debounced via `requestAnimationFrame` so any
 *     burst of history mutations collapses to one render per frame.
 */

import { store, subscribe, formatKRGN } from '../state.js';
import { icon } from '../components/icons.js';
import { orderedHistory, txRow } from '../templates.js';
import { openModal } from '../router.js';
import { setMemo } from './memo.js';
import { renderNav, mountNav } from './dashboard.js';

let unsubs = [];

/** How many tx rows to render per page. ~120-200 keeps the DOM well
 *  inside what the browser can lay out + paint without hitches even on
 *  modest hardware, while showing "enough" recent activity that most
 *  users never click "Show more". Tuneable. */
const PAGE_SIZE = 150;

/** Number of pages currently rendered. Resets to 1 on filter change /
 *  view re-mount. The visible row count is `pagesShown * PAGE_SIZE`. */
let pagesShown = 1;

/** Cached ordered+filtered history for the current view session. Built
 *  lazily by `getOrderedFiltered()` and reused across "Show more" clicks
 *  + history-mutation re-renders within the same frame. Invalidated on
 *  filter change OR when subscribe fires (history actually mutated). */
let orderedCache = null;

export function render() {
  // Reset paging on every view mount so re-entering Activity always
  // starts you at the top.
  pagesShown = 1;
  orderedCache = null;

  return {
    html: `
      <div class="wallet-shell">
        <div class="wallet-content view-enter">
          <div class="section-header" style="margin-bottom: var(--space-lg);">
            <h1 style="font-size: 22px; font-weight: 700;">Activity</h1>
          </div>
          ${renderFilters()}
          <div id="activity-list">
            ${renderTxList(getOrderedFiltered())}
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
      //   - "Show more" click → bump page count + re-render
      //   - Memo preview click → open memo modal (checked first; stops
      //     propagation so it doesn't also trigger the tx-row's explorer)
      //   - tx-row click → open the on-chain explorer for that txid
      // data-memo and data-txid are both escaped on render to block XSS
      // from hostile remote data (memos are attacker-controllable on
      // incoming shielded txs).
      const listEl = document.getElementById('activity-list');
      listEl?.addEventListener('click', (e) => {
        const moreBtn = e.target.closest('[data-show-more]');
        if (moreBtn) {
          e.stopPropagation();
          pagesShown += 1;
          rerenderList();
          return;
        }
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

      // Debounced re-render: coalesce a burst of history mutations into
      // one rAF tick. Without this, `loadPersistedState`'s push-loop
      // re-renders the entire (paged) list once per push during boot.
      let renderQueued = false;
      unsubs.push(subscribe('history', () => {
        // Invalidate the ordered cache — history changed.
        orderedCache = null;
        if (renderQueued) return;
        renderQueued = true;
        requestAnimationFrame(() => {
          renderQueued = false;
          rerenderList();
        });
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
      // Filter changed — reset paging + invalidate cache.
      pagesShown = 1;
      orderedCache = null;
      rerenderList();
    });
  });
}

/** Return ordered+filtered history, memoized for the current
 *  filter/history snapshot. The `orderedHistory` sort and filter are
 *  fast individually, but with thousands of txs they add up if we
 *  redo them on every "Show more" click; one cache lookup is cheap. */
function getOrderedFiltered() {
  if (orderedCache) return orderedCache;
  const filtered = activeFilter === 'all'
    ? store.history
    : store.history.filter(tx => tx.pool === activeFilter);
  orderedCache = orderedHistory(filtered);
  return orderedCache;
}

function rerenderList() {
  const el = document.getElementById('activity-list');
  if (el) el.innerHTML = renderTxList(getOrderedFiltered());
}

function renderTxList(orderedTxs) {
  if (!orderedTxs || orderedTxs.length === 0) {
    return `
      <div class="empty-state" style="margin-top: var(--space-2xl);">
        <div class="empty-state-icon">${icon('activity')}</div>
        <p class="empty-state-text">No transactions yet</p>
      </div>
    `;
  }
  // Shared row markup with the dashboard's Recent Activity — see `txRow`
  // in templates.js. Single source of truth for label/icon/format.
  // Slice to the currently-visible page count; "Show more" expands.
  const total = orderedTxs.length;
  const visibleCount = Math.min(total, pagesShown * PAGE_SIZE);
  const visible = orderedTxs.slice(0, visibleCount);
  const rows = visible.map((tx) => txRow(tx, formatKRGN)).join('');

  const remaining = total - visibleCount;
  const showMore = remaining > 0
    ? `<button class="btn btn-secondary" data-show-more
              style="margin: var(--space-md) auto; display: block; min-width: 180px;">
         Show ${Math.min(remaining, PAGE_SIZE)} more
         <span style="opacity: 0.6; font-size: 12px; margin-left: 6px;">
           (${remaining} hidden)
         </span>
       </button>`
    : '';

  return `<div class="card" style="padding: var(--space-sm) var(--space-md);">${rows}</div>${showMore}`;
}
