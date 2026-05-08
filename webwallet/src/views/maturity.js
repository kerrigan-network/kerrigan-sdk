/** "What is maturing?" explainer modal — opens when the user taps the
 *  "+ X.XX maturing" badge under the transparent balance.
 *
 *  Background: in Bitcoin/Dash-derived chains (Kerrigan included), any
 *  output created in a coinbase transaction (block-creation TX —
 *  carrying mining + masternode rewards) cannot be spent until it
 *  reaches a depth of `COINBASE_MATURITY = 100` blocks. Spending earlier
 *  triggers `bad-txns-premature-spend-of-coinbase` at the node and the
 *  broadcast 500's. This modal explains why the user's freshly-earned
 *  reward is sitting in "maturing" rather than the spendable pool. */

import { createModal } from '../components/modal.js';
import { store, formatKRGN } from '../state.js';

const COINBASE_MATURITY = 100;
const BLOCK_TIME_SEC = 120; // Kerrigan target block time

export function render() {
  const maturing = Number(store.balance.transparentMaturing) || 0;
  const maturingStr = formatKRGN(maturing);
  const approxMinutes = Math.round((COINBASE_MATURITY * BLOCK_TIME_SEC) / 60);
  const approxHours = (approxMinutes / 60).toFixed(1);

  const body = `
    <div style="display: flex; flex-direction: column; gap: var(--space-md);">

      <div style="
        padding: var(--space-md);
        background: rgba(250, 204, 21, 0.08);
        border: 1px solid rgba(250, 204, 21, 0.25);
        border-radius: var(--radius-md);
        text-align: center;
      ">
        <div style="font-size: 11px; letter-spacing: 0.18em; text-transform: uppercase; color: #FACC15; margin-bottom: 6px;">
          Currently maturing
        </div>
        <div style="font-size: 28px; font-weight: 700; color: var(--text-primary);">
          ${maturingStr}<span style="margin-left: 6px; font-size: 14px; color: var(--text-muted);">KRGN</span>
        </div>
      </div>

      <div>
        <h3 style="font-size: 14px; font-weight: 600; margin: 0 0 6px;">What is this?</h3>
        <p style="font-size: 13px; line-height: 1.6; color: var(--text-secondary); margin: 0;">
          Freshly-earned <strong style="color: var(--text-primary);">masternode</strong>
          and <strong style="color: var(--text-primary);">mining rewards</strong>
          need to age before they can be spent — a small safety window
          that protects the network from short forks double-spending
          newly-minted coins.
        </p>
      </div>

      <div>
        <h3 style="font-size: 14px; font-weight: 600; margin: 0 0 6px;">How long does it take?</h3>
        <p style="font-size: 13px; line-height: 1.6; color: var(--text-secondary); margin: 0;">
          Each reward becomes spendable after
          <strong style="color: var(--text-primary);">${COINBASE_MATURITY} confirmations</strong>
          — roughly <strong style="color: var(--text-primary);">${approxHours} hours</strong>
          (~${approxMinutes} minutes). The wallet moves them into your
          spendable balance automatically.
        </p>
      </div>

    </div>
  `;
  return createModal('Maturing Rewards', body);
}
