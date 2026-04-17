/** Memo modal — displays the full Sapling memo attached to a shielded tx. */

import { createModal } from '../components/modal.js';
import { escapeHtml } from '../templates.js';

let memoText = '';

/** Stage the memo to show. Call before `openModal('memo')`. */
export function setMemo(text) {
  memoText = text || '';
}

export function render() {
  return createModal('Memo', `
    <div style="padding: var(--space-sm) 0;">
      <div style="
        background: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius-md);
        padding: var(--space-md);
        font-size: 14px;
        line-height: 1.6;
        color: var(--text-primary);
        white-space: pre-wrap;
        word-break: break-word;
        max-height: 50vh;
        overflow-y: auto;
      ">${escapeHtml(memoText)}</div>
      <div style="font-size: 12px; color: var(--text-muted); margin-top: var(--space-md); text-align: center;">
        Encrypted inside the Sapling note — only the sender and recipient can read it.
      </div>
    </div>
  `);
}
