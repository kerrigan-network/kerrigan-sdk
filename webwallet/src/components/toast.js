/** Toast notification system. */

import { escapeHtml } from '../templates.js';

let toastTimeout = null;

export function showToast(message, type = 'info', duration = 3000) {
  const root = document.getElementById('toast-root');
  clearTimeout(toastTimeout);

  // `message` often comes from error paths (e.g. `err.message` where the
  // error originated from the bridge, ElectrumX, or decoded on-chain data),
  // so escape before interpolation to keep this out of the XSS blast radius.
  const safeMessage = escapeHtml(message);

  const colors = {
    info: 'var(--purple)',
    success: 'var(--green)',
    error: 'var(--red)',
    warning: 'var(--yellow)',
  };

  const icons = {
    info: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>',
    success: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>',
    error: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>',
    warning: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4M12 17h.01"/></svg>',
  };

  root.innerHTML = `
    <div class="toast" style="
      position: fixed;
      top: var(--space-lg);
      left: 50%;
      transform: translateX(-50%);
      z-index: 10000;
      display: flex;
      align-items: center;
      gap: var(--space-sm);
      padding: 12px var(--space-lg);
      background: var(--bg-elevated);
      border: 1px solid ${colors[type]}33;
      border-radius: var(--radius-md);
      box-shadow: 0 4px 24px rgba(0,0,0,0.4), 0 0 12px ${colors[type]}22;
      color: var(--text-primary);
      font-size: 14px;
      font-weight: 500;
      animation: toastIn 250ms var(--ease-out) both;
      max-width: calc(100vw - 32px);
      cursor: pointer;
    ">
      <span style="color: ${colors[type]}; display: flex;">${icons[type]}</span>
      <span style="flex: 1;">${safeMessage}</span>
      <span class="toast-copy" style="display: flex; opacity: 0.4; margin-left: 4px; transition: opacity 150ms, color 150ms;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg></span>
    </div>
  `;

  const typeLabel = type.charAt(0).toUpperCase() + type.slice(1);
  const toastEl = root.querySelector('.toast');
  toastEl?.addEventListener('click', () => {
    navigator.clipboard.writeText(`${typeLabel} - ${message}`).catch(() => {});
    // Flash feedback
    const copyIcon = toastEl.querySelector('.toast-copy');
    if (copyIcon) {
      copyIcon.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>';
      copyIcon.style.color = 'var(--green)';
    }
  });

  toastTimeout = setTimeout(() => {
    const toast = root.querySelector('.toast');
    if (toast) {
      toast.style.animation = 'toastOut 200ms ease forwards';
      setTimeout(() => { root.innerHTML = ''; }, 200);
    }
  }, duration);
}
