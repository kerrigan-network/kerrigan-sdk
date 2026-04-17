/** Reusable HTML template functions for the Kerrigan Wallet UI. */

import { icon } from './components/icons.js';

/**
 * Escape untrusted text for safe interpolation into an HTML string.
 *
 * Use whenever rendering data that could have come from outside the wallet:
 * Sapling memos, tx IDs, addresses entered by third parties, error messages
 * surfaced from the bridge/ElectrumX, etc. Never interpolate such values
 * into innerHTML without running them through this first.
 */
export function escapeHtml(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

// ── App header ──

export function appHeader(rightContent = '') {
  return `
    <div class="app-header">
      <div class="app-logo">
        <img src="/logo.png" alt="Kerrigan">
        <div>
          <div class="app-logo-text">Kerrigan</div>
          <div class="app-logo-sub">Wallet</div>
        </div>
      </div>
      ${rightContent}
    </div>
  `;
}

// ── Layout shells ──

export function fullscreen(content, classes = '') {
  return `<div class="view-fullscreen gradient-mesh ${classes}">${content}</div>`;
}

export function walletShell(content, nav) {
  return `<div class="wallet-shell"><div class="wallet-content view-enter">${content}</div>${nav}</div>`;
}

// ── Typography ──

export function pageTitle(text) {
  return `<div class="section-header" style="margin-bottom: var(--space-lg);"><h1 style="font-size: 22px; font-weight: 700;">${text}</h1></div>`;
}

export function sectionHeader(title, action = '') {
  return `<div class="section-header"><span class="section-title">${title}</span>${action}</div>`;
}

// ── Form elements ──

export function inputGroup(id, { label, type = 'text', placeholder = '', hint = '', mono = false, rows = 0, autocomplete = 'off' } = {}) {
  const cls = `input ${mono ? 'input-mono' : ''}`;
  const field = rows > 0
    ? `<textarea id="${id}" class="${cls}" rows="${rows}" placeholder="${placeholder}" autocomplete="${autocomplete}" autocapitalize="none" spellcheck="false" style="resize: none; line-height: 1.8;"></textarea>`
    : `<input id="${id}" type="${type}" class="${cls}" placeholder="${placeholder}" autocomplete="${autocomplete}" autocapitalize="none" spellcheck="false">`;

  return `
    <div class="input-group" style="width: 100%;">
      ${label ? `<label class="input-label">${label}</label>` : ''}
      ${field}
      ${hint ? `<span id="${id}-hint" class="input-hint">${hint}</span>` : ''}
    </div>
  `;
}

export function passwordInput(id, placeholder = 'Passphrase', autocomplete = 'current-password') {
  return `
    <div class="input-group" style="width: 100%;">
      <input id="${id}" type="password" class="input" placeholder="${placeholder}" autocomplete="${autocomplete}">
      <span id="${id}-error" class="input-error-text" style="display: none;"></span>
    </div>
  `;
}

// ── Buttons ──

export function btnPrimary(id, text, { full = false, lg = false, disabled = false, style = '' } = {}) {
  const cls = `btn btn-primary ${full ? 'btn-full' : ''} ${lg ? 'btn-lg' : ''}`;
  return `<button id="${id}" class="${cls}" ${disabled ? 'disabled' : ''} style="${style}">${text}</button>`;
}

export function btnSecondary(id, text, { full = false, lg = false, style = '' } = {}) {
  const cls = `btn btn-secondary ${full ? 'btn-full' : ''} ${lg ? 'btn-lg' : ''}`;
  return `<button id="${id}" class="${cls}" style="${style}">${text}</button>`;
}

export function btnGhost(id, text, { style = '' } = {}) {
  return `<button id="${id}" class="btn btn-ghost" style="${style}">${text}</button>`;
}

export function btnDanger(id, text, { full = false, style = '' } = {}) {
  return `<button id="${id}" class="btn btn-danger ${full ? 'btn-full' : ''}" style="${style}">${text}</button>`;
}

// ── Cards & containers ──

export function card(content, { style = '', classes = '' } = {}) {
  return `<div class="card ${classes}" style="${style}">${content}</div>`;
}

export function section(content) {
  return `<div class="section">${content}</div>`;
}

// ── Seed phrase grid ──

export function seedGrid(words) {
  const cells = words.map((w, i) => `
    <div class="seed-word">
      <span class="seed-word-num">${i + 1}</span>
      <span class="seed-word-text">${w}</span>
    </div>
  `).join('');
  return `<div class="seed-grid" style="max-width: 400px;">${cells}</div>`;
}

// ── Address & pool display ──

export function poolBadge(isShielded) {
  return isShielded
    ? '<span class="badge badge-shielded">Shielded</span>'
    : '<span class="badge badge-transparent">Transparent</span>';
}

// ── Copy button ──

export function copyBtn(id, text = 'Copy') {
  return `<button id="${id}" class="copy-btn"><span style="width: 14px; height: 14px; display: flex;">${icon('copy')}</span> ${text}</button>`;
}

/** Wire a copy button: click copies text, shows checkmark, resets. */
export function wireCopyBtn(id, getText) {
  const btn = document.getElementById(id);
  if (!btn) return;
  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(typeof getText === 'function' ? getText() : getText);
      const orig = btn.innerHTML;
      btn.classList.add('copied');
      btn.innerHTML = `<span style="width: 14px; height: 14px; display: flex;">${icon('check')}</span> Copied!`;
      setTimeout(() => { btn.classList.remove('copied'); btn.innerHTML = orig; }, 2000);
    } catch { /* clipboard blocked */ }
  });
}

// ── Empty state ──

export function emptyState(iconName, text) {
  return `
    <div class="empty-state">
      <div class="empty-state-icon">${icon(iconName)}</div>
      <p class="empty-state-text">${text}</p>
    </div>
  `;
}

// ── Settings item ──

export function settingsItem(id, label, value, iconName = '') {
  return `
    <div class="settings-item" id="${id}">
      <div>
        <div class="settings-item-label">${label}</div>
        <div class="settings-item-value">${value}</div>
      </div>
      ${iconName ? `<span style="width: 16px; height: 16px; color: var(--text-muted);">${icon(iconName)}</span>` : ''}
    </div>
  `;
}

// ── Pill toggle ──

export function pillToggle(options, { style = '' } = {}) {
  const pills = options.map(({ value, label, active }) =>
    `<button class="pill-option ${active ? 'active' : ''}" data-pill="${value}">${label}</button>`
  ).join('');
  return `<div class="pill-toggle" style="${style}">${pills}</div>`;
}

/** Wire pill toggle: click sets active, calls onChange(value). */
export function wirePillToggle(container, onChange) {
  container.querySelectorAll('[data-pill]').forEach(btn => {
    btn.addEventListener('click', () => {
      container.querySelectorAll('[data-pill]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      onChange(btn.dataset.pill);
    });
  });
}

// ── Row helpers ──

export function detailRow(label, value, { mono = false } = {}) {
  return `
    <div style="display: flex; justify-content: space-between; font-size: 14px;">
      <span style="color: var(--text-muted);">${label}</span>
      <span ${mono ? 'class="font-mono"' : ''}>${value}</span>
    </div>
  `;
}

export function divider() {
  return '<div class="divider" style="margin: 0;"></div>';
}

// ── Tx classification ──

/**
 * Classify a history entry into the pieces both the dashboard and activity
 * views need — icon, label, amount string, CSS class. Returns unformatted
 * strings; the caller wraps them in whatever markup is appropriate. Keeping
 * this single-sourced prevents the dashboard and activity views drifting.
 */
export function classifyTx(tx, formatKRGN) {
  const isReceive = tx.type === 'received';
  const isSend = tx.type === 'sent';
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
                isSelf ? 'Self Transfer' :
                isShielded ? (isReceive ? 'Shielded Receive' : 'Shielded Send') :
                (isReceive ? 'Received' : isSend ? 'Sent' : 'Transaction');
  const amountStr = tx.amount > 0
    ? ((isShield || isUnshield) ? formatKRGN(tx.amount) :
       isSelf ? `-${formatKRGN(tx.amount)}` :
       isReceive ? `+${formatKRGN(tx.amount)}` : `-${formatKRGN(tx.amount)}`)
    : '';
  const amountClass = isReceive ? 'positive' : (isShield || isUnshield) ? '' : 'negative';

  return { isShielded, iconName, iconClass, label, amountStr, amountClass };
}
