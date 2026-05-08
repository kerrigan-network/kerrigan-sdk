/** Settings page — backup, network status, logout. */

import { store } from '../state.js';
import { navigate } from '../router.js';
import { icon } from '../components/icons.js';
import { showToast } from '../components/toast.js';
import * as storage from '../storage.js';
import * as cryptoUtil from '../crypto.js';
import * as net from '../network.js';
import * as T from '../templates.js';
import { renderNav, mountNav, resetDashboard } from './dashboard.js';

let seedRevealed = false;

function truncAddr(addr) {
  return `${addr.slice(0, 16)}...${addr.slice(-6)}`;
}

function settingsGroup(title, content) {
  return `<div class="settings-group"><div class="settings-group-title">${title}</div>${content}</div>`;
}

function statusDot(ok) {
  return `<div class="sync-dot ${ok ? '' : 'syncing'}" style="${ok ? '' : 'background: var(--red);'}"></div>`;
}

export function render() {
  seedRevealed = false;
  return {
    html: T.walletShell([
      T.pageTitle('Settings'),

      // Wallet
      settingsGroup('Wallet', [
        T.settingsItem('settings-backup', 'Backup Recovery Phrase', 'Reveal your 12-word phrase', 'eye'),
        '<div id="seed-reveal-area"></div>',
      ].join('')),

      // Addresses
      settingsGroup('Addresses', [
        T.settingsItem('copy-transparent', 'Transparent', `<span class="font-mono" style="font-size: 12px;">${truncAddr(store.wallet.transparentAddr)}</span>`, 'copy'),
        T.settingsItem('copy-shielded', 'Shielded', `<span class="font-mono" style="font-size: 12px;">${truncAddr(store.wallet.shieldedAddr)}</span>`, 'copy'),
      ].join('')),

      // Network
      settingsGroup('Network', [
        `<div class="settings-item" style="cursor: default;"><div><div class="settings-item-label">Shield Bridge</div><div class="settings-item-value">kerrigan-bridge.jskitty.cat</div></div>${statusDot(store.sync.status === 'synced')}</div>`,
        `<div class="settings-item" style="cursor: default;"><div><div class="settings-item-label">ElectrumX</div><div class="settings-item-value">electrum-kerrigan.jskitty.cat</div></div>${statusDot(store.sync.electrumConnected)}</div>`,
        T.settingsItem('btn-explorer', 'Block Explorer', 'explorer.kerrigan.network', 'externalLink'),
      ].join('')),

      // Actions
      `<div class="settings-group" style="margin-top: var(--space-xl);">
        ${T.btnSecondary('btn-resync', `<span style="width: 16px; height: 16px; display: flex;">${icon('refresh')}</span> Resync Wallet`, { full: true })}
      </div>`,

      // Danger
      `<div class="settings-group">
        ${T.btnDanger('btn-logout', `<span style="width: 16px; height: 16px; display: flex;">${icon('logout')}</span> Lock Wallet`, { full: true })}
        ${T.btnGhost('btn-delete', 'Delete Wallet', { style: 'margin-top: var(--space-sm); color: var(--red); width: 100%;' })}
        <div id="delete-confirm-area"></div>
      </div>`,
    ].join(''), renderNav('settings')),

    onMount: () => {
      mountNav();

      // Explorer link
      document.getElementById('btn-explorer')?.addEventListener('click', () => {
        window.open('https://explorer.kerrigan.network', '_blank');
      });

      // Resync
      document.getElementById('btn-resync')?.addEventListener('click', async () => {
        const btn = document.getElementById('btn-resync');
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner" style="width: 16px; height: 16px; border-width: 2px;"></span> Resyncing...';
        await storage.removeItem('shield_state');
        await storage.removeItem('transparent_utxos');
        await storage.removeItem('tx_history');
        Object.assign(store.balance, { transparent: 0, shielded: 0, pending: 0 });
        store.history.length = 0;
        Object.assign(store.sync, { shieldHeight: 0, targetHeight: 0, progress: 0, status: 'idle' });
        resetDashboard();
        showToast('Wallet data cleared — resyncing', 'info');
        navigate('dashboard');
      });

      // Backup seed
      document.getElementById('settings-backup')?.addEventListener('click', () => {
        if (seedRevealed) { seedRevealed = false; document.getElementById('seed-reveal-area').innerHTML = ''; return; }
        showSeedReveal();
      });

      // Copy addresses
      document.getElementById('copy-transparent')?.addEventListener('click', () => {
        navigator.clipboard.writeText(store.wallet.transparentAddr).then(
          () => showToast('Transparent address copied', 'success'),
          () => showToast('Failed to copy', 'error'),
        );
      });
      document.getElementById('copy-shielded')?.addEventListener('click', () => {
        navigator.clipboard.writeText(store.wallet.shieldedAddr).then(
          () => showToast('Shielded address copied', 'success'),
          () => showToast('Failed to copy', 'error'),
        );
      });

      // Lock
      document.getElementById('btn-logout')?.addEventListener('click', () => {
        Object.assign(store.wallet, { seed: null, mnemonic: null, extsk: '', extfvk: '' });
        Object.assign(store.balance, { transparent: 0, shielded: 0, pending: 0 });
        store.history.length = 0;
        net.disconnectElectrumX();
        resetDashboard();
        navigate('login');
        showToast('Wallet locked', 'info');
      });

      // Delete
      document.getElementById('btn-delete')?.addEventListener('click', () => {
        const area = document.getElementById('delete-confirm-area');
        area.innerHTML = T.card(`
          <p style="color: var(--red); font-weight: 600; margin-bottom: var(--space-md);">
            This will permanently delete your wallet from this device.
          </p>
          <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: var(--space-lg);">
            Make sure you have backed up your recovery phrase. There is no way to recover your funds without it.
          </p>
          ${T.btnDanger('btn-confirm-delete', 'I Understand, Delete Wallet', { full: true })}
        `, { style: 'border-color: var(--red); margin-top: var(--space-md); text-align: center;' });

        document.getElementById('btn-confirm-delete')?.addEventListener('click', async () => {
          await storage.clear();
          store.wallet.seed = null;
          net.disconnectElectrumX();
          resetDashboard();
          navigate('welcome');
          showToast('Wallet deleted', 'info');
        });
      });
    },
  };
}

function showSeedReveal() {
  const area = document.getElementById('seed-reveal-area');
  area.innerHTML = T.card(`
    <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: var(--space-md);">
      Enter your passphrase to reveal your recovery phrase.
    </p>
    ${T.passwordInput('seed-pass')}
    ${T.btnSecondary('btn-reveal', 'Reveal', { full: true, style: 'margin-top: var(--space-md);' })}
  `, { style: 'margin-bottom: var(--space-md);' });

  const passInput = document.getElementById('seed-pass');
  document.getElementById('btn-reveal')?.addEventListener('click', async () => {
    if (!passInput.value) return;
    try {
      const enc = await storage.getItem('encrypted_mnemonic');
      if (!enc) throw new Error('No mnemonic stored — delete wallet and recreate');
      const bytes = await cryptoUtil.decrypt(enc, passInput.value);
      const words = new TextDecoder().decode(bytes).trim().split(/\s+/).filter(Boolean);
      if (words.length < 12) throw new Error('No mnemonic stored — delete wallet and recreate');

      area.innerHTML = T.card(`
        <p style="font-size: 13px; color: var(--yellow); margin-bottom: var(--space-md); font-weight: 600;">
          Never share these words with anyone.
        </p>
        ${T.seedGrid(words)}
        ${T.copyBtn('btn-copy-backup-seed', 'Copy Phrase')}
      `, { style: 'border-color: var(--purple); margin-bottom: var(--space-md);' });
      T.wireCopyBtn('btn-copy-backup-seed', () => words.join(' '));
      seedRevealed = true;
    } catch (err) {
      showToast(`Failed: ${err.message}`, 'error');
    }
  });
  passInput?.focus();
}
