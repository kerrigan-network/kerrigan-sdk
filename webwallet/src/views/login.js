/** Login screen — passphrase entry for returning users. */

import { navigate } from '../router.js';
import { store } from '../state.js';
import * as sdk from '../sdk.js';
import * as cryptoUtil from '../crypto.js';
import * as storage from '../storage.js';
import { icon } from '../components/icons.js';
import * as T from '../templates.js';

export function render() {
  return {
    html: T.fullscreen(`
      <div class="login stagger">
        <div class="login-crystal">${icon('crystal')}</div>
        <h1 class="login-title">Welcome Back</h1>
        <p style="font-size: 14px; color: var(--text-secondary);">Enter your passphrase to unlock</p>
        ${T.passwordInput('login-pass')}
        ${T.btnPrimary('btn-unlock', 'Unlock', { full: true, lg: true, style: 'margin-top: var(--space-xs);' })}
      </div>
    `),
    onMount: () => {
      const passInput = document.getElementById('login-pass');
      const btn = document.getElementById('btn-unlock');
      const error = document.getElementById('login-pass-error');

      async function unlock() {
        const passphrase = passInput.value;
        if (!passphrase) return;

        btn.disabled = true;
        btn.textContent = 'Decrypting...';
        error.style.display = 'none';

        try {
          const encrypted = await storage.getItem('encrypted_seed');
          if (!encrypted) throw new Error('No wallet found');

          const seedBytes = await cryptoUtil.decrypt(encrypted, passphrase);
          const keys = sdk.deriveAllKeys(seedBytes);
          const meta = await storage.getItem('wallet_meta');

          Object.assign(store.wallet, {
            seed: seedBytes,
            transparentAddr: meta?.transparentAddr || keys.transparentAddr,
            shieldedAddr: meta?.shieldedAddr || keys.shieldedAddr,
            extfvk: keys.extfvk,
            extsk: keys.extsk,
          });

          navigate('dashboard');
        } catch {
          error.textContent = 'Incorrect passphrase';
          error.style.display = 'block';
          passInput.classList.add('input-error');
          btn.disabled = false;
          btn.textContent = 'Unlock';
          passInput.value = '';
          passInput.focus();
        }
      }

      btn?.addEventListener('click', unlock);
      passInput?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') unlock();
        if (error.style.display !== 'none') {
          error.style.display = 'none';
          passInput.classList.remove('input-error');
        }
      });
      passInput?.focus();
    },
  };
}
