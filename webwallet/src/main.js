/** Kerrigan Web Wallet — entry point. */

import { initStore, store } from './state.js';
import { registerView, navigate } from './router.js';
import * as sdk from './sdk.js';
import * as storage from './storage.js';

// Views
import * as welcome from './views/welcome.js';
import * as login from './views/login.js';
import * as dashboard from './views/dashboard.js';
import * as send from './views/send.js';
import * as receive from './views/receive.js';
import * as activity from './views/activity.js';
import * as ai from './views/ai.js';
import * as settings from './views/settings.js';
import * as memo from './views/memo.js';
import * as maturity from './views/maturity.js';

async function boot() {
  // Show loading state
  document.getElementById('app').innerHTML = `
    <div class="view-fullscreen gradient-mesh">
      <div style="display: flex; flex-direction: column; align-items: center; gap: var(--space-lg);">
        <div class="spinner" style="width: 32px; height: 32px; border-width: 3px;"></div>
        <span style="font-size: 14px; color: var(--text-muted);">Loading wallet...</span>
      </div>
    </div>
  `;

  // Initialize WASM SDK
  await sdk.init();

  // Initialize state
  initStore();

  // Register views
  registerView('welcome', welcome.render);
  registerView('login', login.render);
  registerView('dashboard', dashboard.render);
  registerView('activity', activity.render);
  registerView('ai', ai.render);
  registerView('settings', settings.render);
  registerView('modal:send', send.render);
  registerView('modal:receive', receive.render);
  registerView('modal:memo', memo.render);
  registerView('modal:maturity', maturity.render);

  // Check if wallet exists
  const hasWallet = await storage.hasWallet();

  if (hasWallet) {
    navigate('login');
  } else {
    navigate('welcome');
  }
}

boot().catch(err => {
  console.error('Boot failed:', err);
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="view-fullscreen gradient-mesh">
      <div style="text-align: center; max-width: 360px;">
        <h2 style="font-size: 20px; font-weight: 700; color: var(--red); margin-bottom: var(--space-md);">
          Failed to load wallet
        </h2>
        <p id="boot-err-msg" style="font-size: 14px; color: var(--text-secondary); margin-bottom: var(--space-lg);"></p>
        <button id="boot-retry" class="btn btn-secondary">Retry</button>
      </div>
    </div>
  `;
  // Use textContent so an error string containing HTML can't inject markup.
  document.getElementById('boot-err-msg').textContent = err?.message || String(err);
  document.getElementById('boot-retry').addEventListener('click', () => location.reload());
});
