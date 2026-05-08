/** Welcome screen — create or restore wallet. */

import { navigate } from '../router.js';
import { store } from '../state.js';
import * as sdk from '../sdk.js';
import * as crypto from '../crypto.js';
import * as storage from '../storage.js';
import { icon } from '../components/icons.js';
import { showToast } from '../components/toast.js';
import * as T from '../templates.js';

let step = 'choice';
let mnemonic = '';
let seedWords = [];
let verifyIndices = [];
/** Which onboarding path the user is on. Set when they pick "Create" or
 *  "Restore" from the choice screen, then used at the passphrase step
 *  to label the action button + success toast appropriately. Defaults
 *  to 'create' for safety (the original copy). */
let flow = 'create';

const LOCK_SVG = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" style="flex-shrink: 0; color: var(--purple-light);"><path d="M17 11V8C17 5.23858 14.7614 3 12 3C9.23858 3 7 5.23858 7 8V11M7.8 21H16.2C17.8802 21 18.7202 21 19.362 20.673C19.9265 20.3854 20.3854 19.9265 20.673 19.362C21 18.7202 21 17.8802 21 16.2V15.8C21 14.1198 21 13.2798 20.673 12.638C20.3854 12.0735 19.9265 11.6146 19.362 11.327C18.7202 11 17.8802 11 16.2 11H7.8C6.11984 11 5.27976 11 4.63803 11.327C4.07354 11.6146 3.6146 12.0735 3.32698 12.638C3 13.2798 3 14.1198 3 15.8V16.2C3 17.8802 3 18.7202 3.32698 19.362C3.6146 19.9265 4.07354 20.3854 4.63803 20.673C5.27976 21 6.11984 21 7.8 21Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';

export function render() {
  step = 'choice';
  return { html: renderChoice(), onMount: () => mountChoice() };
}

function rerender() {
  const app = document.getElementById('app');
  const steps = { choice: [renderChoice, mountChoice], 'create-seed': [renderSeedDisplay, mountSeedDisplay], 'verify-seed': [renderSeedVerify, mountSeedVerify], restore: [renderRestore, mountRestore], passphrase: [renderPassphrase, mountPassphrase] };
  const [renderFn, mountFn] = steps[step];
  app.innerHTML = renderFn();
  mountFn();
}

// ── Choice ──

function renderChoice() {
  return T.fullscreen(`
    <div class="welcome stagger">
      <div class="welcome-crystal">${icon('crystal')}</div>
      <h1 class="welcome-title"><span>Kerrigan</span> Wallet</h1>
      <p class="welcome-subtitle">Your piece of the Swarm.</p>
      <div class="welcome-actions">
        ${T.btnPrimary('btn-create', 'Create New Wallet', { full: true, lg: true })}
        ${T.btnSecondary('btn-restore', 'Restore Wallet', { full: true, lg: true })}
      </div>
    </div>
  `);
}

function mountChoice() {
  document.getElementById('btn-create')?.addEventListener('click', () => {
    mnemonic = sdk.generateMnemonic12();
    seedWords = mnemonic.split(' ');
    flow = 'create';
    step = 'create-seed';
    rerender();
  });
  document.getElementById('btn-restore')?.addEventListener('click', () => {
    flow = 'import';
    step = 'restore';
    rerender();
  });
}

// ── Seed Display ──

function renderSeedDisplay() {
  return T.fullscreen(`
    <div class="welcome stagger" style="gap: var(--space-lg);">
      <h2 style="font-size: 22px; font-weight: 700;">Your Recovery Phrase</h2>
      <p style="font-size: 14px; color: var(--text-secondary); max-width: 340px;">
        Write these 12 words down in order. This is the <strong style="color: var(--text-primary);">only way</strong> to recover your wallet.
      </p>
      ${T.seedGrid(seedWords)}
      ${T.copyBtn('btn-copy-seed', 'Copy Phrase')}
      ${T.btnPrimary('btn-seed-done', "I've Written Them Down", { full: true, lg: true, style: 'max-width: 400px; margin-top: var(--space-sm);' })}
      ${T.btnGhost('btn-seed-back', 'Go Back')}
    </div>
  `);
}

function mountSeedDisplay() {
  T.wireCopyBtn('btn-copy-seed', () => seedWords.join(' '));

  document.getElementById('btn-seed-done')?.addEventListener('click', () => {
    const indices = [];
    while (indices.length < 3) {
      const idx = Math.floor(Math.random() * seedWords.length);
      if (!indices.includes(idx)) indices.push(idx);
    }
    verifyIndices = indices.sort((a, b) => a - b);
    step = 'verify-seed';
    rerender();
  });
  document.getElementById('btn-seed-back')?.addEventListener('click', () => { step = 'choice'; rerender(); });
}

// ── Seed Verification ──

function renderSeedVerify() {
  const fields = verifyIndices.map(idx =>
    T.inputGroup(`verify-${idx}`, { label: `Word #${idx + 1}`, placeholder: `Enter word ${idx + 1}`, mono: true })
  ).join('');

  return T.fullscreen(`
    <div class="welcome" style="gap: var(--space-lg); max-width: 360px;">
      <h2 style="font-size: 22px; font-weight: 700;">Verify Your Phrase</h2>
      <p class="verify-prompt">
        Enter the words at positions
        <strong>#${verifyIndices[0] + 1}</strong>,
        <strong>#${verifyIndices[1] + 1}</strong>, and
        <strong>#${verifyIndices[2] + 1}</strong>.
      </p>
      ${fields}
      ${T.btnPrimary('btn-verify', 'Verify', { full: true, lg: true, disabled: true })}
      ${T.btnGhost('btn-verify-skip', 'Skip Verification')}
      ${T.btnGhost('btn-verify-back', 'Go Back', { style: 'margin-top: calc(-1 * var(--space-sm));' })}
    </div>
  `);
}

function mountSeedVerify() {
  const inputs = verifyIndices.map(idx => document.getElementById(`verify-${idx}`));
  const btn = document.getElementById('btn-verify');

  function checkAll() {
    let filled = 0, correct = 0;
    inputs.forEach((input, i) => {
      const val = input.value.trim().toLowerCase();
      const isCorrect = val === seedWords[verifyIndices[i]].toLowerCase();
      if (val.length > 0) {
        filled++;
        input.classList.toggle('input-error', !isCorrect);
        if (isCorrect) correct++;
      } else {
        input.classList.remove('input-error');
      }
    });
    btn.disabled = !(filled === inputs.length && correct === inputs.length);
  }

  inputs.forEach(input => input?.addEventListener('input', checkAll));
  btn?.addEventListener('click', () => { step = 'passphrase'; rerender(); });
  document.getElementById('btn-verify-skip')?.addEventListener('click', () => { step = 'passphrase'; rerender(); });
  document.getElementById('btn-verify-back')?.addEventListener('click', () => { step = 'create-seed'; rerender(); });
  inputs[0]?.focus();
}

// ── Restore ──

function renderRestore() {
  return T.fullscreen(`
    <div class="welcome stagger" style="gap: var(--space-lg); max-width: 400px;">
      <h2 style="font-size: 22px; font-weight: 700;">Restore Wallet</h2>
      <p style="font-size: 14px; color: var(--text-secondary);">Enter your recovery phrase to restore your wallet.</p>
      ${T.inputGroup('restore-input', { placeholder: 'Enter your 12 or 24-word recovery phrase...', mono: true, rows: 4 })}
      ${T.btnPrimary('btn-restore-next', 'Continue', { full: true, lg: true, disabled: true })}
      ${T.btnGhost('btn-restore-back', 'Go Back')}
    </div>
  `);
}

function mountRestore() {
  const input = document.getElementById('restore-input');
  const btn = document.getElementById('btn-restore-next');
  const hint = document.getElementById('restore-input-hint');

  input?.addEventListener('input', () => {
    const words = input.value.trim().split(/\s+/).filter(Boolean);
    const validLength = words.length === 12 || words.length === 24;
    if (validLength) {
      const valid = sdk.validateMnemonic(words.join(' '));
      btn.disabled = !valid;
      if (hint) { hint.textContent = valid ? `${words.length} words — valid phrase` : `${words.length} words — invalid phrase`; hint.className = valid ? 'input-hint text-green' : 'input-error-text'; }
    } else {
      btn.disabled = true;
      if (hint) { hint.textContent = `${words.length} words`; hint.className = 'input-hint'; }
    }
  });

  btn?.addEventListener('click', () => {
    mnemonic = input.value.trim().split(/\s+/).join(' ');
    seedWords = mnemonic.split(' ');
    step = 'passphrase';
    rerender();
  });
  document.getElementById('btn-restore-back')?.addEventListener('click', () => { step = 'choice'; rerender(); });
  input?.focus();
}

// ── Passphrase ──

function renderPassphrase() {
  const ctaLabel = flow === 'import' ? 'Import Wallet' : 'Create Wallet';
  return T.fullscreen(`
    <div class="passphrase-screen stagger">
      <h2 style="font-size: 22px; font-weight: 700; display: flex; align-items: center; justify-content: center; gap: 10px;">
        ${LOCK_SVG} Set a Passphrase
      </h2>
      <p style="font-size: 14px; color: var(--text-secondary); max-width: 300px; margin-bottom: var(--space-md);">
        This passphrase encrypts your wallet on this device. You'll need it each time you open the wallet.
      </p>
      <div class="input-group" style="width: 100%;">
        <input id="pass-input" type="password" class="input" placeholder="Enter passphrase" autocomplete="new-password">
        <div class="passphrase-strength" style="margin-bottom: 10px;">
          <div id="pass-strength" class="passphrase-strength-fill" style="width: 0%;"></div>
        </div>
      </div>
      ${T.passwordInput('pass-confirm', 'Confirm passphrase', 'new-password')}
      ${T.btnPrimary('btn-pass-save', ctaLabel, { full: true, lg: true, disabled: true, style: 'margin-top: var(--space-md);' })}
    </div>
  `);
}

function mountPassphrase() {
  const passInput = document.getElementById('pass-input');
  const confirmInput = document.getElementById('pass-confirm');
  const strengthBar = document.getElementById('pass-strength');
  const hint = document.getElementById('pass-confirm-error');
  const btn = document.getElementById('btn-pass-save');

  function validate() {
    const pass = passInput.value;
    const confirm = confirmInput.value;

    let strength = 0;
    if (pass.length >= 8) strength += 25;
    if (pass.length >= 12) strength += 25;
    if (/[A-Z]/.test(pass) && /[a-z]/.test(pass)) strength += 25;
    if (/[0-9!@#$%^&*]/.test(pass)) strength += 25;
    strengthBar.style.width = `${strength}%`;
    strengthBar.style.background = strength <= 25 ? 'var(--red)' : strength <= 50 ? 'var(--yellow)' : strength <= 75 ? 'var(--purple-light)' : 'var(--green)';

    if (confirm && confirm !== pass) {
      hint.textContent = 'Passphrases do not match'; hint.style.display = ''; btn.disabled = true;
    } else if (confirm && confirm === pass && pass.length >= 6) {
      hint.textContent = 'Passphrases match'; hint.className = 'input-hint text-green'; hint.style.display = ''; btn.disabled = false;
    } else {
      hint.textContent = pass.length > 0 && pass.length < 6 ? 'Minimum 6 characters' : ''; hint.className = 'input-hint'; hint.style.display = hint.textContent ? '' : 'none'; btn.disabled = true;
    }
  }

  passInput?.addEventListener('input', validate);
  confirmInput?.addEventListener('input', validate);

  btn?.addEventListener('click', async () => {
    btn.disabled = true;
    btn.textContent = 'Encrypting...';
    try {
      const passphrase = passInput.value;
      const seed = sdk.mnemonicToSeed(mnemonic, '');
      const keys = sdk.deriveAllKeys(seed);

      const encrypted = await crypto.encrypt(seed, passphrase);
      const encryptedMnemonic = await crypto.encrypt(mnemonic, passphrase);
      await storage.setItem('encrypted_seed', encrypted);
      await storage.setItem('encrypted_mnemonic', encryptedMnemonic);
      await storage.setItem('wallet_meta', { transparentAddr: keys.transparentAddr, shieldedAddr: keys.shieldedAddr });

      Object.assign(store.wallet, { seed, transparentAddr: keys.transparentAddr, shieldedAddr: keys.shieldedAddr, extfvk: keys.extfvk, extsk: keys.extsk });
      mnemonic = '';
      seedWords = [];

      showToast(
        flow === 'import' ? 'Wallet imported successfully' : 'Wallet created successfully',
        'success',
      );
      navigate('dashboard');
    } catch (err) {
      showToast(`Error: ${err.message}`, 'error');
      btn.disabled = false;
      btn.textContent = flow === 'import' ? 'Import Wallet' : 'Create Wallet';
    }
  });

  passInput?.focus();
}
