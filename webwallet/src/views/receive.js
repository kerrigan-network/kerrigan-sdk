/** Receive modal — QR code + address display with transparent/shielded toggle. */

import { store } from '../state.js';
import { createModal } from '../components/modal.js';
import { generateQR } from '../components/qr-code.js';
import { showToast } from '../components/toast.js';
import * as T from '../templates.js';

let addressType = 'transparent';

function currentAddress() {
  return addressType === 'shielded' ? store.wallet.shieldedAddr : store.wallet.transparentAddr;
}

export function render() {
  addressType = 'transparent';
  const address = currentAddress();

  return createModal('Receive KRGN', `
    <div style="display: flex; flex-direction: column; align-items: center; gap: var(--space-md);">
      ${T.pillToggle([
        { value: 'transparent', label: 'Transparent', active: true },
        { value: 'shielded', label: 'Shielded', active: false },
      ], { style: 'width: 100%; max-width: 260px;' })}
      <div id="receive-qr" style="padding: var(--space-md); background: white; border-radius: var(--radius-md); margin: var(--space-sm) 0;">${generateQR(address, 200)}</div>
      <div id="receive-address" class="address-display" style="text-align: center; padding: 10px 12px; background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); width: 100%; user-select: all; cursor: text; font-size: 12px;">${address}</div>
      ${T.copyBtn('copy-address-btn', 'Copy Address')}
      <p id="addr-hint" style="font-size: 12px; color: var(--text-muted); text-align: center;">Share this address to receive KRGN</p>
    </div>
  `, () => {
    T.wirePillToggle(document.querySelector('.pill-toggle'), (val) => {
      addressType = val;
      updateAddress();
    });
    T.wireCopyBtn('copy-address-btn', currentAddress);
  });
}

function updateAddress() {
  const address = currentAddress();
  const qrEl = document.getElementById('receive-qr');
  const addrEl = document.getElementById('receive-address');
  const hintEl = document.getElementById('addr-hint');

  if (qrEl) qrEl.innerHTML = generateQR(address, 200);
  if (addrEl) addrEl.textContent = address;
  if (hintEl) hintEl.textContent = addressType === 'shielded'
    ? 'Private address — sender must support shielded transactions'
    : 'Share this address to receive KRGN';
}
