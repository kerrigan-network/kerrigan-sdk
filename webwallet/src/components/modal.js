/** Modal overlay renderer. */

import { closeModal } from '../router.js';

/**
 * Wrap content in a modal shell. Returns { html, onMount }.
 */
export function createModal(title, bodyHtml, onMountFn) {
  return {
    html: `
      <div class="modal-backdrop" style="
        position: fixed; inset: 0; z-index: 1000;
        background: rgba(0,0,0,0.6);
        backdrop-filter: blur(8px);
        -webkit-backdrop-filter: blur(8px);
        display: flex; align-items: flex-end; justify-content: center;
        animation: backdropIn 200ms ease both;
      ">
        <div class="modal-panel" style="
          width: 100%; max-width: var(--wallet-max-width);
          max-height: 90dvh;
          background: var(--bg-base);
          border-top: 1px solid var(--border-default);
          border-radius: var(--radius-xl) var(--radius-xl) 0 0;
          overflow-y: auto;
          animation: modalSlideUp 300ms var(--ease-out) both;
        ">
          <div style="
            display: flex; align-items: center; justify-content: space-between;
            padding: var(--space-md) var(--space-md) var(--space-sm);
            position: sticky; top: 0;
            background: var(--bg-base);
            z-index: 1;
          ">
            <h2 style="font-size: 18px; font-weight: 700;">${title}</h2>
            <button id="modal-close-btn" class="btn-ghost" style="
              width: 32px; height: 32px; display: flex; align-items: center;
              justify-content: center; border-radius: var(--radius-full);
            ">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <path d="M18 6L6 18M6 6l12 12"/>
              </svg>
            </button>
          </div>
          <div style="padding: 0 var(--space-md) var(--space-lg);">
            ${bodyHtml}
          </div>
        </div>
      </div>
    `,
    onMount: () => {
      const backdrop = document.querySelector('.modal-backdrop');
      backdrop?.addEventListener('click', (e) => {
        if (e.target === backdrop) closeModal();
      });
      document.getElementById('modal-close-btn')?.addEventListener('click', closeModal);
      onMountFn?.();
    },
  };
}
