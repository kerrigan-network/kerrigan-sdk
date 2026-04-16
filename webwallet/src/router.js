/** Simple hash-based SPA router with view transitions. */

import { store } from './state.js';

const views = {};
let currentCleanup = null;

/** Register a view renderer. */
export function registerView(name, renderFn) {
  views[name] = renderFn;
}

/** Navigate to a view. */
export function navigate(viewName) {
  store.ui.view = viewName;
  render();
}

/** Open a modal overlay. */
export function openModal(name) {
  store.ui.modal = name;
  renderModal();
}

/** Close modal overlay. */
export function closeModal() {
  const root = document.getElementById('modal-root');
  const backdrop = root.querySelector('.modal-backdrop');
  const panel = root.querySelector('.modal-panel');
  if (backdrop && panel) {
    panel.style.animation = 'fadeOut 150ms ease forwards';
    backdrop.style.animation = 'fadeOut 200ms ease forwards';
    setTimeout(() => {
      store.ui.modal = null;
      root.innerHTML = '';
    }, 200);
  } else {
    store.ui.modal = null;
    root.innerHTML = '';
  }
}

function render() {
  const app = document.getElementById('app');
  const view = store.ui.view;
  const renderFn = views[view];
  if (!renderFn) return;

  // Cleanup previous view
  if (currentCleanup) {
    currentCleanup();
    currentCleanup = null;
  }

  // Render new view
  const result = renderFn();
  if (typeof result === 'string') {
    app.innerHTML = result;
  } else if (result?.html) {
    app.innerHTML = result.html;
    if (result.onMount) {
      // Defer to next frame so DOM is ready
      requestAnimationFrame(() => {
        currentCleanup = result.onMount() || null;
      });
    }
  }
}

function renderModal() {
  const name = store.ui.modal;
  if (!name) return;
  const renderFn = views[`modal:${name}`];
  if (!renderFn) return;

  const root = document.getElementById('modal-root');
  const result = renderFn();
  if (result?.html) {
    root.innerHTML = result.html;
    if (result.onMount) {
      requestAnimationFrame(() => result.onMount());
    }
  }
}

/** Start the router. */
export function startRouter() {
  render();
}
