/** AI tab — decentralised LLM chat via the Kerrigan inference relay.
 *
 *  Flow mirrors the CLI's `infer chat`, extended for multi-turn:
 *    1. POST /v1/invoice       (coordinator picks or pins a provider, proxies)
 *    2. "Neural Contract" card (user authorises)
 *    3. Build + sign 0x02 TX   (WASM)
 *    4. Broadcast via Electrum
 *    5. POST /v1/chat          (routes to the paid provider)
 *    6. Render response block, keep provider pinned for next turn
 *
 *  Multi-turn state:
 *    - `conversation` holds every {role, content} pair we send/receive
 *    - `pinnedDroneHash` keeps subsequent turns on the same drone so
 *      the prompt-cache prefix matches. Cleared by the "new chat" button
 *      or when the coordinator rotates us to a new provider.
 *
 *  All visual treatment lives in `css/ai.css` — this file only emits
 *  the markup hooks (classes + data-attrs). Keep it that way.
 */

import { appHeader, escapeHtml } from '../templates.js';
import { store, formatKRGN } from '../state.js';
import { renderNav, mountNav } from './dashboard.js';
import { icon } from '../components/icons.js';
import { renderMarkdown, splitThinking } from '../components/markdown.js';
import {
  requestInferenceInvoice, submitInferenceChat, submitInferenceChatStream,
  sendRawTransaction, getLiveDroneCount, listInferenceModels,
} from '../network.js';
import * as sdk from '../sdk.js';
import * as storage from '../storage.js';
import { refreshTransparentBalance } from '../sync.js';
import { base58Decode } from '../utils.js';

/** Output-token tiers exposed in the settings panel. The client pays
 *  `max_tokens * out_rate` upfront and gets any unused portion back via
 *  the provider's 0x06 refund TX, so over-picking Long is only a cash-
 *  flow hit, not an overspend. */
const TIERS = [
  { id: 'short',  label: 'Short',  tokens: 1024,  hint: '~800 words',   desc: 'Quick answers, sanity checks, small edits.' },
  { id: 'medium', label: 'Medium', tokens: 4096,  hint: '~3000 words',  desc: 'Full explanations, short essays, code snippets.' },
  { id: 'long',   label: 'Long',   tokens: 16384, hint: '~12000 words', desc: 'Long-form writing, detailed walk-throughs.' },
];
const DEFAULT_TIER = 'short';

/** Safety margin for tokenizer disagreement + chat-template overhead.
 *  Without it a client-side estimate that sits right at the limit blows
 *  up on the drone's real tokenization. 128 is generous. */
const CONTEXT_SAFETY = 128;

// Fixed sampling params — the drone's payment validator hashes these,
// so the `params_hash` baked into the TX MUST match what goes into the
// chat request body. Settings UI later.
const PARAMS = { temperature: 0.7, topP: 0.9, seed: 42, k: 16 };

/** Conversation state — list of {kind, role?, content?, ...}. `text` entries
 *  are real turns sent to / received from the model; `sys`, `paid`, and
 *  `thinking` are UI-only ephemera and get filtered when we build the
 *  wire `messages[]` array. */
const conversation = [];
/** Once the first invoice picks a provider, we pin to that hash for every
 *  subsequent turn so the KV cache stays warm. Cleared on new chat or when
 *  the coordinator signals `drone_rotated`. */
let pinnedDroneHash = null;
let selectedTier = DEFAULT_TIER;
let busy = false;
let droneCount = null; // populated async from /v1/node-id (live relay-pool count)
/** Skip the per-request contract authorisation prompt and pay
 *  immediately. User-toggled in the settings panel; persisted to
 *  IndexedDB under `ai_auto_approve_contracts` so the choice survives
 *  reloads. Defaults off — auto-approving silently spends real KRGN, so
 *  we make the user opt in explicitly. */
let autoApproveContracts = false;
const AUTO_APPROVE_KEY = 'ai_auto_approve_contracts';
/** Hide the small "✓ X KRGN · txid…" rows that get inserted into the
 *  chat after each successful payment. Cosmetic only — the entries are
 *  still pushed onto `conversation`, they just don't render. Persisted
 *  alongside the auto-approve flag for the same reason: opt-in, sticky. */
let hidePaymentAmounts = false;
const HIDE_PAYMENTS_KEY = 'ai_hide_payment_amounts';

/** Models the coordinator has discovered across the relay pool. Populated
 *  on mount + whenever the settings panel opens. Each entry is a
 *  (model, context_length) pair — in the current architecture a single
 *  drone serves exactly one model at exactly one context length, so
 *  the tuple is the right unit of user choice. */
let availableModels = [];
/** The user-selected model, stored by `gguf_hash` (the only stable
 *  identifier across providers). `null` until either the user picks
 *  or `refreshModels` auto-selects the first discovered. */
let selectedModelHash = null;
/** Tri-state for the model-discovery lifecycle. The send button + UI
 *  copy branch on it — there's NO fallback model anymore, so the
 *  client must wait for the network to surface real options before
 *  it can broadcast anything.
 *    `'loading'` — initial, /v1/models hasn't returned yet
 *    `'empty'`   — fetch returned, no providers online
 *    `'ready'`   — at least one model + provider available
 */
let modelsState = 'loading';
/** Whether the small "Discovering network…" pill should be visible.
 *  Held false for the first ~200ms of `modelsState === 'loading'` so a
 *  sub-200ms fast load never even shows the pill — the user just sees
 *  the steady empty state, no flicker. Set to true by a delayed timer
 *  set in `arm Loading Pill()`, reset whenever discovery resolves. */
let loadingShown = false;
let loadingShowTimer = null;
function armLoadingPill() {
  if (loadingShowTimer) clearTimeout(loadingShowTimer);
  loadingShown = false;
  loadingShowTimer = setTimeout(() => {
    if (modelsState === 'loading') {
      loadingShown = true;
      rerender();
    }
  }, 200);
}
function disarmLoadingPill() {
  if (loadingShowTimer) { clearTimeout(loadingShowTimer); loadingShowTimer = null; }
  loadingShown = false;
}

/** The currently-active model entry, or `null` if discovery hasn't
 *  produced anything yet. Callers must handle null — there is no
 *  hard-coded fallback. */
function activeModel() {
  if (availableModels.length === 0) return null;
  const pinned = availableModels.find((m) => m.gguf_hash === selectedModelHash);
  return pinned || availableModels[0];
}

/** Effective context window of the active model. Returns 8192 when no
 *  model is selected — this is only used for client-side trim math
 *  on an empty conversation (which trims nothing anyway), so the value
 *  is benign. Send paths always check `activeModel()` first. */
function contextBudget() {
  const m = activeModel();
  return m ? (Number(m.context_length) || 8192) : 8192;
}

/** Whether the AI tab is in a "ready to send" state — discovery
 *  completed, at least one model available, and a model selected. */
function canSend() {
  return modelsState === 'ready' && activeModel() != null;
}

export function render() {
  return {
    html: `
      <div class="wallet-shell">
        <div class="wallet-content view-enter ai-view">
          ${appHeader(renderHeaderRight())}

          <div id="ai-messages" class="ai-messages">
            ${renderStream()}
          </div>

          <div id="ai-invoice-slot" class="ai-invoice-slot"></div>

          <div class="ai-composer">
            <textarea id="ai-prompt"
              class="ai-prompt"
              placeholder="Ask anything…"
              rows="1"
              autocapitalize="sentences"
              autocomplete="off"></textarea>
            <button id="ai-send" class="ai-send-btn" aria-label="Transmit">
              ${icon('chevronRight')}
            </button>
          </div>

        </div>
        ${renderNav('ai')}
      </div>
    `,
    onMount: () => {
      mountNav();
      const textarea = document.getElementById('ai-prompt');
      const sendBtn = document.getElementById('ai-send');

      const autoGrow = () => {
        textarea.style.height = 'auto';
        textarea.style.height = Math.min(textarea.scrollHeight, 160) + 'px';
      };
      textarea.addEventListener('input', autoGrow);

      textarea.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          sendBtn.click();
        }
      });

      sendBtn.addEventListener('click', async () => {
        if (busy) return;
        // Block sends until network discovery has surfaced a real model.
        // No fallback model — the client cannot guess what providers
        // are serving, so we wait for /v1/models to return at least one.
        if (!canSend()) return;
        const prompt = textarea.value.trim();
        if (!prompt) return;
        textarea.value = '';
        autoGrow();
        await handleSend(prompt);
      });

      wireHeaderActions();
      // Reflect the initial loading state on the send button — flips
      // to enabled once `refreshModels` resolves.
      syncSendButton();

      setTimeout(() => {
        textarea.focus();
        scrollToBottom();
      }, 60);

      // Lazy-load network discovery: node count for the header chip,
      // and the model catalogue that drives the settings picker.
      refreshDroneCount();
      refreshModels();

      // Restore the auto-approve toggle from prior sessions. Stored as a
      // boolean; coerce defensively in case an older string slipped in.
      storage.getItem(AUTO_APPROVE_KEY).then((v) => {
        autoApproveContracts = v === true;
      }).catch(() => {});
      storage.getItem(HIDE_PAYMENTS_KEY).then((v) => {
        hidePaymentAmounts = v === true;
        // Re-render so already-pushed paid rows hide on next render
        // pass without waiting for another conversation update.
        if (hidePaymentAmounts) rerender();
      }).catch(() => {});
    },
  };
}

// ── Structural markup helpers ────────────────────────────────────────────

/** Right-side cluster slotted into the shared `appHeader`. Mirrors the
 *  dashboard's "Synced" status pattern: a compact live-status chip plus
 *  any tab-specific controls. Wrapped in a stable id so `syncHeader()`
 *  can swap just this fragment when conversation state changes (the
 *  "New chat" button only appears once there's a conversation to clear). */
function renderHeaderRight() {
  const droneLabel = droneCount == null
    ? '… drones'
    : `${droneCount} ${droneCount === 1 ? 'drone' : 'drones'}`;
  const canReset = conversation.some((m) => m.kind === 'text');
  const newChatBtn = canReset
    ? `<button id="ai-new-chat" class="ai-header-iconbtn" title="New chat" aria-label="New chat">${icon('sparkle')}</button>`
    : '';
  const model = activeModel();
  const chipTooltip = model
    ? model.name
    : (modelsState === 'loading' ? 'Discovering drones…' : 'No drones online');
  return `
    <div id="ai-header-right" class="ai-header-right">
      <span class="ai-status-chip" title="${escapeHtml(chipTooltip)}">
        <span class="live-dot"></span>
        <span id="ai-drones">${escapeHtml(droneLabel)}</span>
      </span>
      ${newChatBtn}
      <button id="ai-settings-cog" class="ai-header-iconbtn" title="Inference settings" aria-label="Inference settings">${icon('settings')}</button>
    </div>
  `;
}

function wireHeaderActions() {
  document.getElementById('ai-new-chat')?.addEventListener('click', () => {
    if (busy) return;
    startNewChat();
  });
  document.getElementById('ai-settings-cog')?.addEventListener('click', toggleSettingsPanel);
}

function selectedTierEntry() {
  return TIERS.find((t) => t.id === selectedTier) || TIERS[0];
}

// ── Context trim (client-side) ───────────────────────────────────────────

function approxTokens(text) {
  // ~4 chars per token is the common rough heuristic for GPT-family
  // tokenizers; Qwen/Llama sit close. The drone re-tokenises with the
  // real model tokenizer, so the only risk is under-counting — which
  // CONTEXT_SAFETY absorbs.
  return Math.max(1, Math.ceil(String(text || '').length / 4));
}

/** Index into `conversation` of the first text message that still fits the
 *  budget. Everything before gets rendered dimmed + is excluded from the
 *  wire `messages[]`. If every message fits, returns 0. `pendingTokens`
 *  is the approx-token cost of the not-yet-appended user turn. */
function computeActiveStart(maxOutput, pendingTokens = 0) {
  const inputBudget = contextBudget() - maxOutput - CONTEXT_SAFETY;
  let acc = pendingTokens;
  const texts = conversation
    .map((m, i) => ({ m, i }))
    .filter((x) => x.m.kind === 'text');
  for (let j = texts.length - 1; j >= 0; j--) {
    const t = approxTokens(texts[j].m.content);
    if (acc + t > inputBudget) {
      // This one + everything older doesn't fit. Active starts at the
      // first conversation index belonging to the next text entry.
      return j + 1 < texts.length ? texts[j + 1].i : conversation.length;
    }
    acc += t;
  }
  return 0;
}

function renderStream() {
  if (conversation.length === 0) return renderEmpty();
  const tier = selectedTierEntry();
  const activeStart = computeActiveStart(tier.tokens);
  const anyDropped = activeStart > 0
    && conversation.slice(0, activeStart).some((m) => m.kind === 'text');

  let html = '';
  let cutoffEmitted = !anyDropped;
  conversation.forEach((m, i) => {
    if (!cutoffEmitted && i >= activeStart) {
      html += `<div class="ai-cutoff" role="separator" aria-label="Older messages not sent">`
            +   `<span class="ai-cutoff-mark">⊘</span>`
            +   `<span class="ai-cutoff-text">older messages not sent · context full</span>`
            + `</div>`;
      cutoffEmitted = true;
    }
    const dropped = i < activeStart && m.kind === 'text';
    html += renderItem(m, dropped);
  });
  return html;
}

function renderEmpty() {
  // Single hero visual (purple sigil + slow breathe) across every state
  // so the transition between loading/empty/ready never visually snaps.
  // What does change is the rail label, the copy below, and an optional
  // small "discovering" pill above the rail. The pill only renders when
  // discovery has been pending for >200ms (see `loadingShown` below) —
  // sub-200ms fast loads get zero flash.
  let rail = 'Standing by';
  let copy = `
    Ask anything. Pay in KRGN. Receive the response.
    <br/>No accounts, no middlemen — <em>negotiated on-chain, one sentence at a time.</em>
  `;
  let pill = '';

  if (modelsState === 'loading' && loadingShown) {
    pill = `<span class="ai-empty-pill"><span class="ai-empty-pill-dot"></span>Discovering network…</span>`;
  } else if (modelsState === 'empty') {
    rail = 'No drones online';
    copy = `
      The network has no drones accepting requests right now.
      <br/>Check back in a moment — or
      <a href="#" id="ai-empty-retry" style="color: var(--cyan); text-decoration: underline dotted;">retry discovery</a>.
    `;
  }

  return `
    <div class="ai-empty">
      ${pill}
      <span class="ai-empty-sigil">${icon('swarm')}</span>
      <span class="ai-empty-rail">${rail}</span>
      <p class="ai-empty-copy">${copy}</p>
    </div>
  `;
}

function renderItem(m, dropped = false) {
  if (m.kind === 'paid') {
    if (hidePaymentAmounts) return '';
    return `
      <div class="ai-paid">
        ${icon('check')}
        <span class="amt">${m.krgn} KRGN</span>
        <span class="txid">${escapeHtml(m.txid.slice(0, 10))}…</span>
      </div>
    `;
  }
  if (m.kind === 'thinking') {
    // Live status line: "queued / generating / elapsed Xs". Updated
    // in place by `tickThinking()` every second so the user sees
    // movement instead of an opaque spinner. Initial values come
    // from the invoice's heartbeat snapshot (m.queueAhead, m.etaSec).
    const status = thinkingStatusText(m);
    return `
      <div class="ai-wave" role="status" aria-label="Receiving">
        <span class="bar"></span><span class="bar"></span><span class="bar"></span>
        <span class="bar"></span><span class="bar"></span>
        <span id="ai-wave-status" class="ai-wave-status">${escapeHtml(status)}</span>
      </div>
    `;
  }
  if (m.kind === 'sys') {
    return `<div class="ai-sys">${escapeHtml(m.content)}</div>`;
  }
  if (m.kind === 'streaming') {
    // In-progress assistant message. Renders into the SAME structural
    // skeleton the finalized message uses (`<details class="ai-think">`
    // for thought blocks, plain-text body, model-name tag) so the
    // visual transition at end-of-stream is just removing one CSS
    // class — no DOM swaps, no layout jumps. The only difference
    // during streaming is the currently-open think block carries
    // `ai-think-streaming` which CSS uses to clip the body to a
    // ~3-line scrolling pane with a top-fade.
    const tag = escapeHtml(activeModel()?.name ?? 'assistant');
    return (
      `<div class="ai-msg ai-msg-assistant ai-msg-streaming">` +
        `<span class="ai-msg-tag">${tag}</span>` +
        `<div class="ai-msg-body md" data-stream-target>${renderStreamingInner(m.buffer)}</div>` +
      `</div>`
    );
  }
  // role-based message bubble. Assistant tag uses the active model name
  // when known; for an existing assistant message persisted from a turn
  // where the user has since switched models / discovery hasn't refreshed,
  // fall back to a neutral label rather than crashing on null.
  const tag = m.role === 'user'
    ? 'You'
    : escapeHtml(activeModel()?.name ?? 'assistant');
  const body = m.role === 'assistant'
    ? renderAssistantContent(m.content)
    : escapeHtml(m.content);
  const cls = m.role === 'assistant' ? 'ai-msg-body md' : 'ai-msg-body';
  const droppedCls = dropped ? ' ai-msg-dropped' : '';
  return (
    `<div class="ai-msg ai-msg-${m.role}${droppedCls}">` +
      `<span class="ai-msg-tag">${tag}</span>` +
      `<div class="${cls}">${body}</div>` +
    `</div>`
  );
}

/** Assistant content pipeline: strip <think> blocks to collapsible
 *  cards, render the rest as markdown. Each section is fully escaped
 *  before any HTML is emitted (see markdown.js).
 *
 *  Whitespace hygiene: some models (especially reasoning models coming
 *  out of a long `<think>` block) pad responses with leading /
 *  trailing newlines or spaces. We trim aggressively here AND on each
 *  extracted thought so nothing renders with a hollow gap at the top
 *  or bottom of its bubble. */
function renderAssistantContent(raw) {
  const trimmed = String(raw || '').trim();
  const { thoughts, body } = splitThinking(trimmed);
  let out = '';
  for (const t of thoughts) {
    const trimmedThought = t.trim();
    if (!trimmedThought) continue;
    // IMPORTANT: no whitespace between tags. Indented template literals
    // leave real text nodes in the DOM; `<details>` + flex summary
    // renders some of them as visible gaps (Firefox especially).
    out +=
      `<details class="ai-think">` +
        `<summary>` +
          `<span class="ai-think-icon">${icon('brain')}</span>` +
          `<span class="ai-think-label">Thought process</span>` +
          `<span class="ai-think-chev">${icon('chevronRight')}</span>` +
        `</summary>` +
        `<div class="ai-think-body">${renderMarkdown(trimmedThought)}</div>` +
      `</details>`;
  }
  const trimmedBody = body.trim();
  if (trimmedBody) out += renderMarkdown(trimmedBody);
  if (!out.trim()) out = escapeHtml('(empty)');
  return out;
}

function rerender() {
  const el = document.getElementById('ai-messages');
  if (!el) return;
  el.innerHTML = renderStream();
  // Re-render the header so "New chat" appears/disappears with state.
  syncHeader();
  // Wire the empty-state's "retry discovery" link if it just rendered.
  document.getElementById('ai-empty-retry')?.addEventListener('click', (e) => {
    e.preventDefault();
    modelsState = 'loading';
    armLoadingPill();
    rerender();
    syncSendButton();
    refreshDroneCount();
    refreshModels();
  });
  syncSendButton();
  scrollToBottom();
}

function syncHeader() {
  const rightEl = document.getElementById('ai-header-right');
  if (!rightEl) return;
  const wrapper = document.createElement('div');
  wrapper.innerHTML = renderHeaderRight();
  rightEl.replaceWith(wrapper.firstElementChild);
  wireHeaderActions();
}

/** Walk a streaming-message buffer and split it into:
 *  - `closedThoughts`: any complete `<think>…</think>` blocks
 *  - `openThought`: the live (still-open) `<think>` content, or `null`
 *  - `body`: everything outside think blocks (visible answer text)
 *
 *  Stream-friendly: tolerates partial tags. The opening `<think>` token
 *  may straddle a chunk boundary, so we only switch into thinking-mode
 *  once the full open tag is in the buffer; same for the closing tag.
 *  Anything before a fully-arrived open tag — including a half-typed
 *  `<thi` — is treated as body text (which is wrong for a single tick
 *  but resolves on the next token, so the user sees at most a flicker). */
function splitStreamingBuffer(buf) {
  const closedThoughts = [];
  let openThought = null;
  let body = '';

  let i = 0;
  while (i < buf.length) {
    const openIdx = buf.indexOf('<think>', i);
    if (openIdx === -1) {
      // No more think blocks — rest is body.
      body += buf.slice(i);
      break;
    }
    // Body up to the open tag.
    body += buf.slice(i, openIdx);
    const afterOpen = openIdx + '<think>'.length;
    const closeIdx = buf.indexOf('</think>', afterOpen);
    if (closeIdx === -1) {
      // Open think still in progress.
      openThought = buf.slice(afterOpen);
      i = buf.length;
    } else {
      closedThoughts.push(buf.slice(afterOpen, closeIdx));
      i = closeIdx + '</think>'.length;
    }
  }
  return { closedThoughts, openThought, body };
}

/** Render the inside of a streaming bubble. Same structural skeleton as
 *  `renderAssistantContent` (closed `<details class="ai-think">` + body
 *  text), with one extra wrinkle: the currently-open `<think>` block —
 *  if any — gets the `ai-think-streaming` class on its `<details>`. CSS
 *  uses that class to clip the body to a ~3-line scrolling pane with a
 *  top-fade mask; JS auto-scrolls it bottom-anchored on each update.
 *  When `</think>` lands, the class is dropped on the next tick and the
 *  details element transitions naturally to the standard collapsible
 *  shape — no DOM swap, no layout jump. */
function renderStreamingInner(buf) {
  const { closedThoughts, openThought, body } = splitStreamingBuffer(buf);
  let out = '';
  for (const t of closedThoughts) {
    const trimmed = t.trim();
    if (!trimmed) continue;
    out +=
      `<details class="ai-think">` +
        `<summary>` +
          `<span class="ai-think-icon">${icon('brain')}</span>` +
          `<span class="ai-think-label">Thought process</span>` +
          `<span class="ai-think-chev">${icon('chevronRight')}</span>` +
        `</summary>` +
        `<div class="ai-think-body">${renderMarkdown(trimmed)}</div>` +
      `</details>`;
  }
  if (openThought !== null) {
    // Same `<details class="ai-think">` shape as a finalized one, just
    // open + flagged for the streaming clip-and-scroll behavior. No
    // markdown render here yet — the inner text is the raw growing
    // reasoning; we render it as a plain `<pre>` inside the body so a
    // mid-codeblock token doesn't break layout. The body stays in
    // place when the stream closes; only the class flag gets removed.
    const live = openThought.replace(/^\n+/, '');
    out +=
      `<details class="ai-think ai-think-streaming" open>` +
        `<summary>` +
          `<span class="ai-think-icon">${icon('brain')}</span>` +
          `<span class="ai-think-label">Thought process · live</span>` +
          `<span class="ai-think-chev">${icon('chevronRight')}</span>` +
        `</summary>` +
        `<div class="ai-think-body">` +
          `<pre class="ai-streaming-thought-content">${escapeHtml(live)}</pre>` +
        `</div>` +
      `</details>`;
  }
  if (body) {
    // Live markdown rendering. The only thing that genuinely breaks
    // mid-stream is an unclosed ``` fence — the lazy matcher in
    // markdown.js won't find a closing pair so the literal backticks
    // would render as text and any subsequent prose would be misread
    // as outside the (yet-to-arrive) code block. Auto-close it before
    // parse so the partial code shows in its proper block as soon as
    // the opening fence lands.
    out += renderPartialMarkdown(body);
  }
  if (!out) {
    out = `<span class="ai-streaming-cursor">▍</span>`;
  }
  return out;
}

function pushMessage(role, content) {
  conversation.push({ kind: 'text', role, content });
  rerender();
}

/** Push an empty in-progress assistant message that the streaming
 *  handler appends tokens to. Returns the message object so the caller
 *  can hold a stable reference (we mutate `buffer` in place rather
 *  than rebuilding the conversation array on every token — the array
 *  itself is the same reference; only the inner string grows). */
function pushStreaming() {
  const msg = { kind: 'streaming', role: 'assistant', buffer: '' };
  conversation.push(msg);
  rerender();
  return msg;
}

/** Auto-close any unclosed ``` code fence so partial markdown renders
 *  cleanly during streaming. The markdown parser's fence regex is
 *  lazy-matched and pair-required — an open fence with no closer
 *  leaves both the literal backticks AND the in-flight code visible
 *  as plain text. Closing it temporarily means the user sees the code
 *  block forming as it streams, rather than backtick noise at the top
 *  followed by misformatted prose below. */
function renderPartialMarkdown(text) {
  const fenceCount = (text.match(/```/g) || []).length;
  const closed = (fenceCount % 2 === 0) ? text : (text + '\n```');
  return renderMarkdown(closed);
}

/** Append a text delta to the in-progress streaming message.
 *
 *  Critical perf note: this runs at ~50–80 Hz during generation. A
 *  full `rerender()` (innerHTML on the whole message stream) at that
 *  rate destroys interactivity, blows away open `<details>`, and
 *  thrashes layout. Instead we mutate ONLY the streaming bubble's
 *  body — its outer shell (assistant tag, bubble class) is rendered
 *  once when the bubble first lands, and stays in place untouched.
 *
 *  Update batching: the DOM write is deferred to the next animation
 *  frame, so multiple tokens that arrive within one frame (~16 ms at
 *  60 fps) coalesce into a single innerHTML swap + single markdown
 *  parse. At 64 tok/s this collapses the work from ~64 renders/sec
 *  down to a frame-rate-bounded 60 renders/sec — and the visible
 *  payoff is bigger than the count suggests, because each render now
 *  handles ~1 token of new content rather than burning a whole render
 *  cycle on each token individually.
 *
 *  Falls back to full rerender ONLY if the bubble isn't on screen yet
 *  (first call after pushStreaming where the rerender hasn't flushed). */
let _pendingStreamRender = null;
function appendStreamDelta(msg, delta) {
  msg.buffer += delta;
  if (_pendingStreamRender) return; // already queued for this frame
  _pendingStreamRender = requestAnimationFrame(() => {
    _pendingStreamRender = null;
    const target = document.querySelector('.ai-msg-streaming [data-stream-target]');
    if (!target) {
      rerender();
      return;
    }
    target.innerHTML = renderStreamingInner(msg.buffer);
    // The live thought block is clipped to ~3 lines; pin scroll to
    // the bottom edge so the newest reasoning stays visible.
    const pre = target.querySelector('.ai-streaming-thought-content');
    if (pre) pre.scrollTop = pre.scrollHeight;
    scrollToBottom();
  });
}

/** Convert a finished streaming message into a stable text message so
 *  it renders through the normal `renderAssistantContent` pipeline
 *  (markdown, collapsed think details, etc.). Optionally records the
 *  Kerrigan extension metadata (commitment + drone hash + token
 *  counts) for future verification UX. */
function finalizeStream(msg, kerriganMeta) {
  const idx = conversation.indexOf(msg);
  if (idx === -1) return;
  // Cancel any rAF queued by the last in-flight token — finalize is
  // about to swap the DOM out anyway, no point in one more partial
  // render right before that happens.
  if (_pendingStreamRender) {
    cancelAnimationFrame(_pendingStreamRender);
    _pendingStreamRender = null;
  }
  const finalText = (msg.buffer || '').trim() || '(empty)';
  conversation[idx] = {
    kind: 'text',
    role: 'assistant',
    content: finalText,
    // Stash for future verification UX (commitment, drone_pubkey_hash,
    // token_count, prompt_tokens, cached_prompt_tokens). Currently
    // unused by the renderer; reserved for the verification badge.
    kerrigan: kerriganMeta || null,
  };
  rerender();
}
function pushSys(content) {
  conversation.push({ kind: 'sys', content });
  rerender();
}
function pushPaid(krgn, txid) {
  conversation.push({ kind: 'paid', krgn, txid });
  rerender();
}
/** Status text shown next to the receiving-waveform animation. Phases:
 *   queued → generating → done. Two heuristics decide the phase:
 *     - elapsed < estimated wait → still queued (someone else is being
 *       served; we count down their remaining time)
 *     - elapsed >= wait → assume our turn started, switch to "generating
 *       Xs" with a live elapsed counter
 *   Cheap, no extra polling needed. */
function thinkingStatusText(m) {
  const elapsed = Math.max(0, Math.floor((Date.now() - (m.startedAt || Date.now())) / 1000));
  const wait = Number(m.etaSec || 0);
  const ahead = Number(m.queueAhead || 0);
  if (ahead > 0 && elapsed < wait) {
    const remaining = Math.max(1, wait - elapsed);
    return `queued · ${ahead} ahead · ~${remaining}s`;
  }
  return `generating · ${elapsed}s elapsed`;
}

let thinkingTimer = null;
function pushThinking({ queueAhead = 0, etaSec = 0 } = {}) {
  conversation.push({
    kind: 'thinking',
    startedAt: Date.now(),
    queueAhead,
    etaSec,
  });
  rerender();
  // Tick the status text once a second so the user sees the wait
  // counting down + then the elapsed counter ticking up. Cheap DOM
  // write, no relayout (just textContent on a single span).
  if (thinkingTimer) clearInterval(thinkingTimer);
  thinkingTimer = setInterval(() => {
    const m = conversation.find((x) => x.kind === 'thinking');
    const el = document.getElementById('ai-wave-status');
    if (!m || !el) return;
    el.textContent = thinkingStatusText(m);
  }, 1000);
}
function popThinking() {
  if (thinkingTimer) { clearInterval(thinkingTimer); thinkingTimer = null; }
  const i = conversation.findIndex(m => m.kind === 'thinking');
  if (i >= 0) conversation.splice(i, 1);
  rerender();
}

function startNewChat() {
  conversation.length = 0;
  pinnedDroneHash = null;
  rerender();
  document.getElementById('ai-prompt')?.focus();
}

function scrollToBottom() {
  const el = document.getElementById('ai-messages');
  if (el) el.scrollTop = el.scrollHeight;
}

async function refreshDroneCount() {
  // Use the coordinator's LIVE relay-pool count, not the on-chain registry
  // count: a drone can be registered (and stay registered) for weeks
  // without actually being online to serve requests. The chip shows
  // "serving right now" — that's `connected_drones` from /v1/node-id.
  const live = await getLiveDroneCount();
  droneCount = live == null ? '—' : live;
  const el = document.getElementById('ai-drones');
  if (el) {
    el.textContent = typeof droneCount === 'number'
      ? `${droneCount} ${droneCount === 1 ? 'drone' : 'drones'}`
      : `${droneCount} drones`;
  }
}

/** Pull the network's model catalogue from the coordinator and update the
 *  local cache. If the current `selectedModelHash` has disappeared
 *  (provider offline, gguf swapped) we fall back to the first entry
 *  rather than pinning to nothing. Re-renders the status chip (model
 *  name) and — if the settings panel is currently open — its model
 *  section, so the UI doesn't show stale data. */
async function refreshModels() {
  // Arm the 200ms grace timer — if discovery completes before it fires,
  // the user never sees the "Discovering…" pill at all.
  armLoadingPill();
  // Snapshot before-state so we only rerender the message stream when
  // something user-visible actually changed. Avoids the cosmetic
  // flicker when the settings panel opens and re-fetches an unchanged
  // catalogue.
  const prevState = modelsState;
  const prevActiveHash = activeModel()?.gguf_hash || null;

  try {
    availableModels = await listInferenceModels();
  } catch {
    availableModels = [];
  }
  if (availableModels.length > 0) {
    const stillThere = availableModels.some((m) => m.gguf_hash === selectedModelHash);
    if (!stillThere) selectedModelHash = availableModels[0].gguf_hash || null;
    modelsState = 'ready';
  } else {
    modelsState = 'empty';
  }
  disarmLoadingPill();

  const newActiveHash = activeModel()?.gguf_hash || null;
  const stateChanged = prevState !== modelsState || prevActiveHash !== newActiveHash;

  if (stateChanged) {
    syncHeader();
    rerender();
    syncSendButton();
  }
  if (settingsOpen) refreshSettingsModelSection();
}

/** Reflect `canSend()` on the send button — disabled appearance + a
 *  tooltip hint when the network's still loading or has no providers. */
function syncSendButton() {
  const btn = document.getElementById('ai-send');
  if (!btn) return;
  if (canSend()) {
    btn.removeAttribute('disabled');
    btn.removeAttribute('title');
  } else {
    btn.setAttribute('disabled', 'true');
    btn.setAttribute('title',
      modelsState === 'loading'
        ? 'Discovering drones…'
        : 'No drones online — try again shortly',
    );
  }
}

// ── Wire-format builder ──────────────────────────────────────────────────

/** Filter the conversation down to the `[{role, content}]` array the
 *  drone understands, applying the context-budget trim. Strips UI
 *  ephemera (paid, sys, thinking) and appends the pending user turn.
 *  Returns `{messages, droppedCount}` so the caller can surface trim
 *  activity to the user. */
function buildMessages(pendingUserTurn, maxOutput) {
  const pendingTokens = approxTokens(pendingUserTurn);
  const activeStart = computeActiveStart(maxOutput, pendingTokens);
  const sliced = conversation.slice(activeStart);
  const droppedCount = conversation
    .slice(0, activeStart)
    .filter((m) => m.kind === 'text')
    .length;
  const out = sliced
    .filter((m) => m.kind === 'text')
    .map(({ role, content }) => ({ role, content }));
  out.push({ role: 'user', content: pendingUserTurn });
  return { messages: out, droppedCount };
}

// ── Inference invoice (pre-pay confirmation card) ───────────────────────

function confirmContract(invoice, model, maxTokens) {
  // Auto-approve short-circuits the entire UI path: no card render, no
  // user gesture, just resolve true so `handleSend` proceeds to broadcast.
  // The setting is opt-in and persisted, so users who flip it know they're
  // delegating per-request payment authorisation to the wallet.
  if (autoApproveContracts) return Promise.resolve(true);
  const slot = document.getElementById('ai-invoice-slot');
  if (!slot) return Promise.resolve(false);
  // Everything user-facing is denominated in KRGN. We still receive
  // amounts as integer sats from the coordinator (smallest unit, exact),
  // but `formatKRGN` handles the conversion + nice precision so we
  // never show "sat" anywhere in the UI.
  const krgn = formatKRGN(Number(invoice.amount_sat));
  const promptTokens = Number(invoice.prompt_tokens || 0);
  const cachedTokens = Number(invoice.cached_prompt_tokens || 0);
  const inRateSat = Number(invoice.in_rate_sat_per_token || 0);
  const cachedRateSat = Number(invoice.cached_rate_sat_per_token || 0);
  const outRateSat = Number(invoice.rate_sat_per_token || 0);
  const rotated = Boolean(invoice.drone_rotated);

  // Per-token rates in KRGN are tiny — ~5×10⁻⁷ KRGN/tok at the default
  // 50-sat input rate — so a "per-token" KRGN line would be unreadably
  // zero-prefixed. Show per-1000-tokens instead, where typical rates
  // become legible (e.g. 50 sat/tok = 0.0005 KRGN/1k tok).
  const fmtPerK = (sat) => formatKRGN(sat * 1000);

  // Build an optional "cache savings" line: shows only when at least one
  // token was served from the cached prefix.
  const savingsLine = cachedTokens > 0
    ? `<span class="k">Cache hit</span>
       <span class="v">${cachedTokens} / ${promptTokens} tokens
         <span class="ai-contract-dim">· saved ${formatKRGN(cachedTokens * (inRateSat - cachedRateSat))} KRGN</span>
       </span>`
    : '';

  const rotatedBanner = rotated
    ? `<div class="ai-contract-rotated">
         ${icon('sparkle')} pinned drone dropped — new drone selected · cache reset
       </div>`
    : '';

  // Live load info from the chosen provider's most recent heartbeat,
  // stamped onto the invoice by the coordinator. `drone_queue_depth`
  // includes anything currently mid-inference, so a value of 1 means
  // "someone else is being served right now, your turn next."
  const queue = Number(invoice.drone_queue_depth || 0);
  const eta = Number(invoice.drone_eta_seconds || 0);
  const queueLine = queue > 0
    ? `<span class="k">Queue</span>
       <span class="v">${queue} ahead of you
         <span class="ai-contract-dim">· ~${eta}s estimated wait</span>
       </span>`
    : '';

  return new Promise((resolve) => {
    slot.innerHTML = `
      <div class="ai-contract" role="dialog" aria-label="Inference invoice">
        <span class="ai-contract-corners"></span>
        <span class="ai-contract-sweep"></span>
        <div class="ai-contract-header">
          <span class="ai-contract-header-icon">${icon('swarm')}</span>
          <span class="ai-contract-header-label">Inference Invoice</span>
          <span class="ai-contract-header-dim"
            title="Direct on-chain payment, broadcast at 0 confirmations. Drones serve immediately and trust the TX will confirm; if a client tries to rescind, the provider files a negative reputation update against them on-chain.">
            0-conf · reputation-backed
          </span>
        </div>
        ${rotatedBanner}
        <div class="ai-contract-rows">
          <span class="k">Model</span>     <span class="v">${escapeHtml(model)}</span>
          <span class="k">Output</span>    <span class="v">${maxTokens} tokens · ${fmtPerK(outRateSat)} KRGN/1k</span>
          <span class="k">Input</span>     <span class="v">${promptTokens} tokens · ${fmtPerK(inRateSat)} KRGN/1k</span>
          ${savingsLine}
          <span class="k">Drone</span>  <span class="v dim">${escapeHtml(invoice.drone_pubkey_hash.slice(0, 24))}…</span>
          ${queueLine}
        </div>
        <div class="ai-contract-total">
          <span class="ai-contract-total-label">Amount due</span>
          <span>
            <span class="ai-contract-total-amt">${krgn}</span>
            <span class="ai-contract-total-sat">KRGN</span>
          </span>
        </div>
        <div class="ai-contract-actions">
          <button id="ai-pay-no"  class="ai-contract-btn secondary">Abort</button>
          <button id="ai-pay-yes" class="ai-contract-btn primary">Authorise</button>
        </div>
      </div>
    `;
    const close = () => { slot.innerHTML = ''; };
    document.getElementById('ai-pay-yes').addEventListener('click', () => { close(); resolve(true); });
    document.getElementById('ai-pay-no' ).addEventListener('click', () => { close(); resolve(false); });
  });
}

// ── End-to-end send ──────────────────────────────────────────────────────

async function handleSend(prompt) {
  busy = true;
  const sendBtn = document.getElementById('ai-send');
  sendBtn?.setAttribute('disabled', 'true');

  const tier = selectedTierEntry();
  const maxTokens = tier.tokens;
  const { messages, droppedCount } = buildMessages(prompt, maxTokens);

  pushMessage('user', prompt);
  if (droppedCount > 0) {
    pushSys(`older ${droppedCount} message${droppedCount === 1 ? '' : 's'} trimmed to fit the ${contextBudget()}-token context — starting a new chat would restore full history`);
  }
  try {
    // 1. Invoice — pin to the current provider if we have one; otherwise
    //    let the coordinator VRF-select and remember its hash for next time.
    const invoice = await requestInferenceInvoice({
      model: activeModel().name,
      messages,
      maxTokens,
      droneHash: pinnedDroneHash,
    });

    // If the coordinator rotated us to a different provider, the cache state
    // we were counting on is gone — surface that to the user so they know
    // why the invoice isn't cheaper.
    if (invoice.drone_rotated) {
      pinnedDroneHash = null; // will be re-pinned below
    }

    // 2. Neural contract
    const ok = await confirmContract(invoice, activeModel().name, maxTokens);
    if (!ok) {
      pushSys('transmission aborted');
      return;
    }

    // 3. Build + broadcast payment TX
    const utxos = await loadFullUtxos();
    const signed = sdk.buildInferencePaymentTx(
      utxos, invoice, PARAMS, store.wallet.seed,
    );
    const txid = await sendRawTransaction(signed.tx_hex);
    const krgn = formatKRGN(Number(invoice.amount_sat));
    pushPaid(krgn, txid);

    // 4. Chat (with waveform indicator + live queue/ETA status).
    //    Initial counts come from the invoice's heartbeat snapshot;
    //    the indicator self-ticks once a second so the user sees
    //    progress instead of an opaque spinner.
    pushThinking({
      queueAhead: Number(invoice.drone_queue_depth || 0),
      etaSec: Number(invoice.drone_eta_seconds || 0),
    });

    // Streaming flow: drop the wave indicator on the first token, push
    // a live `streaming` message that grows token-by-token, finalize
    // it (and capture the Kerrigan commitment in `x_kerrigan` for
    // future verification UX) once the [DONE] sentinel lands.
    let streamingMsg = null;
    let streamErr = null;
    await submitInferenceChatStream({
      invoice,
      paymentTxid: txid,
      messages,
      model: activeModel().name,
      maxTokens,
      temperature: PARAMS.temperature,
      topP: PARAMS.topP,
      seed: PARAMS.seed,
      k: PARAMS.k,
      onDelta: (text) => {
        if (!streamingMsg) {
          popThinking();
          streamingMsg = pushStreaming();
        }
        appendStreamDelta(streamingMsg, text);
      },
      onError: (msg) => {
        streamErr = msg;
      },
      onDone: (kerriganMeta) => {
        if (streamingMsg) finalizeStream(streamingMsg, kerriganMeta);
      },
    });
    if (streamErr) {
      // The drone errored mid-stream (e.g. payment validation failed
      // even though we just broadcast — RBF rescind, double-spend,
      // etc.). Surface it as a sys message rather than silently
      // showing a partial answer.
      popThinking();
      if (streamingMsg) {
        const idx = conversation.indexOf(streamingMsg);
        if (idx !== -1) conversation.splice(idx, 1);
      }
      throw new Error(streamErr);
    }

    // Pin the provider for the rest of the chat so the next turn's
    // prompt prefix hits the KV cache.
    pinnedDroneHash = invoice.drone_pubkey_hash;
  } catch (err) {
    popThinking();
    console.error('ai send failed', err);
    pushSys(`error · ${err.message || err}`);
  } finally {
    busy = false;
    sendBtn?.removeAttribute('disabled');
    document.getElementById('ai-prompt')?.focus();
  }
}

// ── UTXO helper (mirrors loadFullUtxos in views/send.js) ─────────────────

async function loadFullUtxos() {
  // Force a fresh listunspent before every send. Without this, two
  // rapid AI turns in a row read the same stale snapshot from storage
  // and attempt to double-spend the original UTXO before the scripthash
  // subscription has swapped it for the previous tx's change. Electrum
  // returns unconfirmed UTXOs (height=0) in listunspent, so the fresh
  // fetch naturally includes the change we just created.
  await refreshTransparentBalance();
  const all = (await storage.getItem('transparent_utxos')) || [];
  if (all.length === 0) throw new Error('no transparent utxos — fund the wallet first');
  // Filter out immature coinbase UTXOs — the node would reject the
  // broadcast with `bad-txns-premature-spend-of-coinbase` and the user
  // sees an opaque HTTP 500. Pre-fix UTXOs lack the `mature` flag; we
  // default to mature=true for those so legacy data still spends.
  const spendable = all.filter((u) => u.mature !== false);
  if (spendable.length === 0) {
    const maturing = all.length;
    throw new Error(
      `wallet UTXOs all immature (${maturing} maturing — masternode rewards need 100 confirmations before they can be spent)`,
    );
  }
  const scriptPubkey = sdk.hexEncode(
    new Uint8Array(deriveScriptPubkey(store.wallet.transparentAddr)),
  );
  return spendable.map((u) => ({
    txid: u.tx_hash,
    vout: Number(u.tx_pos),
    amount: Number(u.value),
    script_pubkey: scriptPubkey,
  }));
}

function deriveScriptPubkey(address) {
  const raw = base58Decode(address);
  const pubkeyHash = raw.slice(1, 21);
  return [0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac];
}

// ── Inference settings panel ─────────────────────────────────────────────
//
// Slide-in drawer on the right side of the AI tab. Distinct from the
// wallet-wide /settings route — this only houses inference-specific
// options (tier, later: temperature, model, seed). The panel lives inside
// `.ai-view` so the wallet chrome and nav stay accessible behind it.

let settingsOpen = false;

function toggleSettingsPanel() {
  if (settingsOpen) closeSettingsPanel();
  else openSettingsPanel();
}

/** Portal host for the settings drawer. We attach it to <body> directly
 *  so the drawer escapes `.ai-view`'s stacking context (its `isolation:
 *  isolate` means any z-index set inside gets capped by `.ai-view`'s
 *  own auto/0 in the page root, which is below the navbar's z-index
 *  of 100). Reused across open/close cycles. */
const SETTINGS_PORTAL_ID = 'ai-settings-portal';
function settingsPortal() {
  let el = document.getElementById(SETTINGS_PORTAL_ID);
  if (!el) {
    el = document.createElement('div');
    el.id = SETTINGS_PORTAL_ID;
    document.body.appendChild(el);
  }
  return el;
}

function openSettingsPanel() {
  const root = settingsPortal();
  settingsOpen = true;
  root.innerHTML = `
    <div class="ai-settings-backdrop" data-dismiss="true"></div>
    <aside class="ai-settings-panel" role="dialog" aria-label="Inference settings">
      <header class="ai-settings-header">
        <span class="ai-settings-title">Inference settings</span>
        <button class="ai-settings-close" data-dismiss="true" aria-label="Close">×</button>
      </header>
      <section class="ai-settings-section" id="ai-settings-model-section">
        ${renderModelSection()}
      </section>
      <section class="ai-settings-section">
        <h4 class="ai-settings-h">Response length</h4>
        <p class="ai-settings-desc">
          How many tokens the model may generate per reply. You pay upfront
          for the full budget — unused tokens refund automatically in an
          on-chain change TX, so picking Long only moves cash-flow, never
          overspends.
        </p>
        <div class="ai-settings-options" role="radiogroup" aria-label="Response length">
          ${TIERS.map((t) => renderTierOption(t)).join('')}
        </div>
      </section>
      <section class="ai-settings-section">
        <h4 class="ai-settings-h">Payment authorisation</h4>
        <p class="ai-settings-desc">
          Each inference request normally pops a contract card you must
          authorise before the wallet broadcasts the payment TX. With
          auto-approve on, the wallet pays immediately — convenient for
          rapid back-and-forth, but it spends real KRGN with no manual
          gate. You can flip it off any time.
        </p>
        ${renderAutoApproveToggle()}
      </section>
      <section class="ai-settings-section">
        <h4 class="ai-settings-h">Chat appearance</h4>
        <p class="ai-settings-desc">
          Each inference posts a small "✓ X KRGN" row into the chat once
          its payment lands. Hiding them gives a cleaner reading flow —
          the payments still go through, they just don't show up in the
          message list.
        </p>
        ${renderHidePaymentsToggle()}
      </section>
    </aside>
  `;

  // Dismiss on backdrop click + close button + ESC.
  root.querySelectorAll('[data-dismiss="true"]').forEach((el) =>
    el.addEventListener('click', closeSettingsPanel),
  );
  document.addEventListener('keydown', onSettingsKeydown);

  wireSettingsInteractions(root);

  // Re-fetch models whenever the panel opens — catalogue changes as
  // providers join/leave. The initial render uses the cached list so
  // there's no flash of "loading"; the fetched result then updates
  // the section in place via `refreshModels` → `refreshSettingsModelSection`.
  refreshModels();

  // Force the browser to commit the panel's closed state (translateX
  // 100%, opacity 0) before we flip to .open. Without this nudge the
  // initial paint and the class flip get coalesced into the same
  // frame and the CSS transition has no "from" to interpolate from —
  // the panel jumps straight to its open state with no animation.
  // Reading `offsetWidth` is the standard reflow forcer.
  const panel = root.querySelector('.ai-settings-panel');
  const backdrop = root.querySelector('.ai-settings-backdrop');
  if (panel) void panel.offsetWidth;
  panel?.classList.add('open');
  backdrop?.classList.add('open');
}

function closeSettingsPanel() {
  settingsOpen = false;
  document.removeEventListener('keydown', onSettingsKeydown);
  const root = document.getElementById(SETTINGS_PORTAL_ID);
  if (!root) return;
  const panel = root.querySelector('.ai-settings-panel');
  const backdrop = root.querySelector('.ai-settings-backdrop');
  panel?.classList.remove('open');
  backdrop?.classList.remove('open');
  setTimeout(() => { if (!settingsOpen) root.innerHTML = ''; }, 220);
}

function onSettingsKeydown(e) {
  if (e.key === 'Escape') closeSettingsPanel();
}

/** Render the Model section of the settings panel. Each option pairs
 *  the model name with its context length — in the current architecture
 *  a drone serves ONE model at ONE context size, so (model, context)
 *  is the right unit of user choice. Drones count is shown as a
 *  small hint so users can see which options have redundancy. */
function renderModelSection() {
  // Branch on the empty case BEFORE dereferencing the active model —
  // `activeModel()` returns null when no providers have been discovered,
  // and we removed the hard-coded fallback so there's nothing to chain
  // .gguf_hash off of in that state.
  if (availableModels.length === 0) {
    return `
      <h4 class="ai-settings-h">Model</h4>
      <p class="ai-settings-desc">
        ${modelsState === 'loading'
          ? 'Discovering models on the network…'
          : 'No drones are online right now — this picker fills in as soon as a drone joins the swarm.'}
      </p>
    `;
  }

  const active = activeModel();
  const pickedHash = active?.gguf_hash || null;

  const options = availableModels.map((m) => {
    const isSel = m.gguf_hash === pickedHash;
    // 8192 is the only fallback rendered here — used purely for display
    // when a drone misreports its context window. Real send paths
    // always read the live `context_length` straight off the model entry.
    const ctx = Number(m.context_length) || 8192;
    const quant = m.quant && m.quant !== 'unknown' ? ` · ${m.quant}` : '';
    const drones = Array.isArray(m.drones) ? m.drones.length : 0;
    const droneHint = drones === 1 ? '1 drone' : `${drones} drones`;
    return (
      `<label class="ai-settings-option${isSel ? ' selected' : ''}" ` +
        `data-settings-model="${escapeHtml(m.gguf_hash)}" role="radio" aria-checked="${isSel}">` +
        `<span class="ai-settings-option-head">` +
          `<span class="ai-settings-option-label">${escapeHtml(m.name || m.id || 'unnamed')}</span>` +
          `<span class="ai-settings-option-tokens">${ctx.toLocaleString()} ctx</span>` +
        `</span>` +
        `<span class="ai-settings-option-hint">${escapeHtml(droneHint)}${escapeHtml(quant)}</span>` +
      `</label>`
    );
  }).join('');

  return `
    <h4 class="ai-settings-h">Model</h4>
    <p class="ai-settings-desc">
      Each option is a specific model paired with the context window the
      provider loaded it at. Switching models clears the current chat —
      different models use different prompt formats and the running
      conversation wouldn't transfer.
    </p>
    <div class="ai-settings-options" role="radiogroup" aria-label="Model">
      ${options}
    </div>
  `;
}

/** Swap only the model section's contents in place — used when
 *  `refreshModels` runs while the panel is open, so the user sees
 *  freshly discovered/removed models without a full re-open. */
function refreshSettingsModelSection() {
  const section = document.getElementById('ai-settings-model-section');
  if (!section) return;
  section.innerHTML = renderModelSection();
  wireSettingsInteractions(document.getElementById(SETTINGS_PORTAL_ID));
}

/** Attach click handlers to tier + model radios. Idempotent: we blow
 *  away and re-attach on every re-render, cloning nodes to clear any
 *  previously-bound listeners. */
function wireSettingsInteractions(root) {
  if (!root) return;

  root.querySelectorAll('[data-settings-tier]').forEach((el) => {
    const fresh = el.cloneNode(true);
    el.replaceWith(fresh);
    fresh.addEventListener('click', () => {
      selectedTier = fresh.getAttribute('data-settings-tier');
      root.querySelectorAll('[data-settings-tier]').forEach((opt) => {
        const on = opt.getAttribute('data-settings-tier') === selectedTier;
        opt.classList.toggle('selected', on);
        opt.setAttribute('aria-checked', on);
      });
      // Recompute trim indicator immediately — tier changes the budget.
      rerender();
    });
  });

  root.querySelectorAll('[data-settings-model]').forEach((el) => {
    const fresh = el.cloneNode(true);
    el.replaceWith(fresh);
    fresh.addEventListener('click', () => {
      const hash = fresh.getAttribute('data-settings-model');
      if (hash === selectedModelHash) return;
      // Model change mid-chat doesn't make sense — different chat templates,
      // different vocab. Dump the conversation (and the provider pin) so
      // the next turn starts fresh on the new model.
      selectedModelHash = hash;
      startNewChat();
      refreshSettingsModelSection();
      // Also need to refresh the trim indicator + status chip since the
      // context window just changed.
      rerender();
    });
  });

  // Bind every persisted on/off switch in one pass. Each switch
  // declares its data-setting attr (matching a key in the table below);
  // clicking flips the value, persists it, then updates the visual
  // state in place. Persist BEFORE mutating local state so a storage
  // failure doesn't desync the in-memory flag from disk.
  const TOGGLES = {
    'auto-approve': {
      key: AUTO_APPROVE_KEY,
      get: () => autoApproveContracts,
      set: (v) => { autoApproveContracts = v; },
      onChange: null,
    },
    'hide-payments': {
      key: HIDE_PAYMENTS_KEY,
      get: () => hidePaymentAmounts,
      set: (v) => { hidePaymentAmounts = v; },
      // Existing chat needs to redraw so already-rendered paid rows
      // disappear/reappear immediately, not just on the next message.
      onChange: () => rerender(),
    },
  };
  root.querySelectorAll('[data-settings-toggle]').forEach((el) => {
    const fresh = el.cloneNode(true);
    el.replaceWith(fresh);
    const id = fresh.getAttribute('data-settings-toggle');
    const spec = TOGGLES[id];
    if (!spec) return;
    fresh.addEventListener('click', async () => {
      const next = !spec.get();
      try {
        await storage.setItem(spec.key, next);
      } catch (e) {
        console.error(`failed to persist setting ${id}`, e);
        return;
      }
      spec.set(next);
      fresh.classList.toggle('selected', next);
      fresh.setAttribute('aria-checked', next);
      const indicator = fresh.querySelector('.ai-settings-toggle-state');
      if (indicator) indicator.textContent = next ? 'On' : 'Off';
      spec.onChange?.();
    });
  });
}

/** Square-style on/off toggle. Reuses the `.ai-settings-option` shell
 *  so the visual language matches the tier + model pickers, with a
 *  small "Off / On" indicator pill on the right. Single role="switch"
 *  widget — not a radiogroup — because there's only one option to flip.
 *  `id` matches a key in the TOGGLES table inside `wireSettingsInteractions`. */
function renderToggle(id, label, hint, on) {
  return (
    `<div class="ai-settings-option ai-settings-toggle${on ? ' selected' : ''}" ` +
      `data-settings-toggle="${id}" role="switch" aria-checked="${on}" tabindex="0">` +
      `<span class="ai-settings-option-head">` +
        `<span class="ai-settings-option-label">${escapeHtml(label)}</span>` +
        `<span class="ai-settings-toggle-state">${on ? 'On' : 'Off'}</span>` +
      `</span>` +
      `<span class="ai-settings-option-hint">${escapeHtml(hint)}</span>` +
    `</div>`
  );
}

function renderAutoApproveToggle() {
  return renderToggle(
    'auto-approve',
    'Auto-approve contracts',
    'Skip the per-request authorisation card',
    autoApproveContracts,
  );
}

function renderHidePaymentsToggle() {
  return renderToggle(
    'hide-payments',
    'Hide payment amounts',
    'Suppress the ✓ KRGN rows in chat',
    hidePaymentAmounts,
  );
}

function renderTierOption(t) {
  const isSel = t.id === selectedTier;
  return (
    `<label class="ai-settings-option${isSel ? ' selected' : ''}" ` +
      `data-settings-tier="${t.id}" role="radio" aria-checked="${isSel}">` +
      `<span class="ai-settings-option-head">` +
        `<span class="ai-settings-option-label">${escapeHtml(t.label)}</span>` +
        `<span class="ai-settings-option-tokens">${t.tokens} tok</span>` +
      `</span>` +
      `<span class="ai-settings-option-hint">${escapeHtml(t.hint)}</span>` +
      `<span class="ai-settings-option-desc">${escapeHtml(t.desc)}</span>` +
    `</label>`
  );
}
