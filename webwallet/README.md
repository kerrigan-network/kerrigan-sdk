<p align="center">
  <strong>Kerrigan Webwallet</strong><br>
  <em>A private-first browser wallet for the Kerrigan Network. Shielded by default, keys never leave the tab.</em>
</p>

---

> *"We are the Swarm. Our memory is private."*

## What it is

A zero-install browser wallet for KRGN with full Sapling shielded-transaction support. Runs entirely client-side — the SDK and Sapling prover live in a Web Worker as WASM, keys never leave IndexedDB, and the only things crossing the network are compact sync data from the [bridge](../bridge/) and UTXO queries to ElectrumX.

No accounts. No servers holding state. No tracking. Restore from seed anywhere.

## Features

- **Transparent + shielded (Sapling) transactions** — send, receive, shield, unshield, sapling-to-sapling — with proper zk-proof generation in-browser.
- **Encrypted seed storage** — PBKDF2-SHA256 (750k iterations) + AES-256-GCM, IndexedDB-local.
- **Memo support** — ZIP-302-compatible memos on shielded notes; user-submitted memos rendered with HTML escaping.
- **QR-coded receive flow** — switchable between transparent (`K...`) and shielded (`ks1...`) addresses.
- **Live sync** — ElectrumX WebSocket for transparent state; compact binary stream from the bridge for shielded notes; automatic reconnect with subscription reconciliation.
- **Send-max on any pool** — fee math mirrors the SDK's builder for every tx type so the "needs N sat, has N sat" class of error never fires client-side.
- **Pending-tx resolution by txid** — unshields to external addresses track confirmations directly, not via address history.
- **Worker-isolated prover** — Sapling proving params download + SHA-256 verified + cached in IndexedDB once; proving runs off the main thread so the UI doesn't hitch during spends.

## Tech stack

| | |
|---|---|
| Framework | None — hand-rolled SPA in vanilla JS |
| Build | [Vite](https://vitejs.dev) 6 |
| Crypto | Browser WebCrypto (AES-GCM, PBKDF2, SHA-256) |
| WASM | [kerrigan-sdk](../sdk/) compiled via `wasm-pack` |
| QR | `qrcode-generator` (pure JS, no canvas/DOM dependency) |
| State | Proxy-based reactive store (`src/state.js`) with path subscriptions |
| Routing | Hash-free in-memory SPA router (`src/router.js`) |
| Storage | IndexedDB (via thin wrapper at `src/storage.js`) |

## Project layout

```
webwallet/
├── index.html            # Entry point
├── vite.config.js        # Dev server + build config (includes COOP/COEP headers)
├── package.json
├── public/               # Logo, fonts, favicon
├── pkg/ -> ../pkg        # Symlink or copy of the built kerrigan-sdk WASM
└── src/
    ├── main.js           # Boot: init WASM, register views, load wallet or welcome
    ├── router.js         # View registration + navigation + modal overlay
    ├── state.js          # Reactive store (Proxy) + subscribe/notify + balance helpers
    ├── storage.js        # IndexedDB wrapper
    ├── crypto.js         # AES-256-GCM + PBKDF2 for encrypted seed storage
    ├── network.js        # Bridge (HTTP) + ElectrumX (WebSocket) clients
    ├── sync.js           # Shield sync driver + transparent refresh + pending-tx resolver
    ├── sdk.js            # Thin JS wrapper around the kerrigan-sdk WASM exports
    ├── worker.js         # Web Worker: WASM prover + Sapling param cache
    ├── worker-pool.js    # Main-thread side of the worker contract
    ├── templates.js      # Shared HTML builders (escapeHtml, classifyTx, buttons, etc.)
    ├── utils.js          # Small pure helpers (base58 decode)
    ├── components/       # Reusable UI: modal, toast, icons, QR
    ├── css/              # Design system — theme, layout, components, views, animations
    └── views/            # One file per top-level screen
        ├── welcome.js    #   Seed create / restore / passphrase
        ├── login.js      #   Passphrase unlock
        ├── dashboard.js  #   Balances, recent activity, shield nudge
        ├── activity.js   #   Full tx history with filters
        ├── send.js       #   Address → amount → confirm → broadcast (all pools)
        ├── receive.js    #   QR + address display
        └── settings.js   #   Backup phrase, addresses, network status, resync, lock, delete
```

## Building

### Prerequisites

- **Node 20+** (for Vite 6).
- **Rust toolchain + wasm-pack** to build the SDK to WebAssembly.

### Build the SDK (required once, or whenever `sdk/` changes)

From the workspace root:

```bash
wasm-pack build sdk --target web --out-dir ../pkg
```

This produces `pkg/kerrigan_sdk.js` + `pkg/kerrigan_sdk_bg.wasm` at the root of the monorepo. The webwallet imports these directly.

### Development

```bash
cd webwallet
npm install
npm run dev
```

Dev server listens on `http://localhost:5174`. Hot-reloads everything except the WASM — if you change `sdk/` source, rebuild the WASM (above) and restart.

The Vite dev server already sets `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp`, which are required for `SharedArrayBuffer` (used by threaded WASM in some browsers). Production hosts need the same headers — see Deployment.

### Production build

```bash
npm run build
```

Emits a static site to `webwallet/dist/`. Roughly:

```
dist/index.html                    ~1 KB
dist/assets/index-*.js            ~28 KB gzipped   (wallet + workers)
dist/assets/kerrigan_sdk_bg-*.wasm  ~464 KB gzipped  (Rust SDK)
dist/assets/index-*.css           ~5 KB gzipped
dist/assets/worker-*.js           ~600 B gzipped
```

The Sapling proving parameters are **not** shipped in the bundle — the wallet downloads them lazily from the bridge the first time shielded proving is needed (~50 MB, cached in IndexedDB after SHA-256 verification).

## Deployment

The wallet is a plain static SPA. Any static host will do: S3 + CloudFront, Netlify, Caddy, Nginx, a USB drive. **But three headers are required**, otherwise the WASM prover loses threading and the first shield tx will noticeably hitch the UI:

```
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Content-Security-Policy: ... 'wasm-unsafe-eval' ...
```

### Caddy

```caddy
wallet.kerrigan.network {
    root * /var/www/kerrigan-webwallet/dist
    file_server
    header {
        Cross-Origin-Opener-Policy "same-origin"
        Cross-Origin-Embedder-Policy "require-corp"
        Content-Security-Policy "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self' https://kerrigan-bridge.jskitty.cat wss://electrum-kerrigan.jskitty.cat:50003 https://coordinator.jskitty.cat https://vote.kerrigan.network; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    }
}
```

### Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name wallet.kerrigan.network;
    root /var/www/kerrigan-webwallet/dist;

    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Embedder-Policy "require-corp" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self' https://kerrigan-bridge.jskitty.cat wss://electrum-kerrigan.jskitty.cat:50003 https://coordinator.jskitty.cat https://vote.kerrigan.network; style-src 'self' 'unsafe-inline'; img-src 'self' data:;" always;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # Don't cache HTML — always fetch the latest entry point
    location = /index.html {
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }
    # Cache everything else — Vite ships hashed filenames
    location /assets/ {
        add_header Cache-Control "public, max-age=31536000, immutable";
    }
}
```

### Network endpoints

Bridge and ElectrumX URLs are compiled into the bundle at `src/network.js`:

```js
const BRIDGE_URL = 'https://kerrigan-bridge.jskitty.cat';
const ELECTRUMX_URL = 'wss://electrum-kerrigan.jskitty.cat:50003';
```

If you're self-hosting, edit these two lines and rebuild. Both endpoints must be reachable from the user's browser with matching CSP `connect-src`.

### HTTPS

Required in practice — `crypto.subtle` only works in a secure context (HTTPS or `http://localhost`). Without it, seed encryption and decryption silently fail.

## Maintenance

### Updating the SDK

When `sdk/` source changes:

```bash
wasm-pack build sdk --target web --out-dir pkg
cd webwallet
npm run build
# deploy dist/
```

The WASM is referenced via hashed filenames, so users pick up the new version on their next visit without manual cache busting.

### Updating bridge / ElectrumX endpoints

Edit `src/network.js`, rebuild, redeploy. Update the CSP `connect-src` in whatever reverse proxy you're using.

### Changing the KDF

Iteration count lives in `src/crypto.js` as `PBKDF2_ITERATIONS`. The wallet **does not** carry backward-compatibility for changes to this — existing wallets encrypted with the old count will fail to decrypt. Callers re-import from seed.

To change it:

1. Bump `PBKDF2_ITERATIONS`.
2. Rebuild + deploy.
3. Communicate to users that they need to restore from seed once.

### Clearing local state (for testing, or when a user reports "wallet won't open")

IndexedDB under the origin. In Chrome DevTools: Application → IndexedDB → `kerrigan-wallet` → Delete. Then reload — the wallet starts fresh on the welcome screen.

The stored objects:

| Key | What |
|-----|------|
| `encrypted_seed` | AES-GCM-encrypted BIP-39 seed bytes |
| `encrypted_mnemonic` | AES-GCM-encrypted recovery phrase (for the "reveal seed" flow) |
| `wallet_meta` | Transparent + shielded address (so the login screen can show the address before decrypt) |
| `transparent_utxos` | Cached UTXO list for the transparent address |
| `shield_state` | `{ treeHex, notes, lastHeight }` — shield sync state |
| `tx_history` | Local tx history (confirmations, timestamps, memos) |
| `params` store | Sapling proving params (blob, SHA-256 verified on first download) |

### Shield sync out of sync

If a user reports wrong balance: **Settings → Resync Wallet** clears `shield_state`, `transparent_utxos`, and `tx_history`, then triggers a full re-sync against the bridge. Safe — the seed, mnemonic, and encryption remain untouched.

If Resync doesn't fix it, the bridge's `shield.bin` may be stale. See [`bridge/README.md`](../bridge/README.md) for how to regenerate it (`rm shield.bin shield_index.json` + restart).

### Monitoring

The wallet itself doesn't phone home. What to watch:

- **Bridge** — `GET /getblockcount` lag relative to the node's block tip. Drift of more than a few blocks for more than 60s means the bridge's indexer is stalled.
- **ElectrumX** — `server.version` round-trip time. Anything over 1s suggests connection degradation that will surface as UI lag.

### Common issues

| Symptom | Likely cause |
|---|---|
| "Failed to load wallet" on boot | WASM fetch failed (check `connect-src` in CSP, check `pkg/` deployed alongside `dist/`). |
| Shielded balance wrong after a known-good tx | Shield sync missed the tx. Resync. If Resync doesn't fix it, check bridge `shield.bin` integrity. |
| Pending tx never confirms | ElectrumX subscription was broken and subscribers weren't re-registered. Reload the tab. |
| Send modal shows "Insufficient balance" when balance is clearly enough | Fee-vs-builder mismatch. Check that the `pkg/` in production is built from the current `sdk/` — mismatched versions cause silent fee drift. |
| First shield takes >30s | Normal — first-time Sapling param download (~50 MB from bridge) + SHA-256 verify. Only happens once per install. |

## Architecture note

See the [monorepo root](../README.md#architecture) for how the webwallet fits into the rest of the stack. Short version: the webwallet is the WASM leg of the SDK fan-out, and talks to the bridge over HTTP for shielded data + ElectrumX over WSS for transparent data.

## Security posture

- **Seed lives in two places**: encrypted in IndexedDB (persistent) and in-memory in the store while unlocked. On lock, the in-memory copy is zeroed and nav returns to the login screen.
- **No key material crosses the worker boundary** — the worker receives the seed as bytes only when it needs to sign (via base64-serialized postMessage, then deserialized into the worker's own WASM memory).
- **All user-facing data** (memos, addresses from history, remote error strings) is passed through `escapeHtml` before interpolation into innerHTML. A hostile shielded memo cannot inject script.
- **No external script tags, no CDNs, no fonts from Google.** Everything self-hosted.
- **Threat model** — protects against: network attackers, hostile shielded senders, UI-level leaks. Does NOT protect against: a malicious browser extension with IDB access, physical access to an unlocked machine, or offline brute-force of a weak passphrase (PBKDF2 is hardened to 750k iterations, but the ultimate ceiling is passphrase entropy).

## License

MIT

---

<p align="center">
  <em>For the Swarm.</em>
</p>
