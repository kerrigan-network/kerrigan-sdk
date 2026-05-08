import { defineConfig } from 'vite';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Post-build plugin: inject Subresource Integrity hashes on the entry
 * bundle's <script> and <link> tags in dist/index.html.
 *
 * Scope: only static tags in the HTML served to the browser (the chain-of-
 * trust root). Dynamically imported chunks, the WASM, and fonts-via-CSS
 * are not covered — that's a standard SRI limitation, not unique to this
 * app. The integrity-checked entry is trusted to load its own sub-resources
 * correctly; an attacker who can only tamper with chunks still has to
 * contend with the entry bundle that decides what to fetch.
 */
function sriInject() {
  return {
    name: 'sri-inject',
    apply: 'build',
    writeBundle(options) {
      const outDir = options.dir || 'dist';
      const htmlPath = join(outDir, 'index.html');
      let html;
      try {
        html = readFileSync(htmlPath, 'utf8');
      } catch {
        return; // no index.html to patch
      }

      const patched = html.replace(
        /<(script|link)\b([^>]*?)\s+(src|href)="([^"]+)"([^>]*)>/g,
        (match, tag, preAttrs, urlAttr, url, postAttrs) => {
          // Only integrity-check same-origin asset URLs that we actually emitted.
          if (!url.startsWith('/assets/')) return match;
          // Don't double-inject if somehow present already.
          if (/\bintegrity=/.test(preAttrs + postAttrs)) return match;
          try {
            const assetPath = join(outDir, url);
            const bytes = readFileSync(assetPath);
            const hash = createHash('sha384').update(bytes).digest('base64');
            return `<${tag}${preAttrs} ${urlAttr}="${url}" integrity="sha384-${hash}"${postAttrs}>`;
          } catch {
            // Asset not found in dist/ — fall through without mutation.
            return match;
          }
        },
      );

      if (patched !== html) {
        writeFileSync(htmlPath, patched);
      }
    },
  };
}

export default defineConfig({
  root: '.',
  publicDir: 'public',
  server: {
    port: 5174,
    fs: { allow: ['..'] },
    headers: {
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    },
  },
  build: {
    outDir: 'dist',
    target: 'esnext',
  },
  optimizeDeps: {
    exclude: ['kerrigan-sdk'],
  },
  worker: {
    format: 'es',
  },
  plugins: [sriInject()],
});
