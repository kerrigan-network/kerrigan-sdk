/** Sapling proving parameter manager — download, verify, cache in IndexedDB. */

import * as storage from './storage.js';

const OUTPUT_URL = 'https://kerrigan-bridge.jskitty.cat/params/sapling-output.params';
const SPEND_URL = 'https://kerrigan-bridge.jskitty.cat/params/sapling-spend.params';

let cachedOutput = null;
let cachedSpend = null;

/**
 * Get Sapling params (from memory → IndexedDB → network).
 * @param {Function} onProgress - callback({ phase, percent }) for UI updates
 * @returns {{ output: Uint8Array, spend: Uint8Array }}
 */
export async function getSaplingParams(onProgress) {
  // Memory cache
  if (cachedOutput && cachedSpend) return { output: cachedOutput, spend: cachedSpend };

  // IndexedDB cache
  const savedOutput = await storage.getItem('sapling_output_params');
  const savedSpend = await storage.getItem('sapling_spend_params');

  if (savedOutput && savedSpend) {
    cachedOutput = new Uint8Array(savedOutput);
    cachedSpend = new Uint8Array(savedSpend);
    return { output: cachedOutput, spend: cachedSpend };
  }

  // Download
  onProgress?.({ phase: 'Downloading output params...', percent: 0 });
  cachedOutput = await downloadWithProgress(OUTPUT_URL, (pct) => {
    onProgress?.({ phase: 'Downloading output params...', percent: Math.round(pct * 5) }); // 0-5%
  });

  onProgress?.({ phase: 'Downloading spend params...', percent: 5 });
  cachedSpend = await downloadWithProgress(SPEND_URL, (pct) => {
    onProgress?.({ phase: 'Downloading spend params...', percent: 5 + Math.round(pct * 90) }); // 5-95%
  });

  // Cache in IndexedDB
  onProgress?.({ phase: 'Caching params...', percent: 95 });
  await storage.setItem('sapling_output_params', Array.from(cachedOutput));
  await storage.setItem('sapling_spend_params', Array.from(cachedSpend));

  onProgress?.({ phase: 'Ready', percent: 100 });
  return { output: cachedOutput, spend: cachedSpend };
}

async function downloadWithProgress(url, onProgress) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Failed to download: ${response.status}`);

  const contentLength = response.headers.get('content-length');
  if (!contentLength || !response.body) {
    // No streaming — just download all at once
    const buf = await response.arrayBuffer();
    onProgress?.(1);
    return new Uint8Array(buf);
  }

  const total = parseInt(contentLength, 10);
  const reader = response.body.getReader();
  const chunks = [];
  let loaded = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    loaded += value.length;
    onProgress?.(loaded / total);
  }

  // Combine chunks
  const result = new Uint8Array(loaded);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

/** Check if params are already cached (fast check, no download). */
export async function hasParams() {
  if (cachedOutput && cachedSpend) return true;
  const o = await storage.getItem('sapling_output_params');
  const s = await storage.getItem('sapling_spend_params');
  return !!(o && s);
}
