/** AES-256-GCM encryption for seed storage using Web Crypto API + PBKDF2. */

const PBKDF2_ITERATIONS = 750_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;

async function deriveKey(passphrase, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/** Encrypt data with passphrase. Returns { salt, iv, ciphertext } as base64 strings. */
export async function encrypt(data, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await deriveKey(passphrase, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    data instanceof Uint8Array ? data : new TextEncoder().encode(data)
  );
  return {
    salt: btoa(String.fromCharCode(...salt)),
    iv: btoa(String.fromCharCode(...iv)),
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
  };
}

/** Decrypt data with passphrase. Returns Uint8Array. */
export async function decrypt({ salt, iv, ciphertext }, passphrase) {
  const saltBytes = Uint8Array.from(atob(salt), c => c.charCodeAt(0));
  const ivBytes = Uint8Array.from(atob(iv), c => c.charCodeAt(0));
  const ctBytes = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
  const key = await deriveKey(passphrase, saltBytes);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBytes },
    key,
    ctBytes
  );
  return new Uint8Array(plaintext);
}
