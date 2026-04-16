/** IndexedDB wrapper for wallet persistence. */

const DB_NAME = 'kerrigan-wallet';
const DB_VERSION = 2;

let db = null;

function open() {
  if (db) return Promise.resolve(db);
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const d = req.result;
      if (!d.objectStoreNames.contains('wallet')) {
        d.createObjectStore('wallet');
      }
      if (!d.objectStoreNames.contains('params')) {
        d.createObjectStore('params');
      }
    };
    req.onsuccess = () => { db = req.result; resolve(db); };
    req.onerror = () => reject(req.error);
  });
}

async function getStore(mode = 'readonly') {
  const d = await open();
  return d.transaction('wallet', mode).objectStore('wallet');
}

export async function getItem(key) {
  const store = await getStore();
  return new Promise((resolve, reject) => {
    const req = store.get(key);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
  });
}

export async function setItem(key, value) {
  const store = await getStore('readwrite');
  return new Promise((resolve, reject) => {
    const req = store.put(value, key);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

export async function removeItem(key) {
  const store = await getStore('readwrite');
  return new Promise((resolve, reject) => {
    const req = store.delete(key);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

export async function clear() {
  const store = await getStore('readwrite');
  return new Promise((resolve, reject) => {
    const req = store.clear();
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

/** Check if a wallet exists in storage. */
export async function hasWallet() {
  const data = await getItem('encrypted_seed');
  return data !== null;
}
