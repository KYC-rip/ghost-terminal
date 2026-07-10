// src/main/handlers/VigilHandler.ts
import { ipcMain } from 'electron';

/**
 * Persistence for the Vigil feature:
 *  - strike-wallet key blobs (AES-GCM ciphertext produced in the renderer;
 *    opaque to the main process — never plaintext key material)
 *  - armed/executing session snapshots (config only, no key material)
 *
 * NOTE: strike-key blobs are intentionally NOT deleted when an identity is
 * destroyed — an encrypted blob is the last recovery path for any funds left
 * on the burner address.
 */

const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const MAX_SESSION_BYTES = 16 * 1024;

const KEYS_BUCKET = 'vigil_strike_keys';
const RETIRED_BUCKET = 'vigil_strike_keys_retired';
const SESSIONS_BUCKET = 'vigil_sessions';

export const VIGIL_SESSION_VERSION = 1;

function isValidId(id: unknown): id is string {
  return typeof id === 'string' && ID_RE.test(id);
}

function isValidKeyBlob(blob: any): boolean {
  return !!blob
    && typeof blob === 'object'
    && blob.v === 1
    && typeof blob.salt === 'string' && blob.salt.length <= 64 && B64_RE.test(blob.salt)
    && typeof blob.iv === 'string' && blob.iv.length <= 64 && B64_RE.test(blob.iv)
    && typeof blob.ct === 'string' && blob.ct.length <= 4096 && B64_RE.test(blob.ct);
}

function isValidSession(session: any): { ok: boolean; error?: string } {
  if (!session || typeof session !== 'object') return { ok: false, error: 'Session must be an object' };
  if (session.version !== VIGIL_SESSION_VERSION) return { ok: false, error: `Unsupported session version ${session.version}` };
  if (!['SNIPE', 'EJECT'].includes(session.mode)) return { ok: false, error: 'Invalid mode' };
  if (!['ARMED', 'EXECUTING', 'POLLING'].includes(session.phase)) return { ok: false, error: 'Invalid phase' };
  const json = JSON.stringify(session);
  if (json.length > MAX_SESSION_BYTES) return { ok: false, error: 'Session too large' };
  // Defense in depth: sessions must never carry key material
  if (/privateKey|mnemonic|seed/i.test(json)) return { ok: false, error: 'Session must not contain key material' };
  return { ok: true };
}

export function registerVigilHandlers(store: any) {
  ipcMain.handle('vigil-save-strike-key', (_, identityId: string, blob: any) => {
    if (!isValidId(identityId)) return { success: false, error: 'Invalid identity id' };
    if (!isValidKeyBlob(blob)) return { success: false, error: 'Invalid key blob' };
    const keys = store.get(KEYS_BUCKET) || {};
    keys[identityId] = blob;
    store.set(KEYS_BUCKET, keys);
    return { success: true };
  });

  ipcMain.handle('vigil-get-strike-key', (_, identityId: string) => {
    if (!isValidId(identityId)) return null;
    const keys = store.get(KEYS_BUCKET) || {};
    return keys[identityId] || null;
  });

  ipcMain.handle('vigil-delete-strike-key', (_, identityId: string) => {
    if (!isValidId(identityId)) return { success: false, error: 'Invalid identity id' };
    const keys = store.get(KEYS_BUCKET) || {};
    delete keys[identityId];
    store.set(KEYS_BUCKET, keys);
    return { success: true };
  });

  // Burner rotation: move the current blob to a retired archive instead of
  // overwriting it. Retired blobs stay recoverable forever with the vault
  // password — a mistaken rotation can never strand funds permanently.
  ipcMain.handle('vigil-archive-strike-key', (_, identityId: string) => {
    if (!isValidId(identityId)) return { success: false, error: 'Invalid identity id' };
    const keys = store.get(KEYS_BUCKET) || {};
    const blob = keys[identityId];
    if (blob) {
      const retired = store.get(RETIRED_BUCKET) || {};
      retired[identityId] = [...(retired[identityId] || []), { ...blob, retiredAt: Date.now() }];
      store.set(RETIRED_BUCKET, retired);
      delete keys[identityId];
      store.set(KEYS_BUCKET, keys);
    }
    return { success: true };
  });

  ipcMain.handle('vigil-save-session', (_, identityId: string, session: any) => {
    if (!isValidId(identityId)) return { success: false, error: 'Invalid identity id' };
    const check = isValidSession(session);
    if (!check.ok) return { success: false, error: check.error };
    const sessions = store.get(SESSIONS_BUCKET) || {};
    sessions[identityId] = session;
    store.set(SESSIONS_BUCKET, sessions);
    return { success: true };
  });

  ipcMain.handle('vigil-get-session', (_, identityId: string) => {
    if (!isValidId(identityId)) return null;
    const sessions = store.get(SESSIONS_BUCKET) || {};
    return sessions[identityId] || null;
  });

  ipcMain.handle('vigil-clear-session', (_, identityId: string) => {
    if (!isValidId(identityId)) return { success: false, error: 'Invalid identity id' };
    const sessions = store.get(SESSIONS_BUCKET) || {};
    delete sessions[identityId];
    store.set(SESSIONS_BUCKET, sessions);
    return { success: true };
  });
}
