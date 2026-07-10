/**
 * AES-256-GCM encryption for the vigil strike-wallet private key.
 * The key-encryption-key is derived from the vault password with PBKDF2.
 * The resulting blob is opaque to the main process, which only stores it.
 */

const PBKDF2_ITERATIONS = 210_000; // OWASP 2023 recommendation for SHA-256
const VERSION = 1;

export interface EncryptedBlob {
  v: number;
  salt: string; // base64
  iv: string;   // base64
  ct: string;   // base64 (ciphertext + GCM tag)
}

const enc = new TextEncoder();
const dec = new TextDecoder();

function toB64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = '';
  bytes.forEach(b => { bin += String.fromCharCode(b); });
  return btoa(bin);
}

function fromB64(s: string): Uint8Array {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptStrikeKey(privateKeyHex: string, vaultPassword: string): Promise<EncryptedBlob> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(vaultPassword, salt);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, enc.encode(privateKeyHex));
  return { v: VERSION, salt: toB64(salt), iv: toB64(iv), ct: toB64(ct) };
}

export async function decryptStrikeKey(blob: EncryptedBlob, vaultPassword: string): Promise<string> {
  if (blob.v !== VERSION) throw new Error(`Unsupported strike-key blob version ${blob.v}`);
  const key = await deriveKey(vaultPassword, fromB64(blob.salt));
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(blob.iv) as BufferSource },
      key,
      fromB64(blob.ct) as BufferSource
    );
    return dec.decode(pt);
  } catch {
    throw new Error('Strike key decryption failed (wrong vault password?)');
  }
}
