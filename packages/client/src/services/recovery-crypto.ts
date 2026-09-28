import { fromBase64, toBase64 } from './security-storage';
const encoder = new TextEncoder();
export const aad = (userId: string, purpose: string) =>
  encoder.encode(JSON.stringify(['alparts-history-recovery', 1, userId, purpose]));
// A scoped retrieval capability; disclosing it does not disclose the AES key.
export async function recoveryAccess(raw: Uint8Array, userId: string, generation: string) {
  const material = await crypto.subtle.importKey(
    'raw',
    raw as Uint8Array<ArrayBuffer>,
    'HKDF',
    false,
    ['deriveBits'],
  );
  const bytes = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: aad(userId, generation),
        info: encoder.encode('alparts-recovery-retrieval-v1'),
      },
      material,
      256,
    ),
  );
  try {
    const token = toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(token)));
    return {
      token,
      accessTokenHash: Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join(''),
    };
  } finally {
    bytes.fill(0);
  }
}
export async function aes(raw: Uint8Array) {
  return crypto.subtle.importKey('raw', raw as Uint8Array<ArrayBuffer>, 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ]);
}
export async function seal(key: CryptoKey, raw: Uint8Array, context: Uint8Array) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        additionalData: context as Uint8Array<ArrayBuffer>,
      },
      key,
      raw as Uint8Array<ArrayBuffer>,
    ),
  );
  return toBase64(new Uint8Array([...nonce, ...encrypted]));
}
export async function open(key: CryptoKey, value: string, context: Uint8Array) {
  const bytes = fromBase64(value);
  return new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: bytes.slice(0, 12),
        additionalData: context as Uint8Array<ArrayBuffer>,
      },
      key,
      bytes.slice(12),
    ),
  );
}
