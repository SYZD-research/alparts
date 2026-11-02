import { aad, open, seal } from './recovery-crypto';
import { fromBase64, toBase64 } from './security-storage';

/**
 * Version 2 seals the history archive key. Version 1 sealed the recovery code
 * itself, which also opens the key that approves new devices; it is only
 * recognised, never opened.
 */
export interface PasskeyWrap {
  version: 1 | 2;
  credentialId: string;
  rpId: string;
  salt: string;
  ciphertext: string;
}

export function parsePasskeyWrap(value: unknown): PasskeyWrap {
  const v = value as PasskeyWrap | null;
  if (!v || (v.version !== 1 && v.version !== 2) || typeof v.credentialId !== 'string'
    || !/^[A-Za-z0-9_-]{1,2048}$/.test(v.credentialId)
    || typeof v.rpId !== 'string' || !v.rpId || v.rpId.length > 253
    || typeof v.salt !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(v.salt)
    || typeof v.ciphertext !== 'string' || fromBase64(v.ciphertext).length !== 60) throw new Error('INVALID_PASSKEY_WRAP');
  return v;
}

async function evaluate(credentialIds: string[], salt: Uint8Array<ArrayBuffer>, rpId: string, onPrompt?: () => void) {
  if (!window.isSecureContext || !navigator.credentials || !['https:', 'http:'].includes(window.location.protocol)
    || !(window.location.hostname === rpId || window.location.hostname.endsWith(`.${rpId}`))) throw new Error('PASSKEY_VAULT_UNAVAILABLE');
  onPrompt?.();
  const response = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId,
      userVerification: 'required',
      timeout: 60_000,
      allowCredentials: credentialIds.map((id) => ({
        type: 'public-key', id: fromBase64(id.replace(/-/g, '+').replace(/_/g, '/')),
      })),
      extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
    },
  }) as PublicKeyCredential | null;
  if (!response || !credentialIds.includes(response.id)) throw new Error('PASSKEY_VAULT_UNAVAILABLE');
  const results = response.getClientExtensionResults() as AuthenticationExtensionsClientOutputs & {
    prf?: { results?: { first?: ArrayBuffer } };
  };
  const first = results.prf?.results?.first;
  if (!(first instanceof ArrayBuffer) || first.byteLength !== 32) throw new Error('PASSKEY_VAULT_UNAVAILABLE');
  // This assertion and its extension outputs must never be sent to the server.
  return { credentialId: response.id, secret: new Uint8Array(first) };
}

function context(userId: string, generation: string, wrap: Pick<PasskeyWrap, 'rpId' | 'credentialId' | 'salt'>) {
  return aad(userId, JSON.stringify(['passkey-archive', 2, generation, wrap.rpId, wrap.credentialId, wrap.salt]));
}

async function wrappingKey(secret: Uint8Array, binding: Uint8Array<ArrayBuffer>) {
  const key = await crypto.subtle.importKey('raw', secret as Uint8Array<ArrayBuffer>, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: binding,
    info: new TextEncoder().encode('alparts-passkey-master-wrap-v1') }, key,
  { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/**
 * Seals the history archive key (never the recovery code: that would let the
 * passkey approve devices). onPrompt runs just before the browser asks for
 * the passkey, and not at all if it cannot.
 */
export async function wrapArchiveKey(archive: Uint8Array, userId: string, generation: string, credentialIds: string[], rpId: string, onPrompt?: () => void): Promise<PasskeyWrap> {
  if (archive.length !== 32 || !credentialIds.length || credentialIds.length > 32) throw new Error('PASSKEY_VAULT_UNAVAILABLE');
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const result = await evaluate(credentialIds, salt, rpId, onPrompt);
  try {
    const binding = { credentialId: result.credentialId, rpId, salt: toBase64(salt) };
    const associated = context(userId, generation, binding);
    const ciphertext = await seal(await wrappingKey(result.secret, associated), archive, associated);
    return { version: 2, ...binding, ciphertext };
  } finally { result.secret.fill(0); }
}

export async function unwrapArchiveKey(value: unknown, userId: string, generation: string): Promise<Uint8Array> {
  const wrap = parsePasskeyWrap(value);
  if (wrap.version !== 2) throw new Error('INVALID_PASSKEY_WRAP');
  const result = await evaluate([wrap.credentialId], fromBase64(wrap.salt), wrap.rpId);
  try {
    const associated = context(userId, generation, wrap);
    return await open(await wrappingKey(result.secret, associated), wrap.ciphertext, associated);
  } finally { result.secret.fill(0); }
}

/** The stored backup key cannot unlock the master signing key. */
export async function deriveArchiveKey(raw: Uint8Array, userId: string, generation: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', raw as Uint8Array<ArrayBuffer>, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256',
    salt: aad(userId, generation), info: new TextEncoder().encode('alparts-history-archive-v2') }, key, 256));
}
