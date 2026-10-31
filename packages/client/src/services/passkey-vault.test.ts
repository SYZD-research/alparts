import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { deriveArchiveKey, unwrapArchiveKey, wrapArchiveKey } from './passkey-vault';

const credentialId = 'YWxwYXJ0cy10ZXN0LWNyZWRlbnRpYWw';
const credentialSecret = crypto.getRandomValues(new Uint8Array(32));
const credentialGet = vi.fn();
beforeEach(() => {
  vi.stubGlobal('window', { isSecureContext: true, location: { protocol: 'https:', hostname: 'chat.example.test' } });
  vi.stubGlobal('navigator', { credentials: { get: credentialGet } });
  credentialGet.mockImplementation(async () => ({
    id: credentialId, getClientExtensionResults: () => ({ prf: { results: { first: credentialSecret.slice().buffer } } }),
  }));
});
afterEach(() => { vi.unstubAllGlobals(); vi.clearAllMocks(); });

it('unlocks only with the selected passkey and the exact account/generation binding', async () => {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const wrapped = await wrapArchiveKey(raw, 'alice', 'generation', [credentialId], 'example.test');
  expect(await unwrapArchiveKey(wrapped, 'alice', 'generation')).toEqual(raw);
  await expect(unwrapArchiveKey(wrapped, 'bob', 'generation')).rejects.toThrow();
  await expect(unwrapArchiveKey(wrapped, 'alice', 'replacement')).rejects.toThrow();
  const options = credentialGet.mock.calls[0][0];
  expect(options.publicKey.userVerification).toBe('required');
  expect(options.publicKey.challenge).toHaveLength(32);
  expect(JSON.stringify(wrapped)).not.toContain(Array.from(raw).join(','));
});

it('refuses unsupported authenticators and foreign relying parties', async () => {
  credentialGet.mockResolvedValue({ id: credentialId, getClientExtensionResults: () => ({}) });
  await expect(wrapArchiveKey(new Uint8Array(32), 'alice', 'generation', [credentialId], 'example.test')).rejects.toThrow('PASSKEY_VAULT_UNAVAILABLE');
  credentialGet.mockClear();
  await expect(wrapArchiveKey(new Uint8Array(32), 'alice', 'generation', [credentialId], 'attacker.test')).rejects.toThrow();
  expect(credentialGet).not.toHaveBeenCalled();
});

it('never opens a wrap of the recovery code made before 2026-10-30', async () => {
  const wrapped = await wrapArchiveKey(crypto.getRandomValues(new Uint8Array(32)), 'alice', 'generation', [credentialId], 'example.test');
  await expect(unwrapArchiveKey({ ...wrapped, version: 1 }, 'alice', 'generation')).rejects.toThrow('INVALID_PASSKEY_WRAP');
});

it('separates the persistent archive key from the master seed and other accounts', async () => {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const key = await deriveArchiveKey(raw, 'alice', 'generation');
  expect(key).not.toEqual(raw);
  expect(key).not.toEqual(await deriveArchiveKey(raw, 'bob', 'generation'));
  expect(key).not.toEqual(await deriveArchiveKey(raw, 'alice', 'replacement'));
});

// AES-GCM of 32 bytes of 0x44 under the HKDF of a PRF output of 32 bytes of 0x33, nonce 12 bytes of 0x22.
const KNOWN_CIPHERTEXT = 'IiIiIiIiIiIiIiIimF2wEN/nMZv8FE6GUFynn+eOZj5xwKveh144SZtTEDM3csq88tIL283R+rggwDYI';

describe('the version 2 wrap', () => {
  const userId = '11111111-1111-4111-8111-111111111111';
  const generation = '22222222-2222-4222-8222-222222222222';
  const rpId = 'example.test';
  const prf = new Uint8Array(32).fill(0x33);
  const archive = new Uint8Array(32).fill(0x44);
  const salt = btoa(String.fromCharCode(...new Uint8Array(32).fill(0x11)));
  // The associated data, written out: account, generation, relying party, credential and salt are bound.
  const associated = JSON.stringify(['alparts-history-recovery', 1, userId,
    JSON.stringify(['passkey-archive', 2, generation, rpId, credentialId, salt])]);

  async function fixedWrap() {
    // Salt and challenge (32 bytes) and the AES-GCM nonce (12 bytes) are fixed for the vector.
    vi.spyOn(crypto, 'getRandomValues').mockImplementation(((array: Uint8Array) =>
      array.fill(array.length === 12 ? 0x22 : 0x11)) as unknown as typeof crypto.getRandomValues);
    credentialGet.mockImplementation(async () => ({
      id: credentialId, getClientExtensionResults: () => ({ prf: { results: { first: prf.slice().buffer } } }),
    }));
    try {
      return await wrapArchiveKey(archive.slice(), userId, generation, [credentialId], rpId);
    } finally {
      vi.mocked(crypto.getRandomValues).mockRestore();
    }
  }

  it('matches the canonical serialization and the known ciphertext', async () => {
    const wrap = await fixedWrap();
    expect(wrap).toMatchObject({ version: 2, credentialId, rpId, salt });
    // Opened independently from the written-out associated data.
    const aad = new TextEncoder().encode(associated);
    const material = await crypto.subtle.importKey('raw', prf, 'HKDF', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: aad,
      info: new TextEncoder().encode('alparts-passkey-master-wrap-v1') }, material,
    { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const bytes = Uint8Array.from(atob(wrap.ciphertext), (c) => c.charCodeAt(0));
    expect(bytes.slice(0, 12)).toEqual(new Uint8Array(12).fill(0x22));
    const opened = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: bytes.slice(0, 12), additionalData: aad }, key, bytes.slice(12)));
    expect(opened).toEqual(archive);
    expect(wrap.ciphertext).toBe(KNOWN_CIPHERTEXT);
  });

  it('does not open when any bound field is replaced or the ciphertext is altered', async () => {
    const wrap = await fixedWrap();
    // The authenticator answers with the same PRF output whatever it is asked, so only the binding stops these.
    credentialGet.mockImplementation(async (options: { publicKey: { allowCredentials: Array<{ id: ArrayBuffer }> } }) => ({
      id: btoa(String.fromCharCode(...new Uint8Array(options.publicKey.allowCredentials[0].id)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
      getClientExtensionResults: () => ({ prf: { results: { first: prf.slice().buffer } } }),
    }));
    expect(await unwrapArchiveKey(wrap, userId, generation)).toEqual(archive);
    const flipped = Uint8Array.from(atob(wrap.ciphertext), (c) => c.charCodeAt(0));
    flipped[20] ^= 1;
    for (const altered of [
      { ...wrap, credentialId: 'b3RoZXItY3JlZGVudGlhbA' },
      { ...wrap, rpId: 'chat.example.test' },
      { ...wrap, salt: btoa(String.fromCharCode(...new Uint8Array(32).fill(0x55))) },
      { ...wrap, ciphertext: btoa(String.fromCharCode(...flipped)) },
    ]) {
      await expect(unwrapArchiveKey(altered, userId, generation)).rejects.toThrow();
    }
  });
});
