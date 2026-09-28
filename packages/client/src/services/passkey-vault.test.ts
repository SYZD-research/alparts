import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { deriveArchiveKey, unwrapMasterSeed, wrapMasterSeed } from './passkey-vault';

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
  const wrapped = await wrapMasterSeed(raw, 'alice', 'generation', [credentialId], 'example.test');
  expect(await unwrapMasterSeed(wrapped, 'alice', 'generation')).toEqual(raw);
  await expect(unwrapMasterSeed(wrapped, 'bob', 'generation')).rejects.toThrow();
  await expect(unwrapMasterSeed(wrapped, 'alice', 'replacement')).rejects.toThrow();
  const options = credentialGet.mock.calls[0][0];
  expect(options.publicKey.userVerification).toBe('required');
  expect(options.publicKey.challenge).toHaveLength(32);
  expect(JSON.stringify(wrapped)).not.toContain(Array.from(raw).join(','));
});

it('refuses unsupported authenticators and foreign relying parties', async () => {
  credentialGet.mockResolvedValue({ id: credentialId, getClientExtensionResults: () => ({}) });
  await expect(wrapMasterSeed(new Uint8Array(32), 'alice', 'generation', [credentialId], 'example.test')).rejects.toThrow('PASSKEY_VAULT_UNAVAILABLE');
  credentialGet.mockClear();
  await expect(wrapMasterSeed(new Uint8Array(32), 'alice', 'generation', [credentialId], 'attacker.test')).rejects.toThrow();
  expect(credentialGet).not.toHaveBeenCalled();
});

it('separates the persistent archive key from the master seed and other accounts', async () => {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const key = await deriveArchiveKey(raw, 'alice', 'generation');
  expect(key).not.toEqual(raw);
  expect(key).not.toEqual(await deriveArchiveKey(raw, 'bob', 'generation'));
  expect(key).not.toEqual(await deriveArchiveKey(raw, 'alice', 'replacement'));
});
