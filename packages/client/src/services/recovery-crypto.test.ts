import { describe, expect, it } from 'vitest';
import { aad, aes, open, seal, recoveryAccess } from './recovery-crypto';
import { fromBase64, toBase64 } from './security-storage';

describe('encrypted history recovery', () => {
  it('separates retrieval capabilities from encryption keys and other accounts/generations', async () => {
    const code = crypto.getRandomValues(new Uint8Array(32));
    const access = await recoveryAccess(code, 'alice', 'generation-1');
    expect(access).toEqual(await recoveryAccess(code, 'alice', 'generation-1'));
    expect(access.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(access.accessTokenHash).toMatch(/^[a-f0-9]{64}$/);
    expect((await recoveryAccess(code, 'bob', 'generation-1')).token).not.toBe(access.token);
    expect((await recoveryAccess(code, 'alice', 'generation-2')).token).not.toBe(access.token);
    const ciphertext = await seal(await aes(code), new Uint8Array(32), aad('alice', 'secret'));
    const capability = fromBase64(access.token.replace(/-/g, '+').replace(/_/g, '/') + '=');
    await expect(open(await aes(capability), ciphertext, aad('alice', 'secret'))).rejects.toThrow();
  });
  it('restores an archived message after device keys are lost, with exact account and epoch binding', async () => {
    const code = crypto.getRandomValues(new Uint8Array(32));
    const archiveKey = await aes(code);
    const messageKey = crypto.getRandomValues(new Uint8Array(32));
    const context = aad('alice', 'generation:channel:7:commitment');
    const backup = await seal(archiveKey, messageKey, context);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      await aes(messageKey),
      new TextEncoder().encode('以前のメッセージ'),
    );
    messageKey.fill(0);
    const restored = await open(await aes(code), backup, context);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce },
      await aes(restored),
      ciphertext,
    );
    expect(new TextDecoder().decode(plain)).toBe('以前のメッセージ');
    for (const wrongContext of [
      aad('bob', 'generation:channel:7:commitment'),
      aad('alice', 'generation:other:7:commitment'),
      aad('alice', 'generation:channel:8:commitment'),
    ]) {
      await expect(open(archiveKey, backup, wrongContext)).rejects.toThrow();
    }
    await expect(
      open(await aes(crypto.getRandomValues(new Uint8Array(32))), backup, context),
    ).rejects.toThrow();
    const changed = fromBase64(backup);
    changed[changed.length - 1] ^= 1;
    await expect(open(archiveKey, toBase64(changed), context)).rejects.toThrow();
    await expect(open(archiveKey, toBase64(changed.slice(0, 12)), context)).rejects.toThrow();
  });
});
