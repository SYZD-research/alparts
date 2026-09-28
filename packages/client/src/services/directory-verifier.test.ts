import { describe, it, expect } from 'vitest';
import {
  serializeDeviceChallengeProof,
  serializeDeviceDecision,
  serializeDirectoryEntry,
  type DirectoryEntry,
  type DirectoryEvent,
} from '@alparts/shared';
import { emptyDirectory, verifyDirectoryEntries } from './directory-verifier';
import { sha256, toBase64 } from './security-storage';
const userId = '54fc8aa4-9549-4598-859c-747969b241f9';
async function identity() {
  const key = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  return {
    key,
    identityKey: JSON.stringify({
      version: 1,
      signingKey: await crypto.subtle.exportKey('jwk', key.publicKey),
    }),
  };
}
async function sign(key: CryptoKey, payload: string) {
  return toBase64(
    new Uint8Array(
      await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        key,
        new TextEncoder().encode(payload),
      ),
    ),
  );
}
async function append(
  state: ReturnType<typeof emptyDirectory>,
  event: DirectoryEvent,
): Promise<DirectoryEntry> {
  const entry = {
    userId,
    sequence: state.head.sequence + 1,
    previousHash: state.head.hash,
    event,
  };
  return { ...entry, hash: await sha256(serializeDirectoryEntry(entry)) };
}
describe('device transparency', () => {
  it('requires an independently pinned migration prefix before approving legacy devices', async () => {
    const original = emptyDirectory(userId);
    const entry = await append(original, {
      kind: 'legacy',
      deviceId: 'old',
      actorDeviceId: 'old',
      identityKey: (await identity()).identityKey,
      signature: '',
      challenge: 'active',
    });
    await expect(verifyDirectoryEntries(original, [entry])).rejects.toThrow('DIRECTORY_INVALID');
    const anchor = { userId, sequence: entry.sequence, hash: entry.hash };
    await expect(
      verifyDirectoryEntries(original, [entry], {
        ...anchor,
        hash: '0'.repeat(64),
      }),
    ).rejects.toThrow();
    await expect(
      verifyDirectoryEntries(original, [entry], { ...anchor, userId: 'other' }),
    ).rejects.toThrow();
    const forged = await identity();
    const challenge = 'forged-bootstrap';
    const bootstrap = await append(original, {
      kind: 'bootstrap',
      deviceId: 'attacker',
      actorDeviceId: 'attacker',
      identityKey: forged.identityKey,
      challenge,
      signature: await sign(
        forged.key.privateKey,
        serializeDeviceChallengeProof(userId, challenge),
      ),
    });
    await expect(verifyDirectoryEntries(original, [bootstrap], anchor)).rejects.toThrow();
    const state = await verifyDirectoryEntries(original, [entry], anchor);
    expect(state.devices.old.approved).toBe(true);
    expect(state.migrationVerified).toBe(true);
    const injected = await append(state, {
      ...entry.event,
      deviceId: 'injected',
      actorDeviceId: 'injected',
    });
    await expect(verifyDirectoryEntries(state, [injected], anchor)).rejects.toThrow();
    const substituted = await append(original, {
      ...entry.event,
      identityKey: (await identity()).identityKey,
    });
    await expect(verifyDirectoryEntries(original, [substituted], anchor)).rejects.toThrow();
  });
  it('never exposes an approved legacy device before a paginated migration anchor is reached', async () => {
    let construction = emptyDirectory(userId);
    const entries: DirectoryEntry[] = [];
    for (let i = 0; i < 65; i++) {
      const entry = await append(construction, {
        kind: 'legacy',
        deviceId: `old-${i}`,
        actorDeviceId: `old-${i}`,
        identityKey: '{}',
        signature: '',
        challenge: 'active',
      });
      entries.push(entry);
      construction.head = {
        userId,
        sequence: entry.sequence,
        hash: entry.hash,
      };
    }
    const partial = await verifyDirectoryEntries(
      emptyDirectory(userId),
      entries.slice(0, 64),
      construction.head,
    );
    expect(Object.values(partial.devices).some((d) => d.approved)).toBe(false);
    const complete = await verifyDirectoryEntries(partial, entries.slice(64), construction.head);
    expect(Object.values(complete.devices).every((d) => d.approved)).toBe(true);
  });
  it('verifies approvals and rejects key substitution, self approval, reordering and legacy injection', async () => {
    const alice = await identity();
    const other = await identity();
    const challenge = 'test-device-proof';
    let state = emptyDirectory(userId);
    const root = await append(state, {
      kind: 'bootstrap',
      deviceId: 'first',
      identityKey: alice.identityKey,
      actorDeviceId: 'first',
      challenge,
      signature: await sign(alice.key.privateKey, serializeDeviceChallengeProof(userId, challenge)),
    });
    state = await verifyDirectoryEntries(state, [root]);
    const pending = await append(state, {
      kind: 'register',
      deviceId: 'second',
      identityKey: other.identityKey,
      actorDeviceId: 'second',
      challenge,
      signature: await sign(other.key.privateKey, serializeDeviceChallengeProof(userId, challenge)),
    });
    state = await verifyDirectoryEntries(state, [pending]);
    expect(state.devices.second.approved).toBe(false);
    const decision = {
      kind: 'approve' as const,
      deviceId: 'second',
      identityKey: other.identityKey,
      actorDeviceId: 'first',
    };
    const approval = await append(state, {
      ...decision,
      signature: await sign(alice.key.privateKey, serializeDeviceDecision(state.head, decision)),
    });
    expect((await verifyDirectoryEntries(state, [approval])).devices.second.approved).toBe(true);
    await expect(
      verifyDirectoryEntries(state, [{ ...approval, previousHash: '0'.repeat(64) }]),
    ).rejects.toThrow();
    const self = { ...decision, actorDeviceId: 'second' };
    await expect(
      verifyDirectoryEntries(state, [
        await append(state, {
          ...self,
          signature: await sign(other.key.privateKey, serializeDeviceDecision(state.head, self)),
        }),
      ]),
    ).rejects.toThrow();
    const substituted = { ...decision, identityKey: alice.identityKey };
    await expect(
      verifyDirectoryEntries(state, [
        await append(state, {
          ...substituted,
          signature: approval.event.signature,
        }),
      ]),
    ).rejects.toThrow();
    await expect(verifyDirectoryEntries(state, [pending])).rejects.toThrow();
    await expect(
      verifyDirectoryEntries(state, [
        await append(state, {
          ...approval.event,
          kind: 'legacy',
          signature: '',
        }),
      ]),
    ).rejects.toThrow();
  });
});

it('bounds checkpoint growth and fits the largest supported directory in encrypted storage', async () => {
  const state = emptyDirectory(userId);
  state.head = { userId, sequence: 8192, hash: 'f'.repeat(64) };
  // Largest accepted RSA modulus (4096 bits), canonical key fields, and every
  // retained device and checkpoint. The server caps these independently.
  const identityKey = JSON.stringify({ version: 1,
    encryptionKey: { kty: 'RSA', n: 'a'.repeat(684), e: 'AQAB', alg: 'RSA-OAEP-256', ext: true, key_ops: ['encrypt'] },
    signingKey: { kty: 'EC', crv: 'P-256', x: 'a'.repeat(43), y: 'a'.repeat(43), alg: 'ES256', ext: true, key_ops: ['verify'] },
  });
  for (let i = 0; i < 1025; i++) state.devices[String(i).padStart(36, '0')] = {
    identityKey, approved: true, revoked: true, approvedSequence: 8192, revokedSequence: 8192,
  };
  for (let i = 1; i <= 8192; i++) state.checkpoints[i] = 'f'.repeat(64);
  state.recovery = { generation: userId, signingKey: 'a'.repeat(1024) };
  expect(new TextEncoder().encode(JSON.stringify(state)).length).toBeLessThan(2 * 1024 * 1024);
  await expect(verifyDirectoryEntries({ ...state, head: { ...state.head, sequence: 8193 } }, [])).rejects.toThrow('DIRECTORY_INVALID');
  state.devices['extra'] = state.devices[String(0).padStart(36, '0')];
  await expect(verifyDirectoryEntries(state, [])).rejects.toThrow('DIRECTORY_INVALID');
});
