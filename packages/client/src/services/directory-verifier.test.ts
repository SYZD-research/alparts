import { describe, it, expect } from 'vitest';
import {
  expireDirectoryEvent,
  serializeDeviceChallengeProof,
  serializeDeviceDecision,
  serializeDirectoryEntry,
  type DirectoryEntry,
  type DirectoryEvent,
} from '@alparts/shared';
import { deviceMeetsPolicy, emptyDirectory, verifyDirectoryEntries } from './directory-verifier';
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

describe('which devices may sign (SEC-01)', () => {
  it('never trusts a device that registered itself without approval', async () => {
    const owner = await identity();
    const bootstrapChallenge = 'bootstrap-challenge';
    const start = emptyDirectory(userId);
    const bootstrap = await append(start, {
      kind: 'bootstrap',
      deviceId: 'owner',
      actorDeviceId: 'owner',
      identityKey: owner.identityKey,
      challenge: bootstrapChallenge,
      signature: await sign(owner.key.privateKey, serializeDeviceChallengeProof(userId, bootstrapChallenge)),
    });
    const afterBootstrap = await verifyDirectoryEntries(start, [bootstrap]);
    // Anyone holding a fresh key (for example a compromised server) can append this.
    const injected = await identity();
    const registerChallenge = 'register-challenge';
    const register = await append(afterBootstrap, {
      kind: 'register',
      deviceId: 'injected',
      actorDeviceId: 'injected',
      identityKey: injected.identityKey,
      challenge: registerChallenge,
      signature: await sign(injected.key.privateKey, serializeDeviceChallengeProof(userId, registerChallenge)),
    });
    const state = await verifyDirectoryEntries(afterBootstrap, [register]);

    expect(state.devices.injected).toBeDefined();
    expect(deviceMeetsPolicy(state.devices.injected!, 'approved')).toBe(false);
    expect(deviceMeetsPolicy(state.devices.injected!, 'active')).toBe(false);
    expect(deviceMeetsPolicy(state.devices.owner!, 'approved')).toBe(true);
    expect(deviceMeetsPolicy(state.devices.owner!, 'active')).toBe(true);
  });

  it('keeps past signatures of a later-revoked device but not new ones', () => {
    const revoked = { approved: true, revoked: true, approvedSequence: 1, revokedSequence: 4 };
    expect(deviceMeetsPolicy(revoked, 'approved')).toBe(true);
    expect(deviceMeetsPolicy(revoked, 'active')).toBe(false);
    // Devices from before the transparency log carry their approval sequence.
    expect(deviceMeetsPolicy({ approved: false, revoked: false, approvedSequence: 3 }, 'approved')).toBe(true);
  });
});

describe('retiring a device nobody approved', () => {
  const challenge = 'expire-test-challenge';
  type Directory = ReturnType<typeof emptyDirectory>;
  const proof = async (keys: Awaited<ReturnType<typeof identity>>) =>
    sign(keys.key.privateKey, serializeDeviceChallengeProof(userId, challenge));
  /** An account whose first device, `owner`, is approved. */
  async function account() {
    const owner = await identity();
    const start = emptyDirectory(userId);
    const bootstrap = await append(start, {
      kind: 'bootstrap', deviceId: 'owner', actorDeviceId: 'owner', identityKey: owner.identityKey, challenge,
      signature: await proof(owner),
    });
    return { owner, entries: [bootstrap], state: await verifyDirectoryEntries(start, [bootstrap]) };
  }
  /** The device registers itself and stays pending: nobody approves it. */
  async function register(state: Directory, deviceId: string) {
    const keys = await identity();
    const entry = await append(state, {
      kind: 'register', deviceId, actorDeviceId: deviceId, identityKey: keys.identityKey, challenge,
      signature: await proof(keys),
    });
    return { keys, entry, state: await verifyDirectoryEntries(state, [entry]) };
  }
  const expiry = (state: Directory, deviceId: string, event: Partial<DirectoryEvent> = {}) =>
    append(state, { ...expireDirectoryEvent({ id: deviceId, identityKey: state.devices[deviceId].identityKey }), ...event });

  it('accepts the server retiring a pending device, and the entries after it', async () => {
    const { entries, state: opened } = await account();
    const pending = await register(opened, 'pending');
    const retire = await expiry(pending.state, 'pending');
    const retired = await verifyDirectoryEntries(pending.state, [retire]);
    expect(retired.devices.pending).toMatchObject({
      approved: false, revoked: true, approvedSequence: null, revokedSequence: retire.sequence,
    });
    expect(deviceMeetsPolicy(retired.devices.pending!, 'approved')).toBe(false);
    expect(deviceMeetsPolicy(retired.devices.pending!, 'active')).toBe(false);
    expect(retired.devices.owner).toMatchObject({ approved: true, revoked: false });
    expect(retired.head).toEqual({ userId, sequence: retire.sequence, hash: retire.hash });
    expect(retired.checkpoints[retire.sequence]).toBe(retire.hash);
    // Later entries chain from it, and one pass over everything gives the same state as several.
    const later = await register(retired, 'later');
    const all = [...entries, pending.entry, retire, later.entry];
    expect(await verifyDirectoryEntries(emptyDirectory(userId), all)).toEqual(later.state);
    expect(later.state.devices.later).toMatchObject({ approved: false, revoked: false });
  });

  it('refuses to retire a device that is or was approved', async () => {
    const { owner, state: opened } = await account();
    // The device the account started with.
    await expect(verifyDirectoryEntries(opened, [await expiry(opened, 'owner')])).rejects.toThrow('DIRECTORY_INVALID');

    // A device an approved device approved.
    const second = await register(opened, 'second');
    const decision = { kind: 'approve' as const, deviceId: 'second', identityKey: second.keys.identityKey, actorDeviceId: 'owner' };
    const approved = await verifyDirectoryEntries(second.state, [await append(second.state, {
      ...decision, signature: await sign(owner.key.privateKey, serializeDeviceDecision(second.state.head, decision)),
    })]);
    expect(approved.devices.second!.approved).toBe(true);
    await expect(verifyDirectoryEntries(approved, [await expiry(approved, 'second')])).rejects.toThrow('DIRECTORY_INVALID');

    // A device the recovery code approved.
    const recoveryKeys = await identity();
    const recoveryKey = JSON.stringify(await crypto.subtle.exportKey('jwk', recoveryKeys.key.publicKey));
    const generation = 'a7d4d6c0-0000-4000-8000-000000000001';
    const configuration = { kind: 'recovery-config' as const, deviceId: generation, identityKey: recoveryKey, actorDeviceId: 'owner' };
    const configured = await verifyDirectoryEntries(approved, [await append(approved, {
      ...configuration, signature: await sign(owner.key.privateKey, serializeDeviceDecision(approved.head, configuration)),
    })]);
    const third = await register(configured, 'third');
    const restore = { kind: 'recovery' as const, deviceId: 'third', identityKey: third.keys.identityKey, actorDeviceId: generation };
    const restored = await verifyDirectoryEntries(third.state, [await append(third.state, {
      ...restore, signature: await sign(recoveryKeys.key.privateKey, serializeDeviceDecision(third.state.head, restore)),
    })]);
    expect(restored.devices.third!.approved).toBe(true);
    await expect(verifyDirectoryEntries(restored, [await expiry(restored, 'third')])).rejects.toThrow('DIRECTORY_INVALID');

    // A device migrated from before the directory, once its pinned prefix is verified.
    const legacyKeys = await identity();
    const legacy = await append(emptyDirectory(userId), {
      kind: 'legacy', deviceId: 'old', actorDeviceId: 'old', identityKey: legacyKeys.identityKey, signature: '', challenge: 'active',
    });
    const anchor = { userId, sequence: legacy.sequence, hash: legacy.hash };
    const migrated = await verifyDirectoryEntries(emptyDirectory(userId), [legacy], anchor);
    await expect(verifyDirectoryEntries(migrated, [await expiry(migrated, 'old')], anchor)).rejects.toThrow('DIRECTORY_INVALID');
  });

  it('refuses to retire a device twice, and a retired device never comes back', async () => {
    const { owner, state: opened } = await account();
    const pending = await register(opened, 'pending');
    const retired = await verifyDirectoryEntries(pending.state, [await expiry(pending.state, 'pending')]);
    await expect(verifyDirectoryEntries(retired, [await expiry(retired, 'pending')])).rejects.toThrow('DIRECTORY_INVALID');
    const decision = { kind: 'approve' as const, deviceId: 'pending', identityKey: pending.keys.identityKey, actorDeviceId: 'owner' };
    await expect(verifyDirectoryEntries(retired, [await append(retired, {
      ...decision, signature: await sign(owner.key.privateKey, serializeDeviceDecision(retired.head, decision)),
    })])).rejects.toThrow('DIRECTORY_INVALID');
    await expect(verifyDirectoryEntries(retired, [await append(retired, {
      kind: 'register', deviceId: 'pending', actorDeviceId: 'pending', identityKey: pending.keys.identityKey, challenge,
      signature: await proof(pending.keys),
    })])).rejects.toThrow('DIRECTORY_INVALID');
  });

  it('takes the entry only as the server writes it', async () => {
    const { owner, state: opened } = await account();
    const pending = await register(opened, 'pending');
    const other = await identity();
    const refused = async (event: Partial<DirectoryEvent>) =>
      expect(verifyDirectoryEntries(pending.state, [await expiry(pending.state, 'pending', event)])).rejects.toThrow('DIRECTORY_INVALID');
    await refused({ deviceId: 'unknown', actorDeviceId: 'unknown', identityKey: other.identityKey });
    await refused({ identityKey: other.identityKey });
    await refused({ actorDeviceId: 'owner' });
    await refused({ signature: await sign(owner.key.privateKey, 'anything') });
    // Not even a device the account approved may retire it this way: it would have to revoke it.
    const byOwner = { kind: 'expire' as const, deviceId: 'pending', identityKey: pending.keys.identityKey, actorDeviceId: 'owner' };
    await refused({ actorDeviceId: 'owner', signature: await sign(owner.key.privateKey, serializeDeviceDecision(pending.state.head, byOwner)) });
    expect((await verifyDirectoryEntries(pending.state, [await expiry(pending.state, 'pending')])).devices.pending!.revoked).toBe(true);
  });

  it('keeps the hash chain rules for the entry', async () => {
    const { state: opened } = await account();
    const pending = await register(opened, 'pending');
    const retire = await expiry(pending.state, 'pending');
    await expect(verifyDirectoryEntries(pending.state, [{ ...retire, previousHash: '0'.repeat(64) }])).rejects.toThrow('DIRECTORY_INVALID');
    await expect(verifyDirectoryEntries(pending.state, [{ ...retire, sequence: retire.sequence + 1 }])).rejects.toThrow('DIRECTORY_INVALID');
    await expect(verifyDirectoryEntries(pending.state, [{ ...retire, userId: 'someone-else' }])).rejects.toThrow('DIRECTORY_INVALID');
    // Hashed as another device's entry, or as a different kind: the content must match the hash.
    await expect(verifyDirectoryEntries(pending.state, [{ ...retire, event: { ...retire.event, deviceId: 'owner', actorDeviceId: 'owner' } }])).rejects.toThrow('DIRECTORY_INVALID');
    await expect(verifyDirectoryEntries(pending.state, [{ ...retire, event: { ...retire.event, kind: 'revoke' } }])).rejects.toThrow('DIRECTORY_INVALID');
    // An entry between the registration and its retirement cannot be skipped or reordered.
    await expect(verifyDirectoryEntries(opened, [retire])).rejects.toThrow('DIRECTORY_INVALID');
  });
});
