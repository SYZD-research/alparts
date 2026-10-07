import assert from 'node:assert/strict';
import { randomBytes, randomUUID, webcrypto } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  createCommit,
  createGroup,
  encodeMlsMessage,
  generateKeyPackage,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
} from 'ts-mls';
import {
  MAX_KEY_RECIPIENTS,
  MAX_MLS_KEY_PACKAGE_LENGTH,
  MAX_WORKSPACE_MEMBERS,
  MLS_CIPHERSUITE,
  mlsGroupId,
  type MlsGroupCommit,
} from '@alparts/shared';
import { validateMlsKeyPackage } from '../security/mls-package.js';
import { decodeGroupCommit, decodeGroupWelcome, readMemberPackage } from '../security/mls-group-commit.js';
import { assertCommitStructure } from '../services/mls-group-rules.js';
import {
  MLS_EPOCH_BODY_BYTES,
  mlsEpochProposal,
  mlsGroupCommitRequest,
  mlsGroupFreshStartRequest,
} from './mls-schema.js';

const encoder = new TextEncoder();
const base64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');
const fakeSignature = () => randomBytes(64).toString('base64');

async function identityKey() {
  const encryption = await webcrypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt'],
  );
  const signing = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  return JSON.stringify({
    version: 1,
    encryptionKey: { ...(await webcrypto.subtle.exportKey('jwk', encryption.publicKey)), alg: 'RSA-OAEP-256' },
    signingKey: { ...(await webcrypto.subtle.exportKey('jwk', signing.publicKey)), alg: 'ES256' },
  });
}

describe('MLS epoch proposal bounds', () => {
  it('accepts a signed proposal for the largest allowed roster', async () => {
    const cs = await getCiphersuiteImpl(getCiphersuiteFromName(MLS_CIPHERSUITE));
    const now = BigInt(Math.floor(Date.now() / 1000));
    const users = Array.from({ length: MAX_WORKSPACE_MEMBERS }, () => randomUUID());
    const sharedIdentityKey = await identityKey();
    const devices = await Promise.all(Array.from({ length: MAX_KEY_RECIPIENTS }, async (_, index) => {
      const deviceId = randomUUID();
      const pair = await generateKeyPackage(
        { credentialType: 'basic', identity: encoder.encode(deviceId) },
        { versions: ['mls10'], ciphersuites: [MLS_CIPHERSUITE], extensions: [], proposals: [], credentials: ['basic'] },
        { notBefore: now - 300n, notAfter: now + 604800n },
        [],
        cs,
      );
      const keyPackage = base64(encodeMlsMessage({ version: 'mls10', wireformat: 'mls_key_package', keyPackage: pair.publicPackage }));
      return { deviceId, userId: users[index % users.length], pair, keyPackage };
    }));
    const [creator, ...others] = devices;
    const group = await createGroup(encoder.encode('alparts-bounds'), creator.pair.publicPackage, creator.pair.privatePackage, [], cs);
    const result = await createCommit({ state: group, cipherSuite: cs }, {
      ratchetTreeExtension: true,
      extraProposals: others.map((device) => ({ proposalType: 'add' as const, add: { keyPackage: device.pair.publicPackage } })),
    });
    assert.ok(result.welcome);

    // A 400-device commit is about 164k characters, so it must not be capped
    // below what the roster limit itself allows.
    for (const device of devices) assert.ok(device.keyPackage.length <= MAX_MLS_KEY_PACKAGE_LENGTH);
    await validateMlsKeyPackage(creator.keyPackage, creator.deviceId);
    const channelId = randomUUID();
    const body = {
      epoch: {
        channelId,
        version: 2,
        previousVersion: 1,
        previousTranscript: 'a'.repeat(64),
        keyCommitment: 'b'.repeat(43),
        welcome: base64(encodeMlsMessage({ version: 'mls10', wireformat: 'mls_welcome', welcome: result.welcome })),
        commit: base64(encodeMlsMessage(result.commit)),
        roster: devices.map((device) => ({
          packageId: randomUUID(),
          keyPackage: device.keyPackage,
          signature: fakeSignature(),
          deviceId: device.deviceId,
          userId: device.userId,
          identityKey: sharedIdentityKey,
        })),
        directoryHeads: [...users].sort().map((userId) => ({ userId, sequence: 1, hash: 'c'.repeat(64) })),
        distributorDeviceId: creator.deviceId,
        signature: fakeSignature(),
      },
      keys: devices.map((device) => ({
        deviceId: device.deviceId,
        encryptedKey: Buffer.from(JSON.stringify({ mls: 1, version: 2, transcript: 'd'.repeat(64) })).toString('base64'),
        signature: fakeSignature(),
      })),
    };

    assert.equal(mlsEpochProposal.safeParse(body).success, true);
    assert.ok(Buffer.byteLength(JSON.stringify(body)) <= MLS_EPOCH_BODY_BYTES);
  });
});

describe('MLS group commit bounds', () => {
  it('accepts a group created with the largest allowed roster', async () => {
    const cs = await getCiphersuiteImpl(getCiphersuiteFromName(MLS_CIPHERSUITE));
    const now = BigInt(Math.floor(Date.now() / 1000));
    const users = Array.from({ length: MAX_WORKSPACE_MEMBERS }, () => randomUUID());
    const sharedIdentityKey = await identityKey();
    const devices = await Promise.all(Array.from({ length: MAX_KEY_RECIPIENTS }, async (_, index) => {
      const deviceId = randomUUID();
      const pair = await generateKeyPackage(
        { credentialType: 'basic', identity: encoder.encode(deviceId) },
        { versions: ['mls10'], ciphersuites: [MLS_CIPHERSUITE], extensions: [], proposals: [], credentials: ['basic'] },
        { notBefore: now - 900n, notAfter: now + 604800n },
        [],
        cs,
      );
      const keyPackage = base64(encodeMlsMessage({ version: 'mls10', wireformat: 'mls_key_package', keyPackage: pair.publicPackage }));
      return { deviceId, userId: users[index % users.length], pair, keyPackage };
    }));
    const channelId = randomUUID();
    const groupId = mlsGroupId(channelId, 3);
    const [creator, ...others] = devices;
    const group = await createGroup(encoder.encode(groupId), creator.pair.publicPackage, creator.pair.privatePackage, [], cs);
    const result = await createCommit({ state: group, cipherSuite: cs }, {
      wireAsPublicMessage: true,
      ratchetTreeExtension: true,
      extraProposals: others.map((device) => ({ proposalType: 'add' as const, add: { keyPackage: device.pair.publicPackage } })),
    });
    assert.ok(result.welcome);
    const commit: MlsGroupCommit = {
      channelId,
      version: 3,
      previousVersion: 2,
      previousTranscript: 'a'.repeat(64),
      groupId,
      epoch: 1,
      kind: 'create',
      keyCommitment: 'b'.repeat(43),
      commit: base64(encodeMlsMessage(result.commit)),
      welcome: base64(encodeMlsMessage({ version: 'mls10', wireformat: 'mls_welcome', welcome: result.welcome })),
      added: devices.map((device) => ({
        deviceId: device.deviceId,
        userId: device.userId,
        identityKey: sharedIdentityKey,
        packageId: randomUUID(),
        keyPackage: device.keyPackage,
        signature: fakeSignature(),
      })),
      removed: [],
      members: devices.map((device, leafIndex) => ({ deviceId: device.deviceId, userId: device.userId, leafIndex })),
      directoryHeads: [...users].sort().map((userId) => ({ userId, sequence: 1, hash: 'c'.repeat(64) })),
      committerDeviceId: creator.deviceId,
      signature: fakeSignature(),
    };

    for (const body of [{ commit }, { commit, freshStartSignature: fakeSignature() }]) {
      assert.ok(Buffer.byteLength(JSON.stringify(body)) <= MLS_EPOCH_BODY_BYTES);
    }
    assert.equal(mlsGroupCommitRequest.safeParse({ commit }).success, true);
    assert.equal(mlsGroupFreshStartRequest.safeParse({ commit, freshStartSignature: fakeSignature() }).success, true);
    assert.equal(mlsGroupCommitRequest.safeParse({ commit, freshStartSignature: fakeSignature() }).success, false);
    // The server reads the full-size envelope without group secrets.
    const keys = await Promise.all(commit.added.map((entry) => readMemberPackage(entry.keyPackage, entry.deviceId)));
    assertCommitStructure(commit, await decodeGroupCommit(commit.commit), decodeGroupWelcome(commit.welcome), keys);
  });
});
