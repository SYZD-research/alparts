import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { serializeMlsEpoch, type MlsEpoch } from '@alparts/shared';

vi.mock('./api', () => ({ api: { securityRequest: vi.fn() } }));
vi.mock('./crypto.service', () => ({
  getActiveDevice: () => ({ userId: 'account', deviceId: 'device' }),
  signDevicePayload: vi.fn(),
  verifyDevicePayload: vi.fn(),
}));
vi.mock('./directory.service', () => ({
  verifiedDirectory: vi.fn(),
  verifyDirectoryDevices: vi.fn(),
}));
vi.mock('./mls-crypto', () => ({
  decodePublicPackage: () => ({
    leafNode: { credential: { credentialType: 'basic', identity: new TextEncoder().encode('device') } },
  }),
  joinEpochGroup: vi.fn(),
}));
vi.mock('./security-storage', async (original) => ({
  ...(await original<typeof import('./security-storage')>()),
  readSecurityState: vi.fn(),
  writeSecurityState: vi.fn(),
  deleteSecurityState: vi.fn(),
  listSecurityStateNames: vi.fn(),
}));
import { api } from './api';
import { channelKeyScopes } from './channel-key-scope';
import { verifyDevicePayload } from './crypto.service';
import { emptyDirectory } from './directory-verifier';
import { verifiedDirectory } from './directory.service';
import { joinEpochGroup } from './mls-crypto';
import {
  deleteSecurityState,
  listSecurityStateNames,
  readSecurityState,
  sha256,
  toBase64,
  writeSecurityState,
} from './security-storage';
import { deriveMlsDelivery, lowestMlsVersion, mlsHeadVersion, nonMlsDeliveryAllowed } from './mls.service';

const channel = '11111111-1111-4111-8111-111111111111';
const transcript = 'a'.repeat(64);
const raw = new Uint8Array(32).fill(42);
const records = new Map<string, unknown>();
const epochs = new Map<number, { envelope: MlsEpoch; transcript: string; status: string }>();
/** This device's records: the pinned head and the keys it derived for `versions`. */
function local(pinned: { version: number; transcript: string; minVersion?: number } | null, versions = [2]) {
  records.clear();
  if (pinned) records.set(`mls-head:${channel}`, pinned);
  for (const version of versions) records.set(`mls-key:${channel}:${version}`, { raw: toBase64(raw), transcript });
}
/** A verified epoch the server serves, with this device's package for it. */
async function serverEpoch(version: number, previous: { version: number; transcript: string }, status: string) {
  const envelope: MlsEpoch = {
    channelId: channel,
    version,
    previousVersion: previous.version,
    previousTranscript: previous.transcript,
    keyCommitment: 'commitment',
    welcome: 'welcome',
    commit: 'commit',
    roster: [{
      deviceId: 'device',
      userId: 'account',
      identityKey: 'identity',
      packageId: `package-${version}`,
      keyPackage: `key-package-${version}`,
      signature: 'signature',
    }],
    directoryHeads: [{ userId: 'account', sequence: 1, hash: 'hash' }],
    distributorDeviceId: 'device',
    signature: 'signature',
  };
  const epoch = { envelope, transcript: await sha256(serializeMlsEpoch(envelope)), status };
  epochs.set(version, epoch);
  records.set(`mls-package:${channel}:${version}`, {
    packageId: `package-${version}`,
    material: { publicPackage: `key-package-${version}` },
    createdAt: 0,
  });
  return epoch;
}
beforeEach(() => {
  vi.stubGlobal('navigator', {
    locks: { request: (_name: string, run: () => unknown) => run() },
  });
  epochs.clear();
  vi.mocked(api.securityRequest).mockImplementation(async (path) => {
    const epoch = epochs.get(Number(path.split('/').pop()));
    if (!epoch) throw new Error('network verification required');
    return epoch;
  });
  vi.mocked(verifyDevicePayload).mockResolvedValue(true);
  vi.mocked(verifiedDirectory).mockResolvedValue({
    ...emptyDirectory('account'),
    devices: {
      device: { identityKey: 'identity', approved: true, revoked: false, approvedSequence: 1, revokedSequence: null },
    },
  });
  vi.mocked(joinEpochGroup).mockResolvedValue(raw);
  vi.mocked(readSecurityState).mockImplementation(async (_owner, name) => records.get(name) ?? null);
  vi.mocked(writeSecurityState).mockImplementation(async (_owner, name, value, scope) => {
    if (scope) channelKeyScopes.assertCurrent(scope);
    records.set(name, value);
  });
  vi.mocked(deleteSecurityState).mockImplementation(async (_owner, name) => {
    records.delete(name);
  });
  // In key order, as IndexedDB lists them: version 10 comes before version 9.
  vi.mocked(listSecurityStateNames).mockImplementation(async (_owner, prefix, limit) =>
    [...records.keys()].filter((name) => name.startsWith(prefix)).sort().slice(0, limit),
  );
  channelKeyScopes.reset();
});
afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

describe('authenticated MLS archive and checkpoint reuse', () => {
  it('reuses an already activated exact transcript without refetching immutable proofs', async () => {
    local({ version: 2, transcript });
    expect(await deriveMlsDelivery(channel, 2, transcript, 'active')).toEqual(raw);
    expect(api.securityRequest).not.toHaveBeenCalled();
  });
  it('does not promote a pending local record without verifying its activation', async () => {
    local(null);
    await expect(deriveMlsDelivery(channel, 2, transcript, 'active')).rejects.toThrow(
      'network verification required',
    );
    expect(api.securityRequest).toHaveBeenCalledOnce();
  });
  it('rejects a substituted transcript and an active epoch older than the pinned head', async () => {
    local({ version: 2, transcript });
    await expect(deriveMlsDelivery(channel, 2, 'b'.repeat(64), 'active')).rejects.toThrow(
      'INVALID_MLS_TRANSCRIPT',
    );
    local({ version: 3, transcript: 'c'.repeat(64) });
    await expect(deriveMlsDelivery(channel, 2, transcript, 'active')).rejects.toThrow(
      'INVALID_MLS_TRANSCRIPT',
    );
    expect(api.securityRequest).not.toHaveBeenCalled();
  });
  it('keeps a verified retired archive readable without weakening channel revocation', async () => {
    local({ version: 3, transcript: 'c'.repeat(64) });
    expect(await deriveMlsDelivery(channel, 2, transcript, 'retired')).toEqual(raw);
    channelKeyScopes.invalidate(channel);
    await expect(deriveMlsDelivery(channel, 2, transcript, 'retired')).rejects.toThrow();
  });
});

describe('channels already on MLS (SEC-01)', () => {
  it('refuses a non-MLS key for the pinned version or later, but keeps older history', () => {
    expect(nonMlsDeliveryAllowed(null, 7)).toBe(true);
    expect(nonMlsDeliveryAllowed(5, 4)).toBe(true);
    expect(nonMlsDeliveryAllowed(5, 5)).toBe(false);
    expect(nonMlsDeliveryAllowed(5, 6)).toBe(false);
  });

  it('pins the newest and the lowest version a device verifies, also from retired epochs', async () => {
    local(null, []);
    const first = await serverEpoch(1, { version: 0, transcript: '0'.repeat(64) }, 'active');
    const second = await serverEpoch(2, { version: 1, transcript: first.transcript }, 'pending');
    expect(await deriveMlsDelivery(channel, 1, first.transcript, 'active')).toEqual(raw);
    // A pending epoch moves the head only once its activation is verified.
    expect(await deriveMlsDelivery(channel, 2, second.transcript, 'pending')).toEqual(raw);
    expect(await mlsHeadVersion(channel)).toBe(1);
    second.status = 'active';
    expect(await deriveMlsDelivery(channel, 2, second.transcript, 'active')).toEqual(raw);
    expect(records.get(`mls-head:${channel}`)).toEqual({ version: 2, transcript: second.transcript, lowestVersion: 1 });
    expect(await mlsHeadVersion(channel)).toBe(2);
    expect(nonMlsDeliveryAllowed(await lowestMlsVersion(channel), 1)).toBe(false);

    // A device that first opens the channel after both epochs retired.
    local(null, []);
    await serverEpoch(1, { version: 0, transcript: '0'.repeat(64) }, 'retired');
    await serverEpoch(2, { version: 1, transcript: first.transcript }, 'retired');
    expect(await deriveMlsDelivery(channel, 2, second.transcript, 'retired')).toEqual(raw);
    expect(await deriveMlsDelivery(channel, 1, first.transcript, 'retired')).toEqual(raw);
    expect(records.get(`mls-head:${channel}`)).toEqual({ version: 2, transcript: second.transcript, lowestVersion: 1 });
    expect(nonMlsDeliveryAllowed(await lowestMlsVersion(channel), 1)).toBe(false);
    expect(listSecurityStateNames).not.toHaveBeenCalled();
  });

  it('gives a head saved by an earlier release the lowest version this device derived', async () => {
    // Only the newest version 12 was pinned; 30 is a key of a later group.
    local({ version: 12, transcript }, [9, 10, 12, 30]);
    expect(await mlsHeadVersion(channel)).toBe(12);
    expect(await lowestMlsVersion(channel)).toBe(9);
    expect(records.get(`mls-head:${channel}`)).toEqual({ version: 12, transcript, lowestVersion: 9 });
    expect(nonMlsDeliveryAllowed(await lowestMlsVersion(channel), 9)).toBe(false);
    expect(nonMlsDeliveryAllowed(await lowestMlsVersion(channel), 8)).toBe(true);
    expect(listSecurityStateNames).toHaveBeenCalledOnce();

    // The previous release took its minimum from the head alone.
    local({ version: 5, transcript, minVersion: 4 }, [3, 4, 5]);
    expect(await lowestMlsVersion(channel)).toBe(3);
    expect(records.get(`mls-head:${channel}`)).toEqual({ version: 5, transcript, lowestVersion: 3 });

    local({ version: 4, transcript }, [6]);
    expect(await lowestMlsVersion(channel)).toBe(4);
  });

  it('completes such a head on a cached read of retired history and keeps it when the head moves', async () => {
    local({ version: 4, transcript }, [3, 4]);
    expect(await deriveMlsDelivery(channel, 3, transcript, 'retired')).toEqual(raw);
    expect(api.securityRequest).not.toHaveBeenCalled();
    expect(records.get(`mls-head:${channel}`)).toEqual({ version: 4, transcript, lowestVersion: 3 });

    local({ version: 4, transcript }, [3, 4]);
    const next = await serverEpoch(5, { version: 4, transcript }, 'retired');
    expect(await deriveMlsDelivery(channel, 5, next.transcript, 'retired')).toEqual(raw);
    expect(records.get(`mls-head:${channel}`)).toEqual({ version: 5, transcript: next.transcript, lowestVersion: 3 });
    expect(nonMlsDeliveryAllowed(await lowestMlsVersion(channel), 3)).toBe(false);
  });
});
