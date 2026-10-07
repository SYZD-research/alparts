import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mlsGroupId, type User } from '@alparts/shared';

// Which source each version key may come from (DESIGN §6.4, [sec-7]): keys of
// a continuous group come only from that group or from a backup whose
// commitment agrees with what this device verified; earlier versions keep
// the per-device deliveries. The device session runs on an in-memory key
// store; group sync is stubbed.

const mocks = vi.hoisted(() => ({
  storage: new Map<string, string>(),
  api: {
    getDevices: vi.fn(),
    getDeviceChallenge: vi.fn(),
    registerDevice: vi.fn(),
    getKeyRecipients: vi.fn(),
    getChannelKeys: vi.fn(),
    getChannelDeviceDirectory: vi.fn(),
  },
  verifiedDirectory: vi.fn(),
}));

vi.mock('./api', async (importOriginal) => ({
  ...await importOriginal<typeof import('./api')>(),
  api: mocks.api,
}));

vi.mock('./directory.service', () => ({
  verifiedDirectory: mocks.verifiedDirectory,
  cachedDirectory: vi.fn(async () => null),
}));

vi.mock('./desktop.service', () => ({
  getDesktopBridge: () => null,
  getDesktopSecret: vi.fn(),
  setDesktopSecret: vi.fn(),
  deleteDesktopSecret: vi.fn(),
}));

vi.mock('./mls-group.service', () => ({
  cancelGroupMaintenance: vi.fn(),
  createChannelGroupVersion: vi.fn(),
  ensureChannelGroupKey: vi.fn(),
  localGroupView: vi.fn(),
  syncChannelGroup: vi.fn(),
}));

vi.mock('./security-storage', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./security-storage')>();
  const id = (owner: { userId: string; deviceId: string }, name: string) => `${owner.userId}:${owner.deviceId}:${name}`;
  return {
    ...actual,
    readSecurityState: async (owner: { userId: string; deviceId: string }, name: string) => {
      const value = mocks.storage.get(id(owner, name));
      return value === undefined ? null : JSON.parse(value);
    },
    writeSecurityState: async (owner: { userId: string; deviceId: string }, name: string, value: unknown) => {
      mocks.storage.set(id(owner, name), JSON.stringify(value));
    },
    deleteSecurityState: async (owner: { userId: string; deviceId: string }, name: string) => {
      mocks.storage.delete(id(owner, name));
    },
  };
});

import type { ChannelKeyRecipientState } from './api';
import { channelKeyScopes } from './channel-key-scope';
import {
  clearActiveDevice,
  ensureDeviceSession,
  exportHistoryKey,
  getActiveDevice,
  getChannelKeysForVersions,
  saveRecoveredChannelKey,
} from './crypto.service';
import { localGroupView, syncChannelGroup } from './mls-group.service';
import { toBase64 } from './security-storage';

const userId = '11111111-1111-4111-8111-111111111111';
const deviceId = '22222222-2222-4222-8222-222222222222';
const channelId = '33333333-3333-4333-8333-333333333333';

/** The few IndexedDB calls the device key store makes, in memory. */
function memoryIndexedDb() {
  const data = new Map<IDBValidKey, unknown>();
  const later = (run: () => void) => setTimeout(run, 0);
  const request = <T>(result: T) => {
    const pending: { result: T; onsuccess: (() => void) | null; onerror: (() => void) | null } = {
      result,
      onsuccess: null,
      onerror: null,
    };
    later(() => pending.onsuccess?.());
    return pending;
  };
  const store = {
    put: (value: unknown, key: IDBValidKey) => { data.set(key, value); },
    delete: (key: IDBValidKey) => { data.delete(key); },
    get: (key: IDBValidKey) => request(data.get(key)),
    openCursor: () => request(null),
  };
  const database = {
    createObjectStore: () => store,
    transaction: () => {
      const tx = { objectStore: () => store, oncomplete: null as (() => void) | null, onerror: null, onabort: null };
      later(() => tx.oncomplete?.());
      return tx;
    },
    close: () => undefined,
  };
  return {
    open: () => {
      const opening = {
        result: database,
        transaction: { objectStore: () => store },
        onupgradeneeded: null as ((event: { oldVersion: number }) => void) | null,
        onsuccess: null as (() => void) | null,
        onerror: null,
      };
      later(() => {
        opening.onupgradeneeded?.({ oldVersion: 0 });
        opening.onsuccess?.();
      });
      return opening;
    },
  };
}

function put(name: string, value: unknown) {
  mocks.storage.set(`${userId}:${deviceId}:${name}`, JSON.stringify(value));
}

function stored(name: string): unknown {
  const value = mocks.storage.get(`${userId}:${deviceId}:${name}`);
  return value === undefined ? null : JSON.parse(value);
}

const key = (fill: number) => new Uint8Array(32).fill(fill);

async function commitmentOf(raw: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', raw as Uint8Array<ArrayBuffer>));
  return toBase64(digest).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sameKey(candidate: CryptoKey | null | undefined, raw: Uint8Array): Promise<boolean> {
  if (!candidate) return false;
  const iv = new Uint8Array(12);
  const sealed = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, candidate, new Uint8Array([1, 2, 3]));
  const expected = await crypto.subtle.importKey('raw', raw as Uint8Array<ArrayBuffer>, 'AES-GCM', false, ['decrypt']);
  try {
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, expected, sealed);
    return true;
  } catch {
    return false;
  }
}

function serverState(change: Partial<ChannelKeyRecipientState> = {}): ChannelKeyRecipientState {
  return {
    protocolVersion: 4,
    pendingProtocolVersion: null,
    currentVersion: 8,
    keyCommitment: 'c'.repeat(43),
    pendingVersion: null,
    pendingKeyCommitment: null,
    pendingInvalid: false,
    nextVersion: 9,
    rotationRequired: false,
    historyRecoveryRequired: false,
    canRotate: true,
    canAbortPending: false,
    distributedDeviceIds: [],
    pendingAcknowledgedDeviceIds: [],
    pendingRequiredDeviceIds: [],
    recipients: [{ deviceId, userId, identityKey: '{}' }],
    group: {
      genesisVersion: 6,
      groupId: mlsGroupId(channelId, 6),
      epoch: 3,
      transcript: 'a'.repeat(64),
      members: [{ deviceId: '44444444-4444-4444-8444-444444444444', userId, leafIndex: 0 }],
    },
    ownMembership: null,
    pendingAddDeviceIds: [deviceId],
    requiredRemoveDeviceIds: [],
    updateRequired: false,
    ownLeafRefreshDue: false,
    canCommit: false,
    canCreate: false,
    genesisWaiting: [],
    ...change,
  };
}

beforeAll(async () => {
  vi.stubGlobal('indexedDB', memoryIndexedDb());
  vi.stubGlobal('navigator', {
    platform: 'test',
    locks: { request: (_name: string, run: () => unknown) => run() },
  });
  let registered = '';
  mocks.api.getDevices.mockResolvedValue([]);
  mocks.api.getDeviceChallenge.mockResolvedValue({ challenge: 'challenge' });
  mocks.api.registerDevice.mockImplementation(async (_name: string, identityKey: string) => {
    registered = identityKey;
    return { id: deviceId, identityKey, approvedAt: '2026-10-01T00:00:00.000Z' };
  });
  mocks.verifiedDirectory.mockImplementation(async () => ({
    devices: { [deviceId]: { identityKey: registered, approved: true, revoked: false } },
  }));
  await ensureDeviceSession({ id: userId } as User);
  expect(getActiveDevice().deviceId).toBe(deviceId);
}, 60_000);

afterAll(() => {
  clearActiveDevice();
  vi.unstubAllGlobals();
});

beforeEach(() => {
  mocks.storage.clear();
  channelKeyScopes.restore(channelId);
  mocks.api.getKeyRecipients.mockReset();
  mocks.api.getChannelKeys.mockReset().mockResolvedValue([]);
  vi.mocked(localGroupView).mockReset();
  vi.mocked(syncChannelGroup).mockReset().mockResolvedValue({ status: 'ready', version: 8 });
});

afterEach(() => {
  vi.mocked(localGroupView).mockReset();
});

describe('version keys of continuous groups', () => {
  it('takes them only from the group or a verified backup, and earlier versions from deliveries', async () => {
    vi.mocked(localGroupView).mockResolvedValue({ version: 7, v4Start: 5 });
    put(`mls-head:${channelId}`, { version: 4, transcript: 'a'.repeat(64) });
    put(`mls-key:${channelId}:6`, { raw: toBase64(key(6)), transcript: 'b'.repeat(64) });
    // Never verified here: the account's own backup is used as it is.
    put(`recovered:${channelId}:5`, { raw: toBase64(key(5)) });
    // Verified here as another key: the backup is refused.
    put(`recovered:${channelId}:7`, { raw: toBase64(key(7)) });
    put(`key-commitment:${channelId}:7`, await commitmentOf(key(70)));

    const keys = await getChannelKeysForVersions(channelId, [3, 4, 5, 6, 7]);
    expect(mocks.api.getChannelKeys).toHaveBeenCalledOnce();
    expect(mocks.api.getChannelKeys).toHaveBeenCalledWith(channelId, [3, 4], undefined);
    expect(mocks.api.getKeyRecipients).not.toHaveBeenCalled();
    expect(keys.get(3)).toBeNull();
    expect(keys.get(4)).toBeNull();
    expect(await sameKey(keys.get(5), key(5))).toBe(true);
    expect(await sameKey(keys.get(6), key(6))).toBe(true);
    expect(keys.get(7)).toBeNull();
  });

  it('catches up once for a version not reached yet, and follows the server group start while waiting', async () => {
    vi.mocked(localGroupView).mockResolvedValue({ version: null, v4Start: null });
    mocks.api.getKeyRecipients.mockResolvedValue(serverState());
    const keys = await getChannelKeysForVersions(channelId, [5, 6, 7]);
    // Versions of the server's group never come from a delivery on a waiting device.
    expect(mocks.api.getChannelKeys).toHaveBeenCalledWith(channelId, [5], undefined);
    expect(syncChannelGroup).not.toHaveBeenCalled();
    expect(keys.get(6)).toBeNull();
    expect(keys.get(7)).toBeNull();

    // A member catches its group up first.
    mocks.api.getKeyRecipients.mockResolvedValue(serverState({
      ownMembership: { joinedVersion: 6, leafIndex: 0, rejoinRequested: false },
      pendingAddDeviceIds: [],
    }));
    vi.mocked(localGroupView).mockResolvedValue({ version: 7, v4Start: 6 });
    put(`mls-key:${channelId}:8`, { raw: toBase64(key(8)), transcript: 'b'.repeat(64) });
    const caughtUp = await getChannelKeysForVersions(channelId, [8]);
    expect(syncChannelGroup).toHaveBeenCalledOnce();
    expect(await sameKey(caughtUp.get(8), key(8))).toBe(true);

    // Contradicting verified history stays visible; anything else does not stop reading.
    vi.mocked(syncChannelGroup).mockRejectedValueOnce(new Error('INVALID_MLS_TRANSCRIPT'));
    await expect(getChannelKeysForVersions(channelId, [9])).rejects.toThrow('INVALID_MLS_TRANSCRIPT');
    vi.mocked(syncChannelGroup).mockRejectedValueOnce(new Error('temporary'));
    expect((await getChannelKeysForVersions(channelId, [9])).get(9)).toBeNull();
  });

  it('never lets a restored key replace one this device derived or verified', async () => {
    put(`mls-key:${channelId}:6`, { raw: toBase64(key(6)), transcript: 'b'.repeat(64) });
    put(`key-commitment:${channelId}:6`, await commitmentOf(key(6)));
    await saveRecoveredChannelKey(channelId, 6, key(66));
    expect(stored(`recovered:${channelId}:6`)).toBeNull();
    vi.mocked(localGroupView).mockResolvedValue({ version: 6, v4Start: 5 });
    expect(await sameKey((await getChannelKeysForVersions(channelId, [6])).get(6), key(6))).toBe(true);

    put(`key-commitment:${channelId}:8`, await commitmentOf(key(8)));
    await saveRecoveredChannelKey(channelId, 8, key(88));
    expect(stored(`recovered:${channelId}:8`)).toBeNull();
    await saveRecoveredChannelKey(channelId, 8, key(8));
    expect(stored(`recovered:${channelId}:8`)).toEqual({ raw: toBase64(key(8)) });
    await saveRecoveredChannelKey(channelId, 9, key(9));
    expect(stored(`recovered:${channelId}:9`)).toEqual({ raw: toBase64(key(9)) });
  });

  it('backs up only keys checked against a signed envelope from the first group on', async () => {
    // A waiting device: the server's group decides, and no delivery is backed up for it.
    vi.mocked(localGroupView).mockResolvedValue({ version: null, v4Start: null });
    mocks.api.getKeyRecipients.mockResolvedValue(serverState());
    expect(await exportHistoryKey(channelId, 6)).toBeNull();
    expect(mocks.api.getChannelKeys).not.toHaveBeenCalled();
    expect(await exportHistoryKey(channelId, 5)).toBeNull();
    expect(mocks.api.getChannelKeys).toHaveBeenCalledWith(channelId, [5]);

    vi.mocked(localGroupView).mockResolvedValue({ version: 9, v4Start: 6 });
    put(`mls-key:${channelId}:6`, { raw: toBase64(key(6)), transcript: 'b'.repeat(64) });
    put(`key-commitment:${channelId}:6`, await commitmentOf(key(6)));
    put(`mls-key:${channelId}:7`, { raw: toBase64(key(7)), transcript: 'b'.repeat(64) });
    put(`recovered:${channelId}:8`, { raw: toBase64(key(8)) });
    put(`key-commitment:${channelId}:8`, await commitmentOf(key(80)));
    put(`recovered:${channelId}:9`, { raw: toBase64(key(9)) });
    put(`key-commitment:${channelId}:9`, await commitmentOf(key(9)));
    expect(await exportHistoryKey(channelId, 6)).toEqual(key(6));
    expect(await exportHistoryKey(channelId, 7)).toBeNull();
    expect(await exportHistoryKey(channelId, 8)).toBeNull();
    expect(await exportHistoryKey(channelId, 9)).toEqual(key(9));
    expect(mocks.api.getChannelKeys).toHaveBeenCalledOnce();
  });
});
