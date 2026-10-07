import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  mlsGroupId,
  serializeGroupKeyPackage,
  serializeMlsEpoch,
  serializeMlsGroupCommit,
  serializeMlsMemberPackage,
  type DirectoryHead,
  type GroupKeyPackage,
  type MlsEpoch,
  type MlsGroupCommit,
  type MlsMemberPackage,
} from '@alparts/shared';

// Simulated devices against an in-memory server that orders group commits
// like the real one (version compare-and-swap, membership-scoped reads).
// Each device keeps its own encrypted-storage records; every sync reloads
// the group from them, so state round trips are exercised throughout.

interface TestDevice {
  name: string;
  userId: string;
  deviceId: string;
  identityKey: string;
  privateKey: CryptoKey;
}

const env = vi.hoisted(() => ({
  current: null as null | { userId: string; deviceId: string; privateKey: CryptoKey },
  storage: new Map<string, string>(),
  /** Keys handed to storeGroupVersionKey: device -> channel:version -> base64. */
  keys: new Map<string, Map<string, string>>(),
  /** Order of persisted records per device, to check key-before-group. */
  writes: [] as string[],
  server: null as unknown as Record<string, (...args: never[]) => unknown>,
  directory: null as unknown as (userId: string, expected?: { userId: string; sequence: number; hash: string }) => unknown,
  cached: null as unknown as (userId: string) => unknown,
}));

vi.mock('./api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./api')>();
  return {
    ...actual,
    api: new Proxy({}, {
      get: (_target, property: string) => (...args: never[]) => env.server[property](...args),
    }),
  };
});

vi.mock('./crypto.service', () => {
  const b64 = (bytes: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
  return {
    getActiveDevice: () => {
      if (!env.current) throw new Error('Security device is not initialized');
      return { userId: env.current.userId, deviceId: env.current.deviceId, approved: true };
    },
    signDevicePayload: async (payload: string) => b64(await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      env.current!.privateKey,
      new TextEncoder().encode(payload),
    )),
    verifyDevicePayload: async (payload: string, signature: string, identityKey: string) => {
      try {
        const key = await crypto.subtle.importKey(
          'jwk',
          (JSON.parse(identityKey) as { signingKey: JsonWebKey }).signingKey,
          { name: 'ECDSA', namedCurve: 'P-256' },
          false,
          ['verify'],
        );
        return await crypto.subtle.verify(
          { name: 'ECDSA', hash: 'SHA-256' },
          key,
          Uint8Array.from(atob(signature), (c) => c.charCodeAt(0)),
          new TextEncoder().encode(payload),
        );
      } catch {
        return false;
      }
    },
    storeGroupVersionKey: async (channelId: string, version: number, raw: Uint8Array) => {
      const device = env.current!.deviceId;
      const keys = env.keys.get(device) ?? new Map<string, string>();
      keys.set(`${channelId}:${version}`, btoa(String.fromCharCode(...raw)));
      env.keys.set(device, keys);
      env.writes.push(`${device}:key:${version}`);
    },
  };
});

vi.mock('./directory.service', () => ({
  verifiedDirectory: async (userId: string, _channelId?: string, expected?: { userId: string; sequence: number; hash: string }) => env.directory(userId, expected),
  cachedDirectory: async (userId: string) => env.cached(userId),
}));

// Pass-through, so a test can make ts-mls refuse one call.
vi.mock('./mls-crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./mls-crypto')>();
  return {
    ...actual,
    commitChannelGroup: vi.fn(actual.commitChannelGroup),
    createChannelGroup: vi.fn(actual.createChannelGroup),
  };
});

vi.mock('./security-storage', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./security-storage')>();
  const { channelKeyScopes } = await import('./channel-key-scope');
  const id = (owner: { userId: string; deviceId: string }, name: string) => `${owner.userId}:${owner.deviceId}:${name}`;
  return {
    ...actual,
    readSecurityState: async (owner: { userId: string; deviceId: string }, name: string) => {
      const value = env.storage.get(id(owner, name));
      return value === undefined ? null : JSON.parse(value);
    },
    writeSecurityState: async (
      owner: { userId: string; deviceId: string },
      name: string,
      value: unknown,
      scope?: Parameters<typeof channelKeyScopes.assertCurrent>[0],
    ) => {
      if (scope) channelKeyScopes.assertCurrent(scope);
      env.storage.set(id(owner, name), JSON.stringify(value));
      const kind = name.split(':')[0];
      if (kind === 'mls-group' || kind === 'mls-chain') {
        env.writes.push(`${owner.deviceId}:${kind}:${(value as { version: number }).version}`);
      }
    },
    deleteSecurityState: async (owner: { userId: string; deviceId: string }, name: string) => {
      env.storage.delete(id(owner, name));
    },
    listSecurityStateNames: async (owner: { userId: string; deviceId: string }, prefix: string, limit: number) => {
      const start = id(owner, prefix);
      return [...env.storage.keys()]
        .filter((key) => key.startsWith(start))
        .slice(0, limit)
        .map((key) => key.slice(id(owner, '').length));
    },
  };
});

import { decodeMlsMessage, encodeMlsMessage } from 'ts-mls';
import { ApiConnectionError, ApiError, type ChannelKeyRecipientState, type MlsGroupCommitRecord } from './api';
import { channelKeyScopes } from './channel-key-scope';
import { channelKeyWait } from './channel-key-wait';
import { signDevicePayload } from './crypto.service';
import {
  commitChannelGroup,
  createChannelGroup,
  createEpochGroup,
  generateEpochKeyPackage,
  generateMemberPackage,
  type EpochKeyPackage,
} from './mls-crypto';
import {
  cancelGroupMaintenance,
  ChannelGroupChangedError,
  commitChannelGroupChanges,
  createChannelGroupVersion,
  ensureChannelGroupKey,
  revokedGroupMembers,
  scheduleGroupMaintenance,
  syncChannelGroup,
  type ChannelKeyPurpose,
} from './mls-group.service';
import { computeGroupKeyCommitment, rosterUsers } from './mls-group-model';
import { fromBase64, sha256, toBase64 } from './security-storage';


const channelId = '11111111-1111-4111-8111-111111111111';

// === Server ===

interface MemberRow {
  deviceId: string;
  userId: string;
  leafIndex: number;
  joinedVersion: number;
  removedVersion: number | null;
  pkg: MlsMemberPackage;
}

interface DirectoryState {
  sequence: number;
  checkpoints: Record<number, string>;
  devices: Record<string, {
    identityKey: string;
    approved: boolean;
    revoked: boolean;
    approvedSequence: number | null;
    revokedSequence: number | null;
  }>;
}

class FakeServer {
  devices = new Map<string, TestDevice & { revoked: boolean }>();
  viewers = new Set<string>();
  versions: MlsGroupCommitRecord[] = [];
  genesis: number | null = null;
  members: MemberRow[] = [];
  packages = new Map<string, { packageId: string; keyPackage: string; signature: string; rejoin: boolean }>();
  publishedIds = new Set<string>();
  rejoinRequests = new Set<string>();
  updateRequired = false;
  freshStartAllowed = false;
  directories = new Map<string, DirectoryState>();
  /** Per reading device: views the server presents instead of the stored ones. */
  tamper: ((record: MlsGroupCommitRecord, readerId: string) => MlsGroupCommitRecord) | null = null;
  stateOverride: ((state: ChannelKeyRecipientState) => ChannelKeyRecipientState) | null = null;
  /** A committer that signs something else than it computed. */
  rewrite: ((envelope: MlsGroupCommit) => Promise<MlsGroupCommit>) | null = null;
  dropResponses = 0;
  pendingWork: { needPackage: string[]; needCommit: string[] } = { needPackage: [], needCommit: [] };
  /** The active version of group protocol 3, before a first group exists. */
  legacy: { version: number; transcript: string } | null = null;
  legacyEpochs = new Map<number, { envelope: MlsEpoch; transcript: string; status: string }>();
  genesisWaiting: string[] = [];
  /** Every package sent, in order (also those the fault refused). */
  packagePosts: Array<{ deviceId: string; packageId: string }> = [];
  publishFault: ((deviceId: string) => Error | null) | null = null;
  /** Cached directories per reading device. */
  cache = new Map<string, Map<string, unknown>>();

  private self() {
    const device = this.devices.get(env.current!.deviceId)!;
    return device;
  }

  private conflict(reason: string, status = 409): never {
    throw new ApiError('conflict', status, 'GROUP_STATE_CHANGED', undefined, { reason });
  }

  eligible(): Set<string> {
    return new Set([...this.devices.values()]
      .filter((device) => !device.revoked && this.viewers.has(device.userId))
      .map((device) => device.deviceId));
  }

  current(): MemberRow[] {
    return this.members.filter((member) => member.removedVersion === null).sort((a, b) => a.leafIndex - b.leafIndex);
  }

  latest(): MlsGroupCommitRecord | undefined {
    return this.versions[this.versions.length - 1];
  }

  directoryHead(userId: string): DirectoryHead {
    const state = this.directories.get(userId)!;
    return { userId, sequence: state.sequence, hash: state.checkpoints[state.sequence] };
  }

  directoryEvent(userId: string, deviceId: string, kind: 'approve' | 'revoke') {
    const state = this.directories.get(userId) ?? { sequence: 0, checkpoints: {}, devices: {} };
    state.sequence += 1;
    state.checkpoints[state.sequence] = `${userId.slice(0, 8)}${String(state.sequence).padStart(56, '0')}`;
    const device = this.devices.get(deviceId)!;
    if (kind === 'approve') {
      state.devices[deviceId] = {
        identityKey: device.identityKey,
        approved: true,
        revoked: false,
        approvedSequence: state.sequence,
        revokedSequence: null,
      };
    } else {
      state.devices[deviceId] = { ...state.devices[deviceId], approved: false, revoked: true, revokedSequence: state.sequence };
    }
    this.directories.set(userId, state);
  }

  readDirectory(userId: string, expected?: DirectoryHead) {
    const state = this.directories.get(userId);
    if (!state) throw new Error('DIRECTORY_INVALID');
    if (expected && (expected.sequence > state.sequence || state.checkpoints[expected.sequence] !== expected.hash)) {
      throw new Error('DIRECTORY_INVALID');
    }
    const view = structuredClone({ head: this.directoryHead(userId), devices: state.devices, verificationVersion: 2 });
    const reader = env.current!.deviceId;
    const cache = this.cache.get(reader) ?? new Map<string, unknown>();
    cache.set(userId, view);
    this.cache.set(reader, cache);
    return view;
  }

  async getKeyRecipients(): Promise<ChannelKeyRecipientState> {
    const self = this.self();
    const eligible = this.eligible();
    const latest = this.latest();
    const current = this.current();
    const memberIds = new Set(current.map((member) => member.deviceId));
    const own = current.find((member) => member.deviceId === self.deviceId);
    const usable = Boolean(own && eligible.has(self.deviceId) && !this.rejoinRequests.has(self.deviceId));
    const pendingAddDeviceIds = [...this.packages.entries()]
      .filter(([id, pkg]) => eligible.has(id) && (!memberIds.has(id) || (pkg.rejoin && this.rejoinRequests.has(id))))
      .map(([id]) => id)
      .sort();
    const requiredRemoveDeviceIds = current.filter((member) => !eligible.has(member.deviceId)).map((member) => member.deviceId).sort();
    const currentVersion = latest?.version ?? this.legacy?.version ?? 0;
    const group = this.genesis ? {
      genesisVersion: this.genesis,
      groupId: mlsGroupId(channelId, this.genesis),
      epoch: currentVersion - this.genesis + 1,
      transcript: latest!.transcript,
      members: current.map(({ deviceId, userId, leafIndex }) => ({ deviceId, userId, leafIndex })),
    } : null;
    const state: ChannelKeyRecipientState = {
      protocolVersion: latest || !this.legacy ? 4 : 3,
      pendingProtocolVersion: null,
      currentVersion,
      keyCommitment: latest?.envelope.keyCommitment ?? (this.legacy ? 'L'.repeat(43) : null),
      pendingVersion: null,
      pendingKeyCommitment: null,
      pendingInvalid: false,
      nextVersion: currentVersion + 1,
      rotationRequired: !group || requiredRemoveDeviceIds.length > 0 || this.updateRequired,
      historyRecoveryRequired: Boolean(group && eligible.has(self.deviceId) && !usable && this.freshStartAllowed),
      canRotate: true,
      canAbortPending: false,
      distributedDeviceIds: [],
      pendingAcknowledgedDeviceIds: [],
      pendingRequiredDeviceIds: [],
      recipients: [...eligible].map((id) => {
        const device = this.devices.get(id)!;
        return { deviceId: id, userId: device.userId, identityKey: device.identityKey };
      }),
      group,
      ownMembership: own ? {
        joinedVersion: own.joinedVersion,
        leafIndex: own.leafIndex,
        rejoinRequested: this.rejoinRequests.has(self.deviceId),
      } : null,
      pendingAddDeviceIds,
      requiredRemoveDeviceIds: group ? requiredRemoveDeviceIds : [],
      updateRequired: Boolean(group && this.updateRequired),
      ownLeafRefreshDue: false,
      canCommit: Boolean(group && usable),
      canCreate: !group && eligible.has(self.deviceId),
      genesisWaiting: group ? [] : this.genesisWaiting,
    };
    return this.stateOverride ? this.stateOverride(state) : state;
  }

  async publishMemberPackage(_channelId: string, body: { packageId: string; keyPackage: string; signature: string; rejoin?: boolean }) {
    const self = this.self();
    this.packagePosts.push({ deviceId: self.deviceId, packageId: body.packageId });
    const fault = this.publishFault?.(self.deviceId);
    if (fault) throw fault;
    if (!this.eligible().has(self.deviceId)) this.conflict('DEVICE_APPROVAL_REQUIRED', 403);
    const member = this.current().some((candidate) => candidate.deviceId === self.deviceId);
    if (member && !body.rejoin) this.conflict('ALREADY_MEMBER');
    const existing = this.packages.get(self.deviceId);
    const resent = existing?.packageId === body.packageId && existing.keyPackage === body.keyPackage;
    if (!resent && this.publishedIds.has(body.packageId)) this.conflict('PACKAGE_CONSUMED');
    const rejoin = Boolean(member && body.rejoin);
    if (rejoin && !(resent && existing!.rejoin)) this.rejoinRequests.add(self.deviceId);
    this.packages.set(self.deviceId, { packageId: body.packageId, keyPackage: body.keyPackage, signature: body.signature, rejoin });
    this.publishedIds.add(body.packageId);
    return { success: true as const };
  }

  async getPendingMemberPackages(): Promise<MlsMemberPackage[]> {
    const state = await this.getKeyRecipients();
    return state.pendingAddDeviceIds.map((id) => {
      const device = this.devices.get(id)!;
      const pkg = this.packages.get(id)!;
      return {
        deviceId: id,
        userId: device.userId,
        identityKey: device.identityKey,
        packageId: pkg.packageId,
        keyPackage: pkg.keyPackage,
        signature: pkg.signature,
      };
    });
  }

  private visible(deviceId: string, version: number): boolean {
    return this.members.some((row) => (
      row.deviceId === deviceId
      && row.joinedVersion <= version
      && (row.removedVersion === null || version <= row.removedVersion)
    ));
  }

  async getGroupCommits(_channelId: string, after: number, limit: number): Promise<MlsGroupCommitRecord[]> {
    const self = this.self();
    const result: MlsGroupCommitRecord[] = [];
    for (const record of this.versions.filter((candidate) => candidate.version > after).slice(0, limit)) {
      if (!this.visible(self.deviceId, record.version)) break;
      const copy = structuredClone(record);
      result.push(this.tamper ? this.tamper(copy, self.deviceId) : copy);
    }
    return result;
  }

  async getGroupMembers(_channelId: string, version: number) {
    const self = this.self();
    const rows = this.members.filter((row) => row.joinedVersion <= version && (row.removedVersion === null || version < row.removedVersion));
    if (!rows.some((row) => row.deviceId === self.deviceId)) throw new ApiError('not found', 404, 'NOT_FOUND');
    return rows.sort((a, b) => a.leafIndex - b.leafIndex).map((row) => ({
      ...row.pkg,
      leafIndex: row.leafIndex,
      joinedVersion: row.joinedVersion,
      joinedDirectorySequence: 1,
    }));
  }

  async submitGroupCommit(_channelId: string, envelope: MlsGroupCommit) {
    return this.admit(envelope, false);
  }

  async submitGroupFreshStart(_channelId: string, envelope: MlsGroupCommit) {
    if (!this.freshStartAllowed) this.conflict('KEY_FRESH_START_NOT_REQUIRED');
    return this.admit(envelope, true);
  }

  async getPendingGroupWork() {
    return { ...this.pendingWork, cursor: null };
  }

  async getLegacyEpochTranscript(_channelId: string, version: number) {
    if (this.legacy?.version !== version) throw new ApiError('not found', 404, 'NOT_FOUND');
    return this.legacy.transcript;
  }

  /** Group protocol 3 epochs, as history reads them. */
  async securityRequest(path: string) {
    const version = Number(/\/mls\/epochs\/(\d+)$/.exec(path)?.[1]);
    const epoch = this.legacyEpochs.get(version);
    if (!epoch) throw new ApiError('not found', 404, 'NOT_FOUND');
    return structuredClone(epoch);
  }

  async admit(submitted: MlsGroupCommit, freshStart: boolean) {
    const envelope = this.rewrite ? await this.rewrite(submitted) : submitted;
    const transcript = await sha256(serializeMlsGroupCommit(envelope));
    const existing = this.versions.find((record) => record.version === envelope.version);
    if (existing) {
      if (existing.transcript === transcript) return { version: envelope.version, epoch: envelope.epoch, replay: true as const };
      this.conflict('MLS_CONFLICT');
    }
    const latest = this.latest();
    const latestVersion = latest?.version ?? this.legacy?.version ?? 0;
    if (
      envelope.version !== latestVersion + 1
      || envelope.previousVersion !== latestVersion
      || envelope.previousTranscript !== (latest?.transcript ?? this.legacy?.transcript ?? '0'.repeat(64))
    ) this.conflict('MLS_CONFLICT');
    if (envelope.kind === 'create' && this.genesis && !freshStart) this.conflict('KEY_FRESH_START_REQUIRED', 403);
    const leaf = new Map(envelope.members.map((member) => [member.deviceId, member.leafIndex]));
    if (envelope.kind === 'create') {
      for (const row of this.current()) row.removedVersion = envelope.version;
      this.genesis = envelope.version;
    } else {
      for (const row of this.current()) if (envelope.removed.includes(row.deviceId)) row.removedVersion = envelope.version;
    }
    for (const entry of envelope.added) {
      this.members.push({
        deviceId: entry.deviceId,
        userId: entry.userId,
        leafIndex: leaf.get(entry.deviceId)!,
        joinedVersion: envelope.version,
        removedVersion: null,
        pkg: entry,
      });
      this.packages.delete(entry.deviceId);
      this.rejoinRequests.delete(entry.deviceId);
    }
    if (envelope.kind === 'create' || envelope.removed.length > 0 || envelope.added.length === 0) this.updateRequired = false;
    this.versions.push({ version: envelope.version, transcript, envelope: structuredClone(envelope) });
    if (this.dropResponses > 0) {
      this.dropResponses -= 1;
      throw new ApiConnectionError();
    }
    return { version: envelope.version, epoch: envelope.epoch };
  }
}

let server: FakeServer;
let deviceCounter = 0;

async function newDevice(name: string, userId?: string): Promise<TestDevice> {
  deviceCounter += 1;
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const signingKey = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const suffix = String(deviceCounter).padStart(12, '0');
  const device = {
    name,
    userId: userId ?? `aaaaaaaa-aaaa-4aaa-8aaa-${suffix}`,
    deviceId: `dddddddd-dddd-4ddd-8ddd-${suffix}`,
    identityKey: JSON.stringify({ version: 1, signingKey }),
    privateKey: pair.privateKey,
  };
  server.devices.set(device.deviceId, { ...device, revoked: false });
  server.viewers.add(device.userId);
  server.directoryEvent(device.userId, device.deviceId, 'approve');
  return device;
}

function use(device: TestDevice) {
  env.current = { userId: device.userId, deviceId: device.deviceId, privateKey: device.privateKey };
}

function keyOf(device: TestDevice, version: number): string | undefined {
  return env.keys.get(device.deviceId)?.get(`${channelId}:${version}`);
}

function record<T>(device: TestDevice, name: string): T | null {
  const value = env.storage.get(`${device.userId}:${device.deviceId}:${name}`);
  return value === undefined ? null : JSON.parse(value) as T;
}

function setRecord(device: TestDevice, name: string, value: unknown) {
  env.storage.set(`${device.userId}:${device.deviceId}:${name}`, JSON.stringify(value));
}

function deleteRecord(device: TestDevice, name: string) {
  env.storage.delete(`${device.userId}:${device.deviceId}:${name}`);
}

function postsOf(device: TestDevice): string[] {
  return server.packagePosts.filter((post) => post.deviceId === device.deviceId).map((post) => post.packageId);
}

type EnsureResult =
  | { status: 'ready'; version: number }
  | { status: 'waiting'; rejoining: boolean }
  | { status: 'genesis-waiting' }
  | { status: 'unavailable'; freshStartAvailable: boolean };

/** crypto.service's ensureChannelKey: the real attempt loop, with this device's derived keys. */
async function ensure(device: TestDevice, purpose: ChannelKeyPurpose = 'write'): Promise<EnsureResult> {
  use(device);
  try {
    const { version } = await ensureChannelGroupKey(channelId, channelKeyScopes.capture(channelId), {
      purpose,
      loadKey: async (candidate) => keyOf(device, candidate) ?? null,
    });
    return { status: 'ready', version };
  } catch (error) {
    const wait = channelKeyWait(error);
    if (!wait) throw error;
    if (wait.reason === 'unavailable') return { status: 'unavailable', freshStartAvailable: wait.freshStartAvailable };
    if (wait.reason === 'genesis-waiting') return { status: 'genesis-waiting' };
    return { status: 'waiting', rejoining: wait.reason === 'rejoining' };
  }
}

/** A member adds the devices that wait (the background maintenance step). */
async function addPending(device: TestDevice) {
  use(device);
  const scope = channelKeyScopes.capture(channelId);
  const state = await server.getKeyRecipients();
  expect(await syncChannelGroup(channelId, state, scope)).toMatchObject({ status: 'ready' });
  return commitChannelGroupChanges(channelId, state, scope);
}

async function expectSameKey(devices: TestDevice[], version: number) {
  const keys = devices.map((device) => keyOf(device, version));
  expect(keys[0]).toBeTruthy();
  for (const key of keys) expect(key).toBe(keys[0]);
}

/** Rewrite a stored-looking record the way a lying server would, keeping its transcript consistent. */
async function reTranscribe(record: MlsGroupCommitRecord): Promise<MlsGroupCommitRecord> {
  return { ...record, transcript: await sha256(serializeMlsGroupCommit(record.envelope)) };
}

/** Alice, Bob and Carol in one group at version 2. */
async function threeMembers() {
  const [alice, bob, carol] = [await newDevice('alice'), await newDevice('bob'), await newDevice('carol')];
  await ensure(alice);
  await ensure(bob);
  await ensure(carol);
  await addPending(alice);
  expect(await ensure(bob)).toEqual({ status: 'ready', version: 2 });
  expect(await ensure(carol)).toEqual({ status: 'ready', version: 2 });
  return { alice, bob, carol };
}

/** The committer signs an envelope other than the one it computed. */
async function resign(signer: TestDevice, envelope: MlsGroupCommit, change: Partial<MlsGroupCommit>): Promise<MlsGroupCommit> {
  const { signature: _old, ...rest } = envelope;
  const unsigned = { ...rest, ...change };
  use(signer);
  return { ...unsigned, signature: await signDevicePayload(serializeMlsGroupCommit(unsigned)) };
}

beforeEach(() => {
  vi.stubGlobal('navigator', { locks: { request: (_name: string, run: () => unknown) => run() } });
  vi.spyOn(console, 'warn').mockImplementation(() => undefined);
  env.storage.clear();
  env.keys.clear();
  env.writes.length = 0;
  server = new FakeServer();
  env.server = server as unknown as typeof env.server;
  env.directory = (userId, expected) => server.readDirectory(userId, expected as DirectoryHead | undefined);
  env.cached = (userId) => server.cache.get(env.current!.deviceId)?.get(userId) ?? null;
  channelKeyScopes.reset();
});

afterEach(() => {
  cancelGroupMaintenance();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  env.current = null;
});

describe('continuous channel groups across devices', () => {
  it('creates, adds, removes and refreshes with every member on the same key', async () => {
    const alice = await newDevice('alice');
    const bob = await newDevice('bob');
    const carol = await newDevice('carol');
    expect(await ensure(bob)).toEqual({ status: 'ready', version: 1 });
    // Alone at first, the genesis adds nobody; others publish and wait.
    expect(server.genesis).toBe(1);
    expect(await ensure(alice)).toEqual({ status: 'waiting', rejoining: false });
    expect(await ensure(carol)).toEqual({ status: 'waiting', rejoining: false });
    expect(await addPending(bob)).toEqual({ status: 'committed', version: 2 });
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 2 });
    expect(await ensure(carol)).toEqual({ status: 'ready', version: 2 });
    await expectSameKey([alice, bob, carol], 2);

    // Bob's device is revoked: writes wait for its removal, which any member commits.
    server.devices.get(bob.deviceId)!.revoked = true;
    server.directoryEvent(bob.userId, bob.deviceId, 'revoke');
    expect(await ensure(carol)).toEqual({ status: 'ready', version: 3 });
    expect(server.latest()!.envelope.removed).toEqual([bob.deviceId]);
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 3 });
    await expectSameKey([alice, carol], 3);
    expect(keyOf(bob, 3)).toBeUndefined();

    // A day without a path refresh: the next writer makes an empty commit.
    server.updateRequired = true;
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 4 });
    expect(server.latest()!.envelope).toMatchObject({ added: [], removed: [] });
    expect(await ensure(carol)).toEqual({ status: 'ready', version: 4 });
    await expectSameKey([alice, carol], 4);
    expect(new Set([2, 3, 4].map((version) => keyOf(alice, version))).size).toBe(3);
  });

  it('catches an offline device up through every version and saves each key before its group', async () => {
    const [alice, bob, carol] = [await newDevice('alice'), await newDevice('bob'), await newDevice('carol')];
    await ensure(alice);
    await ensure(bob);
    await ensure(carol);
    await addPending(alice);
    await ensure(bob);
    // Carol joined at 2 and goes offline while three more versions pass.
    await ensure(carol);
    const dave = await newDevice('dave');
    await ensure(dave);
    await addPending(alice);
    server.updateRequired = true;
    await ensure(bob);
    server.updateRequired = true;
    await ensure(alice);
    expect(server.latest()!.version).toBe(5);
    env.writes.length = 0;
    expect(await ensure(carol)).toEqual({ status: 'ready', version: 5 });
    for (const version of [3, 4, 5]) await expectSameKey([alice, carol], version);
    const carolWrites = env.writes.filter((entry) => entry.startsWith(carol.deviceId)).map((entry) => entry.slice(carol.deviceId.length + 1));
    expect(carolWrites).toEqual([
      'key:3', 'mls-group:3', 'mls-chain:3',
      'key:4', 'mls-group:4', 'mls-chain:4',
      'key:5', 'mls-group:5', 'mls-chain:5',
    ]);
  });

  it('adopts its own genesis and commit after the response was lost', async () => {
    const alice = await newDevice('alice');
    const bob = await newDevice('bob');
    use(bob);
    await server.publishMemberPackage(channelId, await bobPackage(bob));
    server.dropResponses = 1;
    use(alice);
    await expect(createChannelGroupVersion(channelId, await server.getKeyRecipients(), channelKeyScopes.capture(channelId)))
      .rejects.toThrow(ApiConnectionError);
    expect(record(alice, `mls-group-pending:${channelId}`)).toMatchObject({ kind: 'create', version: 1 });
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 1 });
    expect(record(alice, `mls-group-pending:${channelId}`)).toBeNull();
    expect(await ensure(bob)).toEqual({ status: 'ready', version: 1 });
    await expectSameKey([alice, bob], 1);

    // A refresh commit whose response is lost: the device cannot process its
    // own path commit, so it adopts the state it saved before sending.
    server.updateRequired = true;
    server.dropResponses = 1;
    use(alice);
    await expect(commitChannelGroupChanges(channelId, await server.getKeyRecipients(), channelKeyScopes.capture(channelId)))
      .rejects.toThrow(ApiConnectionError);
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 2 });
    expect(await ensure(bob)).toEqual({ status: 'ready', version: 2 });
    await expectSameKey([alice, bob], 2);
  });

  it('loses a race, discards its own commit and processes the winner with its unchanged state', async () => {
    const [alice, bob, carol] = [await newDevice('alice'), await newDevice('bob'), await newDevice('carol')];
    await ensure(alice);
    await ensure(bob);
    await ensure(carol);
    await addPending(alice);
    await ensure(bob);
    await ensure(carol);
    // Alice builds a refresh on version 2, but Carol's lands first.
    server.updateRequired = true;
    use(alice);
    const aliceState = await server.getKeyRecipients();
    const original = server.admit.bind(server);
    let first = true;
    (server as unknown as { admit: typeof original }).admit = async (envelope: MlsGroupCommit, fresh: boolean) => {
      if (first && envelope.committerDeviceId === alice.deviceId) {
        first = false;
        use(carol);
        const carolResult = await ensure(carol);
        expect(carolResult).toEqual({ status: 'ready', version: 3 });
        use(alice);
      }
      return original(envelope, fresh);
    };
    expect(await commitChannelGroupChanges(channelId, aliceState, channelKeyScopes.capture(channelId)))
      .toEqual({ status: 'conflict', reason: 'MLS_CONFLICT' });
    expect(record(alice, `mls-group-pending:${channelId}`)).toMatchObject({ version: 3 });
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 3 });
    expect(record(alice, `mls-group-pending:${channelId}`)).toBeNull();
    expect(await ensure(bob)).toEqual({ status: 'ready', version: 3 });
    await expectSameKey([alice, bob, carol], 3);
  });

  it('removes a device and adds another into the same leaf in one commit', async () => {
    const [alice, bob, carol] = [await newDevice('alice'), await newDevice('bob'), await newDevice('carol')];
    await ensure(alice);
    await ensure(bob);
    await ensure(carol);
    await addPending(alice);
    await ensure(bob);
    await ensure(carol);
    const bobLeaf = server.current().find((member) => member.deviceId === bob.deviceId)!.leafIndex;
    const dave = await newDevice('dave');
    expect(await ensure(dave)).toEqual({ status: 'waiting', rejoining: false });
    server.devices.get(bob.deviceId)!.revoked = true;
    server.directoryEvent(bob.userId, bob.deviceId, 'revoke');
    expect(await addPending(carol)).toEqual({ status: 'committed', version: 3 });
    expect(server.latest()!.envelope).toMatchObject({ removed: [bob.deviceId], added: [{ deviceId: dave.deviceId }] });
    expect(server.current().find((member) => member.deviceId === dave.deviceId)!.leafIndex).toBe(bobLeaf);
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 3 });
    expect(await ensure(dave)).toEqual({ status: 'ready', version: 3 });
    await expectSameKey([alice, carol, dave], 3);
  });

  it('rejoins after losing its state, through a commit that removes and re-adds it in its old leaf', async () => {
    const [alice, bob, carol] = [await newDevice('alice'), await newDevice('bob'), await newDevice('carol')];
    await ensure(alice);
    await ensure(bob);
    await ensure(carol);
    await addPending(alice);
    await ensure(bob);
    await ensure(carol);
    const bobLeaf = server.current().find((member) => member.deviceId === bob.deviceId)!.leafIndex;
    // Bob loses its group and its packages (for example a cleared profile).
    for (const name of [`mls-group:${channelId}`, `mls-member-package:${channelId}`]) {
      env.storage.delete(`${bob.userId}:${bob.deviceId}:${name}`);
    }
    expect(await ensure(bob)).toEqual({ status: 'waiting', rejoining: true });
    expect(server.rejoinRequests.has(bob.deviceId)).toBe(true);
    // While it waits, polling neither sends the request again nor counts it again.
    const sent = postsOf(bob).length;
    expect(await ensure(bob)).toEqual({ status: 'waiting', rejoining: true });
    expect(await ensure(bob, 'read')).toEqual({ status: 'waiting', rejoining: true });
    expect(postsOf(bob)).toHaveLength(sent);
    expect(record<unknown[]>(bob, `mls-rejoin:${channelId}`)).toHaveLength(1);
    expect(await addPending(carol)).toEqual({ status: 'committed', version: 3 });
    expect(server.latest()!.envelope).toMatchObject({ removed: [bob.deviceId], added: [{ deviceId: bob.deviceId }] });
    expect(server.current().find((member) => member.deviceId === bob.deviceId)!.leafIndex).toBe(bobLeaf);
    expect(await ensure(bob)).toEqual({ status: 'ready', version: 3 });
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 3 });
    await expectSameKey([alice, bob, carol], 3);
  });

  it('joins at the version that added it even when a member was revoked afterwards', async () => {
    const [alice, bob] = [await newDevice('alice'), await newDevice('bob')];
    await ensure(alice);
    await ensure(bob);
    await addPending(alice);
    await ensure(bob);
    const dave = await newDevice('dave');
    await ensure(dave);
    expect(await addPending(alice)).toEqual({ status: 'committed', version: 3 });
    // Dave stays offline; Bob is revoked and removed at version 4.
    server.devices.get(bob.deviceId)!.revoked = true;
    server.directoryEvent(bob.userId, bob.deviceId, 'revoke');
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 4 });
    expect(await ensure(dave)).toEqual({ status: 'ready', version: 4 });
    await expectSameKey([alice, dave], 3);
    await expectSameKey([alice, dave], 4);
  });

  it('joins the first group another device created at the same time', async () => {
    const [alice, bob] = [await newDevice('alice'), await newDevice('bob')];
    use(alice);
    await server.publishMemberPackage(channelId, await bobPackage(alice));
    const aliceState = await server.getKeyRecipients();
    // Bob creates first and adds Alice's published package.
    expect(await ensure(bob)).toEqual({ status: 'ready', version: 1 });
    expect(server.latest()!.envelope.added.map((entry) => entry.deviceId)).toEqual([bob.deviceId, alice.deviceId]);
    use(alice);
    await expect(createChannelGroupVersion(channelId, aliceState, channelKeyScopes.capture(channelId)))
      .rejects.toThrow(ChannelGroupChangedError);
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 1 });
    await expectSameKey([alice, bob], 1);
  });

  it('follows its removal after losing access, then joins again when it is added back', async () => {
    const [alice, bob] = [await newDevice('alice'), await newDevice('bob')];
    await ensure(alice);
    await ensure(bob);
    await addPending(alice);
    expect(await ensure(bob)).toEqual({ status: 'ready', version: 2 });
    server.viewers.delete(bob.userId);
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 3 });
    expect(server.latest()!.envelope.removed).toEqual([bob.deviceId]);
    server.viewers.add(bob.userId);
    expect(await ensure(bob)).toEqual({ status: 'waiting', rejoining: false });
    expect(record(bob, `mls-group:${channelId}`)).toBeNull();
    expect(record(bob, `mls-chain:${channelId}`)).toMatchObject({ version: 3, left: true });
    expect(await addPending(alice)).toEqual({ status: 'committed', version: 4 });
    expect(await ensure(bob)).toEqual({ status: 'ready', version: 4 });
    expect(keyOf(bob, 3)).toBeUndefined();
    await expectSameKey([alice, bob], 2);
    await expectSameKey([alice, bob], 4);
  });

  it('starts over with a fresh start when every member asks to be added again', async () => {
    const [alice, bob, mallory] = [await newDevice('alice'), await newDevice('bob'), await newDevice('mallory')];
    await ensure(mallory);
    await ensure(alice);
    await ensure(bob);
    await addPending(mallory);
    await ensure(alice);
    await ensure(bob);
    // Mallory signs a commit whose key commitment matches nothing: correctly
    // signed and chained, but unusable. Readers ask to be added again.
    server.rewrite = (envelope) => resign(mallory, envelope, { keyCommitment: 'A'.repeat(43) });
    server.updateRequired = true;
    await ensure(mallory);
    server.rewrite = null;
    expect(await ensure(alice)).toEqual({ status: 'waiting', rejoining: true });
    expect(await ensure(bob)).toEqual({ status: 'waiting', rejoining: true });
    expect(keyOf(alice, 2)).toBeTruthy();
    expect(keyOf(alice, 3)).toBeUndefined();
    expect(record(alice, `mls-group:${channelId}`)).toBeNull();
    // Nobody usable remains to add them: the server allows a fresh start.
    server.freshStartAllowed = true;
    use(alice);
    const state = await server.getKeyRecipients();
    expect(state.historyRecoveryRequired).toBe(true);
    expect(await createChannelGroupVersion(channelId, state, channelKeyScopes.capture(channelId), { freshStart: true })).toBe(4);
    expect(server.latest()!.envelope).toMatchObject({ kind: 'create', added: [{ deviceId: alice.deviceId }, { deviceId: bob.deviceId }] });
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 4 });
    expect(await ensure(bob)).toEqual({ status: 'ready', version: 4 });
    await expectSameKey([alice, bob], 4);
    expect(record(alice, `mls-chain:${channelId}`)).toMatchObject({ version: 4, v4Start: 1 });
  });
});

async function bobPackage(device: TestDevice) {
  const { generateMemberPackage } = await import('./mls-crypto');
  const { serializeMlsMemberPackage } = await import('@alparts/shared');
  const { signDevicePayload } = await import('./crypto.service');
  use(device);
  const material = await generateMemberPackage(device.deviceId);
  const packageId = crypto.randomUUID();
  env.storage.set(`${device.userId}:${device.deviceId}:mls-member-package:${channelId}`, JSON.stringify({
    packages: [{ packageId, material, createdAt: Date.now(), signature: '', rejoin: false }],
  }));
  const signature = await signDevicePayload(serializeMlsMemberPackage(channelId, {
    deviceId: device.deviceId,
    packageId,
    keyPackage: material.publicPackage,
  }));
  const stored = JSON.parse(env.storage.get(`${device.userId}:${device.deviceId}:mls-member-package:${channelId}`)!);
  stored.packages[0].signature = signature;
  env.storage.set(`${device.userId}:${device.deviceId}:mls-member-package:${channelId}`, JSON.stringify(stored));
  return { packageId, keyPackage: material.publicPackage, signature };
}

describe('envelopes that contradict verified history', () => {
  /** Three members after a refresh at version 3. */
  async function refreshedGroup() {
    const members = await threeMembers();
    server.updateRequired = true;
    expect(await ensure(members.alice)).toEqual({ status: 'ready', version: 3 });
    return members;
  }

  async function expectStopped(device: TestDevice, code: string) {
    const before = record<{ version: number }>(device, `mls-group:${channelId}`);
    await expect(ensure(device)).rejects.toThrow(code);
    expect(record<{ version: number }>(device, `mls-group:${channelId}`)).toEqual(before);
    expect(server.rejoinRequests.has(device.deviceId)).toBe(false);
  }

  it('refuses a changed signed field, roster or chain link, stale directory heads and rollbacks', async () => {
    const { alice, bob, carol } = await refreshedGroup();
    const stored = server.versions.find((candidate) => candidate.version === 3)!;

    const signed = structuredClone(stored);
    signed.envelope.keyCommitment = 'B'.repeat(43);
    server.versions[2] = await reTranscribe(signed);
    await expectStopped(bob, 'INVALID_MLS_SIGNATURE');

    const roster = structuredClone(stored);
    roster.envelope.members = [...roster.envelope.members].reverse().map((member, index) => ({ ...member, leafIndex: index }));
    server.versions[2] = await reTranscribe(roster);
    await expectStopped(bob, 'INVALID_MLS_ROSTER');

    const chain = structuredClone(stored);
    chain.envelope.previousTranscript = 'e'.repeat(64);
    server.versions[2] = await reTranscribe(chain);
    await expectStopped(bob, 'INVALID_MLS_TRANSCRIPT');

    const heads = structuredClone(stored);
    heads.envelope.directoryHeads = heads.envelope.directoryHeads.map((head) => ({ ...head, sequence: head.sequence - 1 }));
    server.versions[2] = await reTranscribe(heads);
    await expectStopped(bob, 'DIRECTORY_INVALID');

    server.versions[2] = stored;
    expect(await ensure(bob)).toEqual({ status: 'ready', version: 3 });
    // The server now claims an older current version than Bob verified.
    server.stateOverride = (state) => ({
      ...state,
      currentVersion: 2,
      nextVersion: 3,
      group: state.group && { ...state.group, epoch: 2 },
    });
    await expectStopped(bob, 'INVALID_MLS_TRANSCRIPT');
    server.stateOverride = null;
    // A genesis older than the one this device verified is a rollback too.
    server.stateOverride = (state) => ({ ...state, group: state.group && { ...state.group, genesisVersion: 0 } });
    use(carol);
    await expect(syncChannelGroup(channelId, await server.getKeyRecipients(), channelKeyScopes.capture(channelId)))
      .rejects.toThrow('INVALID_MLS_TRANSCRIPT');
    server.stateOverride = null;
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 3 });
  });

  it('refuses to seal for a member its own directory shows as revoked', async () => {
    const { alice, bob } = await refreshedGroup();
    server.directoryEvent(bob.userId, bob.deviceId, 'revoke');
    use(alice);
    // Alice learns of the revocation from the directory; the server does not list a removal.
    server.readDirectory(bob.userId);
    expect(await revokedGroupMembers(channelId)).toEqual([bob.deviceId]);
    await expect(ensure(alice)).rejects.toThrow('DIRECTORY_INVALID');
    // The server lists the removal but claims Alice may not commit it.
    server.stateOverride = (state) => ({ ...state, requiredRemoveDeviceIds: [bob.deviceId], canCommit: false });
    await expect(ensure(alice)).rejects.toThrow('DIRECTORY_INVALID');
    server.stateOverride = null;
    // Reading needs no key for sealing and goes on.
    expect(await ensure(alice, 'read')).toEqual({ status: 'ready', version: 3 });
  });

  it('never accepts "no change needed" for a removal the same state asks for', async () => {
    const { alice, bob } = await refreshedGroup();
    server.devices.get(bob.deviceId)!.revoked = true;
    server.directoryEvent(bob.userId, bob.deviceId, 'revoke');
    use(alice);
    server.readDirectory(bob.userId);
    const admit = vi.spyOn(server, 'admit').mockRejectedValue(
      new ApiError('conflict', 409, 'GROUP_STATE_CHANGED', undefined, { reason: 'KEY_ROTATION_NOT_REQUIRED' }),
    );
    await expect(ensure(alice)).rejects.toThrow();
    expect(admit).toHaveBeenCalled();
    expect(record<{ members: { deviceId: string }[] }>(alice, `mls-group:${channelId}`)!.members.map((member) => member.deviceId))
      .toContain(bob.deviceId);
    admit.mockRestore();
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 4 });
    expect(server.latest()!.envelope.removed).toEqual([bob.deviceId]);
  });

  it('stops when a server claims there is no group after this device verified one', async () => {
    const { alice } = await threeMembers();
    server.stateOverride = (state) => ({
      ...state,
      group: null,
      ownMembership: null,
      canCommit: false,
      canCreate: true,
      historyRecoveryRequired: false,
      requiredRemoveDeviceIds: [],
    });
    await expect(ensure(alice)).rejects.toThrow('MLS_DOWNGRADE');
    use(alice);
    await expect(createChannelGroupVersion(channelId, await server.getKeyRecipients(), channelKeyScopes.capture(channelId)))
      .rejects.toThrow('MLS_DOWNGRADE');
    expect(postsOf(alice)).toHaveLength(1);
  });

  it('stops when a server shows a membership from before this device was removed', async () => {
    const { alice, bob } = await threeMembers();
    server.viewers.delete(bob.userId);
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 3 });
    expect(await ensure(bob)).toEqual({ status: 'waiting', rejoining: false });
    expect(record(bob, `mls-chain:${channelId}`)).toMatchObject({ version: 3, left: true, genesisVersion: 1 });
    // The server claims Bob is still the member it was at version 2.
    server.stateOverride = (state) => ({
      ...state,
      ownMembership: { joinedVersion: 2, leafIndex: state.group!.members[0].leafIndex, rejoinRequested: false },
    });
    await expect(ensure(bob)).rejects.toThrow('INVALID_MLS_TRANSCRIPT');
  });

  it('stops when a device without a group is shown one that started before its pinned version', async () => {
    const { alice, bob, carol } = await threeMembers();
    // Bob loses its group, asks to be added again, and nobody can: it starts over at version 3.
    deleteRecord(bob, `mls-group:${channelId}`);
    expect(await ensure(bob)).toEqual({ status: 'waiting', rejoining: true });
    server.freshStartAllowed = true;
    use(bob);
    expect(await createChannelGroupVersion(channelId, await server.getKeyRecipients(), channelKeyScopes.capture(channelId), { freshStart: true })).toBe(3);
    server.freshStartAllowed = false;
    // Carol follows its group until the fresh start left it out.
    expect(await ensure(carol)).toEqual({ status: 'waiting', rejoining: false });
    expect(record(carol, `mls-chain:${channelId}`)).toMatchObject({ version: 3, genesisVersion: 3, left: true });
    // A server that shows Carol a continuation of the closed group branches off her history.
    server.stateOverride = (state) => ({
      ...state,
      group: state.group && { ...state.group, genesisVersion: 1, groupId: mlsGroupId(channelId, 1), epoch: state.currentVersion },
    });
    await expect(ensure(carol)).rejects.toThrow('INVALID_MLS_TRANSCRIPT');
    server.stateOverride = null;
    void alice;
  });
});

describe('background maintenance', () => {
  it('publishes a package for channels the server lists', async () => {
    const alice = await newDevice('alice');
    await ensure(alice);
    const bob = await newDevice('bob');
    use(bob);
    server.pendingWork = { needPackage: [channelId], needCommit: [] };
    scheduleGroupMaintenance(0);
    await vi.waitFor(() => expect(server.packages.has(bob.deviceId)).toBe(true));
    use(alice);
    expect((await server.getKeyRecipients()).pendingAddDeviceIds).toEqual([bob.deviceId]);
  });
});

describe('joining and asking to be added again', () => {
  it('asks to be added again when a Welcome holds another tree than the signed roster', async () => {
    const [alice, mallory, carol] = [await newDevice('alice'), await newDevice('mallory'), await newDevice('carol')];
    await ensure(alice);
    await ensure(mallory);
    await ensure(carol);
    await addPending(alice);
    expect(await ensure(mallory)).toEqual({ status: 'ready', version: 2 });
    expect(await ensure(carol)).toEqual({ status: 'ready', version: 2 });
    const dave = await newDevice('dave');
    expect(await ensure(dave)).toEqual({ status: 'waiting', rejoining: false });
    const carolLeaf = server.current().find((member) => member.deviceId === carol.deviceId)!.leafIndex;
    // Mallory sends Dave the Welcome of another commit made from the same
    // state (Carol removed). Nobody but Dave can tell.
    server.rewrite = async (envelope) => {
      const { decodeChannelGroupState, readMemberPackage, treeAuthMap } = await import('./mls-crypto');
      const state = decodeChannelGroupState(record<{ state: string }>(mallory, `mls-group:${channelId}`)!.state);
      const daveEntry = envelope.added.find((entry) => entry.deviceId === dave.deviceId)!;
      const authMap = treeAuthMap(state, [carolLeaf]);
      authMap.set(dave.deviceId, readMemberPackage(daveEntry.keyPackage).signatureKey);
      const other = await commitChannelGroup(state, { add: [daveEntry.keyPackage], removeLeaves: [carolLeaf], authMap });
      return resign(mallory, envelope, { welcome: other.welcome });
    };
    expect(await addPending(mallory)).toEqual({ status: 'committed', version: 3 });
    server.rewrite = null;
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 3 });
    expect(await ensure(carol)).toEqual({ status: 'ready', version: 3 });
    expect(await ensure(dave)).toEqual({ status: 'waiting', rejoining: true });
    expect(server.rejoinRequests.has(dave.deviceId)).toBe(true);
    expect(await addPending(alice)).toEqual({ status: 'committed', version: 4 });
    expect(server.latest()!.envelope).toMatchObject({ removed: [dave.deviceId], added: [{ deviceId: dave.deviceId }] });
    expect(await ensure(dave)).toEqual({ status: 'ready', version: 4 });
    expect(await ensure(carol)).toEqual({ status: 'ready', version: 4 });
    await expectSameKey([alice, carol, dave], 4);
  });

  it('asks to be added again when it cannot open its Welcome', async () => {
    const [alice, mallory] = [await newDevice('alice'), await newDevice('mallory')];
    await ensure(alice);
    await ensure(mallory);
    await addPending(alice);
    expect(await ensure(mallory)).toEqual({ status: 'ready', version: 2 });
    const dave = await newDevice('dave');
    expect(await ensure(dave)).toEqual({ status: 'waiting', rejoining: false });
    server.rewrite = (envelope) => {
      const message = decodeMlsMessage(fromBase64(envelope.welcome), 0)![0];
      if (message.wireformat !== 'mls_welcome') throw new Error('expected a Welcome');
      message.welcome.encryptedGroupInfo[0] ^= 1;
      return resign(mallory, envelope, { welcome: toBase64(encodeMlsMessage(message)) });
    };
    expect(await addPending(mallory)).toEqual({ status: 'committed', version: 3 });
    server.rewrite = null;
    expect(await ensure(dave)).toEqual({ status: 'waiting', rejoining: true });
    expect(await addPending(alice)).toEqual({ status: 'committed', version: 4 });
    expect(await ensure(dave)).toEqual({ status: 'ready', version: 4 });
    await expectSameKey([alice, dave], 4);
  });

  it('asks to be added again after an update whose path it cannot use, and starts over when nobody can add it', async () => {
    const [mallory, alice, bob] = [await newDevice('mallory'), await newDevice('alice'), await newDevice('bob')];
    await ensure(mallory);
    await ensure(alice);
    await ensure(bob);
    await addPending(mallory);
    await ensure(alice);
    await ensure(bob);
    // Mallory changes one byte of an encrypted path secret after making the
    // update and signs the envelope again: ts-mls refuses the commit.
    server.rewrite = (envelope) => {
      const message = decodeMlsMessage(fromBase64(envelope.commit), 0)![0];
      if (message.wireformat !== 'mls_public_message' || message.publicMessage.content.contentType !== 'commit') {
        throw new Error('expected a commit');
      }
      message.publicMessage.content.commit.path!.nodes[0].encryptedPathSecret[0].ciphertext[0] ^= 1;
      return resign(mallory, envelope, { commit: toBase64(encodeMlsMessage(message)) });
    };
    server.updateRequired = true;
    expect(await ensure(mallory)).toEqual({ status: 'ready', version: 3 });
    server.rewrite = null;
    expect(await ensure(alice)).toEqual({ status: 'waiting', rejoining: true });
    expect(await ensure(bob)).toEqual({ status: 'waiting', rejoining: true });
    expect(keyOf(alice, 2)).toBeTruthy();
    server.freshStartAllowed = true;
    use(alice);
    expect(await createChannelGroupVersion(channelId, await server.getKeyRecipients(), channelKeyScopes.capture(channelId), { freshStart: true })).toBe(4);
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 4 });
    expect(await ensure(bob)).toEqual({ status: 'ready', version: 4 });
    await expectSameKey([alice, bob], 4);
  });

  it('stops asking to be added again after three requests a day and says so plainly', async () => {
    const { alice, bob, carol } = await threeMembers();
    for (let round = 0; round < 3; round += 1) {
      deleteRecord(bob, `mls-group:${channelId}`);
      expect(await ensure(bob)).toEqual({ status: 'waiting', rejoining: true });
      expect(await addPending(carol)).toMatchObject({ status: 'committed' });
      expect(await ensure(bob)).toMatchObject({ status: 'ready' });
    }
    expect(record<unknown[]>(bob, `mls-rejoin:${channelId}`)).toHaveLength(3);
    const version = server.latest()!.version;
    deleteRecord(bob, `mls-group:${channelId}`);
    expect(await ensure(bob)).toEqual({ status: 'unavailable', freshStartAvailable: false });
    expect(server.rejoinRequests.has(bob.deviceId)).toBe(false);
    // Keys already derived stay; sending waits. Where the server offers a
    // fresh start, the waiting state says so.
    expect(keyOf(bob, version)).toBeTruthy();
    server.stateOverride = (state) => ({ ...state, historyRecoveryRequired: true });
    expect(await ensure(bob)).toEqual({ status: 'unavailable', freshStartAvailable: true });
    server.stateOverride = null;
    void alice;
  });

  it('counts a request to be added again once, however often sending it failed', async () => {
    const { bob } = await threeMembers();
    deleteRecord(bob, `mls-group:${channelId}`);
    let failures = 3;
    server.publishFault = (deviceId) => (deviceId === bob.deviceId && failures-- > 0 ? new ApiConnectionError() : null);
    for (let attempt = 0; attempt < 3; attempt += 1) await expect(ensure(bob)).rejects.toThrow(ApiConnectionError);
    expect(server.rejoinRequests.has(bob.deviceId)).toBe(false);
    expect(record(bob, `mls-rejoin:${channelId}`)).toBeNull();
    expect(await ensure(bob)).toEqual({ status: 'waiting', rejoining: true });
    expect(server.rejoinRequests.has(bob.deviceId)).toBe(true);
    expect(record<unknown[]>(bob, `mls-rejoin:${channelId}`)).toHaveLength(1);
    // Every attempt sent the one package made for this request.
    expect(new Set(postsOf(bob).slice(-4))).toHaveProperty('size', 1);
  });

  it('waits instead of failing when the server asks to slow down', async () => {
    const alice = await newDevice('alice');
    await ensure(alice);
    const dave = await newDevice('dave');
    server.publishFault = () => new ApiError('slow down', 429, 'RATE_LIMITED');
    expect(await ensure(dave)).toEqual({ status: 'waiting', rejoining: false });
    server.publishFault = null;
    expect(await ensure(dave)).toEqual({ status: 'waiting', rejoining: false });
    expect(server.packages.has(dave.deviceId)).toBe(true);
  });
});

describe('packages', () => {
  it('does not send its package again while the server lists it as waiting', async () => {
    const alice = await newDevice('alice');
    await ensure(alice);
    const dave = await newDevice('dave');
    expect(await ensure(dave)).toEqual({ status: 'waiting', rejoining: false });
    expect(await ensure(dave, 'read')).toEqual({ status: 'waiting', rejoining: false });
    expect(await ensure(dave)).toEqual({ status: 'waiting', rejoining: false });
    expect(postsOf(dave)).toHaveLength(1);
  });

  it('creates a first group with the package the server already lists, without sending it again', async () => {
    const [alice, bob] = [await newDevice('alice'), await newDevice('bob')];
    server.legacy = { version: 3, transcript: 'c'.repeat(64) };
    server.genesisWaiting = [alice.deviceId];
    expect(await ensure(bob)).toEqual({ status: 'genesis-waiting' });
    expect(postsOf(bob)).toHaveLength(1);
    server.genesisWaiting = [];
    expect(await ensure(bob)).toEqual({ status: 'ready', version: 4 });
    expect(postsOf(bob)).toHaveLength(1);
    expect(server.latest()!.envelope).toMatchObject({ previousVersion: 3, previousTranscript: 'c'.repeat(64) });
  });

  it('replaces a package the server reports as used when the channel needs one again', async () => {
    const [alice, bob] = [await newDevice('alice'), await newDevice('bob')];
    await ensure(alice);
    expect(await ensure(bob)).toEqual({ status: 'waiting', rejoining: false });
    const used = server.packages.get(bob.deviceId)!.packageId;
    // Bob is added, then removed after losing access before it ever synced.
    expect(await addPending(alice)).toEqual({ status: 'committed', version: 2 });
    server.viewers.delete(bob.userId);
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 3 });
    server.viewers.add(bob.userId);
    use(bob);
    server.pendingWork = { needPackage: [channelId], needCommit: [] };
    scheduleGroupMaintenance(0);
    await vi.waitFor(() => expect(server.packages.get(bob.deviceId)?.packageId).toBeTruthy());
    expect(server.packages.get(bob.deviceId)!.packageId).not.toBe(used);
  });
});

describe('own envelopes', () => {
  it('adopts its own fresh start after the response was lost, while others catch up through it', async () => {
    const { alice, bob, carol } = await threeMembers();
    // Alice goes offline at version 2; Carol refreshes at 3.
    server.updateRequired = true;
    expect(await ensure(carol)).toEqual({ status: 'ready', version: 3 });
    expect(await ensure(bob)).toEqual({ status: 'ready', version: 3 });
    deleteRecord(bob, `mls-group:${channelId}`);
    expect(await ensure(bob)).toEqual({ status: 'waiting', rejoining: true });
    server.freshStartAllowed = true;
    server.dropResponses = 1;
    use(bob);
    await expect(createChannelGroupVersion(channelId, await server.getKeyRecipients(), channelKeyScopes.capture(channelId), { freshStart: true }))
      .rejects.toThrow(ApiConnectionError);
    expect(record(bob, `mls-group-pending:${channelId}`)).toMatchObject({ kind: 'create', version: 4 });
    expect(await ensure(bob)).toEqual({ status: 'ready', version: 4 });
    expect(record(bob, `mls-group-pending:${channelId}`)).toBeNull();
    server.freshStartAllowed = false;
    // Alice follows her old group up to the fresh start that left her out.
    expect(await ensure(alice)).toEqual({ status: 'waiting', rejoining: false });
    await expectSameKey([alice, carol], 3);
    expect(record(alice, `mls-chain:${channelId}`)).toMatchObject({ version: 4, genesisVersion: 4, left: true });
    expect(await ensure(carol)).toEqual({ status: 'waiting', rejoining: false });
    expect(await addPending(bob)).toEqual({ status: 'committed', version: 5 });
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 5 });
    expect(await ensure(carol)).toEqual({ status: 'ready', version: 5 });
    await expectSameKey([alice, bob, carol], 5);
  });

  it('starts over only when the server lets this device, and asks for nothing otherwise', async () => {
    const { alice } = await threeMembers();
    use(alice);
    const posts = postsOf(alice).length;
    // A usable member's view: no fresh start offered.
    await expect(createChannelGroupVersion(channelId, await server.getKeyRecipients(), channelKeyScopes.capture(channelId), { freshStart: true }))
      .rejects.toThrow(ChannelGroupChangedError);
    expect(postsOf(alice)).toHaveLength(posts);
    expect(server.rejoinRequests.size).toBe(0);
  });

  it('drops its own first group that lost to another one it is not in', async () => {
    const [alice, bob] = [await newDevice('alice'), await newDevice('bob')];
    use(alice);
    const aliceState = await server.getKeyRecipients();
    expect(await ensure(bob)).toEqual({ status: 'ready', version: 1 });
    use(alice);
    await expect(createChannelGroupVersion(channelId, aliceState, channelKeyScopes.capture(channelId)))
      .rejects.toMatchObject({ status: 409 });
    expect(record(alice, `mls-group-pending:${channelId}`)).toMatchObject({ kind: 'create', version: 1 });
    expect(await ensure(alice)).toEqual({ status: 'waiting', rejoining: false });
    expect(record(alice, `mls-group-pending:${channelId}`)).toBeNull();
  });

  it('forgets an own envelope left behind after it was adopted', async () => {
    const { alice } = await threeMembers();
    setRecord(alice, `mls-group-pending:${channelId}`, {
      kind: 'commit', genesisVersion: 1, version: 2, transcript: 'f'.repeat(64), newState: '', raw: '',
    });
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 2 });
    expect(record(alice, `mls-group-pending:${channelId}`)).toBeNull();
  });
});

describe('commits', () => {
  /** A package whose MLS signature is broken: every check here passes, ts-mls refuses it. */
  async function refusedPackage(device: TestDevice) {
    use(device);
    const material = await generateMemberPackage(device.deviceId);
    const message = decodeMlsMessage(fromBase64(material.publicPackage), 0)![0];
    if (message.wireformat !== 'mls_key_package') throw new Error('expected a key package');
    message.keyPackage.signature[0] ^= 1;
    const keyPackage = toBase64(encodeMlsMessage(message));
    const packageId = crypto.randomUUID();
    const signature = await signDevicePayload(serializeMlsMemberPackage(channelId, { deviceId: device.deviceId, packageId, keyPackage }));
    server.packages.set(device.deviceId, { packageId, keyPackage, signature, rejoin: false });
    server.publishedIds.add(packageId);
  }

  it('removes a revoked device even while a package ts-mls refuses waits to be added', async () => {
    const { alice, bob, carol } = await threeMembers();
    const dave = await newDevice('dave');
    await refusedPackage(dave);
    server.devices.get(bob.deviceId)!.revoked = true;
    server.directoryEvent(bob.userId, bob.deviceId, 'revoke');
    expect(await ensure(carol)).toEqual({ status: 'ready', version: 3 });
    expect(server.latest()!.envelope).toMatchObject({ removed: [bob.deviceId], added: [] });
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 3 });
    use(alice);
    expect((await server.getKeyRecipients()).pendingAddDeviceIds).toEqual([dave.deviceId]);
  });

  it('commits a removal without additions when a package runs out of time, and reads on when the list is unavailable', async () => {
    const { alice, bob, carol } = await threeMembers();
    const dave = await newDevice('dave');
    expect(await ensure(dave)).toEqual({ status: 'waiting', rejoining: false });
    server.devices.get(bob.deviceId)!.revoked = true;
    server.directoryEvent(bob.userId, bob.deviceId, 'revoke');
    vi.mocked(commitChannelGroup).mockRejectedValueOnce(new Error('Current time not within Lifetime'));
    expect(await ensure(carol)).toEqual({ status: 'ready', version: 3 });
    expect(server.latest()!.envelope).toMatchObject({ removed: [bob.deviceId], added: [] });
    // The additions follow in the background.
    expect(await addPending(alice)).toEqual({ status: 'committed', version: 4 });
    expect(await ensure(dave)).toEqual({ status: 'ready', version: 4 });
    // A refresh still goes through when the waiting packages cannot be read.
    const eve = await newDevice('eve');
    expect(await ensure(eve)).toEqual({ status: 'waiting', rejoining: false });
    server.updateRequired = true;
    const list = vi.spyOn(server, 'getPendingMemberPackages').mockRejectedValue(new ApiConnectionError());
    expect(await ensure(carol)).toEqual({ status: 'ready', version: 5 });
    list.mockRestore();
    expect(server.latest()!.envelope).toMatchObject({ added: [], removed: [] });
  });

  it('waits for a first group when a package runs out of time while it is made', async () => {
    const [alice, bob] = [await newDevice('alice'), await newDevice('bob')];
    use(bob);
    await server.publishMemberPackage(channelId, await bobPackage(bob));
    vi.mocked(createChannelGroup).mockRejectedValueOnce(new Error('Current time not within Lifetime'));
    expect(await ensure(alice)).toEqual({ status: 'genesis-waiting' });
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 1 });
    expect(await ensure(bob)).toEqual({ status: 'ready', version: 1 });
  });

  it('leaves removals to writers when it only reads', async () => {
    const { alice, bob } = await threeMembers();
    server.devices.get(bob.deviceId)!.revoked = true;
    server.directoryEvent(bob.userId, bob.deviceId, 'revoke');
    expect(await ensure(alice, 'read')).toEqual({ status: 'ready', version: 2 });
    expect(server.latest()!.version).toBe(2);
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 3 });
    expect(server.latest()!.envelope.removed).toEqual([bob.deviceId]);
  });

  it('sends anyway when only its own leaf is old and refreshing it fails', async () => {
    const { alice } = await threeMembers();
    server.stateOverride = (state) => ({ ...state, ownLeafRefreshDue: Boolean(state.ownMembership) && state.currentVersion < 3 });
    const admit = vi.spyOn(server, 'admit').mockRejectedValueOnce(
      new ApiError('conflict', 409, 'GROUP_STATE_CHANGED', undefined, { reason: 'COMMIT_RATE_LIMITED' }),
    ).mockRejectedValueOnce(new ApiConnectionError());
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 2 });
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 2 });
    admit.mockRestore();
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 3 });
    server.stateOverride = null;
  });

  it('never seals for the version of a state another tab already moved past', async () => {
    const { alice, carol } = await threeMembers();
    use(alice);
    const stale = await server.getKeyRecipients();
    server.updateRequired = true;
    expect(await ensure(carol)).toEqual({ status: 'ready', version: 3 });
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 3 });
    // The first read hands out the state from before; the group service reads again.
    let first = true;
    server.stateOverride = (state) => {
      if (!first) return state;
      first = false;
      return stale;
    };
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 3 });
    server.stateOverride = null;
  });
});

describe('history from before continuous groups', () => {
  /** A group protocol 3 epoch made by `distributor` for `members`. */
  async function legacyEpoch(
    distributor: TestDevice,
    members: TestDevice[],
    version: number,
    previous: { version: number; transcript: string },
  ) {
    const roster: GroupKeyPackage[] = [];
    const materials = new Map<string, { packageId: string; material: EpochKeyPackage }>();
    for (const device of members) {
      use(device);
      const material = await generateEpochKeyPackage(device.deviceId);
      const entry = {
        deviceId: device.deviceId,
        userId: device.userId,
        identityKey: device.identityKey,
        packageId: crypto.randomUUID(),
        keyPackage: material.publicPackage,
      };
      roster.push({ ...entry, signature: await signDevicePayload(serializeGroupKeyPackage(channelId, version, entry)) });
      materials.set(device.deviceId, { packageId: entry.packageId, material });
    }
    const groupId = JSON.stringify(['alparts', channelId, version, previous.transcript]);
    use(distributor);
    const created = await createEpochGroup(groupId, materials.get(distributor.deviceId)!.material, roster.map((entry) => entry.keyPackage));
    const unsigned: Omit<MlsEpoch, 'signature'> = {
      channelId,
      version,
      previousVersion: previous.version,
      previousTranscript: previous.transcript,
      keyCommitment: await computeGroupKeyCommitment(created.raw),
      welcome: created.welcome,
      commit: created.commit,
      roster,
      directoryHeads: rosterUsers(members).map((userId) => server.directoryHead(userId)),
      distributorDeviceId: distributor.deviceId,
    };
    const envelope: MlsEpoch = { ...unsigned, signature: await signDevicePayload(serializeMlsEpoch(unsigned)) };
    const transcript = await sha256(serializeMlsEpoch(envelope));
    server.legacyEpochs.set(version, { envelope, transcript, status: 'retired' });
    return { transcript, raw: created.raw, materials };
  }

  it('keeps v3 packages of versions not read yet, so that history stays readable after the first group', async () => {
    const [alice, bob] = [await newDevice('alice'), await newDevice('bob')];
    const pinned = { version: 4, transcript: 'c'.repeat(64) };
    const epoch = await legacyEpoch(alice, [alice, bob], 5, pinned);
    server.legacy = { version: 5, transcript: epoch.transcript };
    // Bob followed the channel up to version 4 and was offline when 5 was made.
    const own = epoch.materials.get(bob.deviceId)!;
    setRecord(bob, `mls-head:${channelId}`, pinned);
    setRecord(bob, `mls-package:${channelId}:5`, { packageId: own.packageId, material: own.material, createdAt: Date.now() });
    // A package and a proposal for a version that never became active.
    setRecord(bob, `mls-package:${channelId}:6`, { packageId: crypto.randomUUID(), material: own.material, createdAt: Date.now() });
    setRecord(bob, `mls-proposal:${channelId}:6`, { raw: toBase64(new Uint8Array(32)), transcript: 'd'.repeat(64) });

    expect(await ensure(alice)).toEqual({ status: 'ready', version: 6 });
    expect(server.latest()!.envelope).toMatchObject({ kind: 'create', previousVersion: 5, previousTranscript: epoch.transcript });
    expect(await ensure(bob)).toEqual({ status: 'waiting', rejoining: false });
    expect(record(bob, `mls-package:${channelId}:5`)).not.toBeNull();
    expect(record(bob, `mls-package:${channelId}:6`)).toBeNull();
    expect(record(bob, `mls-proposal:${channelId}:6`)).toBeNull();

    use(bob);
    const { deriveMlsDelivery } = await import('./mls.service');
    expect(await deriveMlsDelivery(channelId, 5, epoch.transcript, 'retired')).toEqual(epoch.raw);
  });

  it('links the first group to the newest v3 version verified here, also one read late', async () => {
    const alice = await newDevice('alice');
    setRecord(alice, `mls-head:${channelId}`, { version: 4, transcript: 'c'.repeat(64) });
    server.legacy = { version: 5, transcript: 'e'.repeat(64) };
    server.genesisWaiting = ['bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'];
    expect(await ensure(alice)).toEqual({ status: 'genesis-waiting' });
    expect(record(alice, `mls-chain:${channelId}`)).toMatchObject({ version: 4, v4Start: null });
    // Version 5 is read later, so the pin moves; the server then names another transcript for it.
    setRecord(alice, `mls-head:${channelId}`, { version: 5, transcript: 'f'.repeat(64) });
    server.genesisWaiting = [];
    await expect(ensure(alice)).rejects.toThrow('INVALID_MLS_TRANSCRIPT');
    expect(server.genesis).toBeNull();
    server.legacy = { version: 5, transcript: 'f'.repeat(64) };
    expect(await ensure(alice)).toEqual({ status: 'ready', version: 6 });
    expect(server.latest()!.envelope).toMatchObject({ previousVersion: 5, previousTranscript: 'f'.repeat(64) });
    expect(record(alice, `mls-chain:${channelId}`)).toMatchObject({ version: 6, v4Start: 6, genesisVersion: 6 });
  });
});
