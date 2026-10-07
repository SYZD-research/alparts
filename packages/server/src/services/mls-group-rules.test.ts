import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  acceptAll,
  createCommit,
  createGroup,
  decodeMlsMessage,
  encodeMlsMessage,
  generateKeyPackage,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
  joinGroup,
  makePskIndex,
  emptyPskIndex,
  processMessage,
  type ClientState,
  type KeyPackage,
  type MlsPublicMessage,
  type PrivateKeyPackage,
  type Proposal,
} from 'ts-mls';
import { defaultClientConfig } from 'ts-mls/clientConfig.js';
import { signKeyPackage } from 'ts-mls/keyPackage.js';
import { signLeafNodeCommit, signLeafNodeKeyPackage } from 'ts-mls/leafNode.js';
import {
  MLS_CIPHERSUITE,
  mlsGroupId,
  type DirectoryHead,
  type MlsGroupCommit,
  type MlsGroupMember,
} from '@alparts/shared';
import {
  decodeGroupCommit,
  decodeGroupWelcome,
  readMemberPackage,
  storedPackageInitKey,
  type DecodedGroupCommit,
  type MemberPackageKeys,
} from '../security/mls-group-commit.js';
import {
  COMMIT_RATE_LIMIT,
  EMPTY_TRANSCRIPT,
  GENESIS_WAIT_MS,
  LEAF_REFRESH_INTERVAL_MS,
  PATH_REFRESH_INTERVAL_MS,
  assertCommitStructure,
  canBecomeValidMemberPackage,
  commitTreeKeys,
  deriveMembership,
  describeGroupState,
  freshStartPermitted,
  groupCommitTranscript,
  lowestFreeLeaves,
  nextRoster,
  packageKeyConflicts,
  planCommitAdmission,
  type AdmissionPlan,
  type AdmissionState,
  type EligibleDevice,
  type GroupMemberState,
  type MemberPackageState,
  type RejoinRequestState,
} from './mls-group-rules.js';

const cs = await getCiphersuiteImpl(getCiphersuiteFromName(MLS_CIPHERSUITE));
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const base64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');
const fakeSignature = 'A'.repeat(86) + '==';
const MINUTE = 60_000;

// identity -> leaf signature key, as clients build their authentication map.
const directory = new Map<string, string>();
const clientConfig = {
  ...defaultClientConfig,
  keyRetentionConfig: { retainKeysForGenerations: 0, retainKeysForEpochs: 1, maximumForwardRatchetSteps: 1000 },
  authService: {
    async validateCredential(credential: KeyPackage['leafNode']['credential'], signingKey: Uint8Array) {
      return credential.credentialType === 'basic'
        && directory.get(decoder.decode(credential.identity)) === base64(signingKey);
    },
  },
};

interface Package {
  packageId: string;
  pub: KeyPackage;
  priv: PrivateKeyPackage;
  encoded: string;
  keys: MemberPackageKeys;
}

interface Device {
  deviceId: string;
  userId: string;
  identityKey: string;
  pkg: Package;
}

async function newPackage(deviceId: string): Promise<Package> {
  const now = BigInt(Math.floor(Date.now() / 1000));
  const pair = await generateKeyPackage(
    { credentialType: 'basic', identity: encoder.encode(deviceId) },
    { versions: ['mls10'], ciphersuites: [MLS_CIPHERSUITE], extensions: [], proposals: [], credentials: ['basic'] },
    { notBefore: now - 900n, notAfter: now + 604800n },
    [],
    cs,
  );
  const encoded = base64(encodeMlsMessage({ version: 'mls10', wireformat: 'mls_key_package', keyPackage: pair.publicPackage }));
  directory.set(deviceId, base64(pair.publicPackage.leafNode.signaturePublicKey));
  return {
    packageId: randomUUID(),
    pub: pair.publicPackage,
    priv: pair.privatePackage,
    encoded,
    keys: await readMemberPackage(encoded, deviceId),
  };
}

/** A correctly signed package of `device` whose leaf HPKE key is `hpkeKey` (base64). */
async function packageWithLeafKey(device: Device, hpkeKey: string): Promise<Package> {
  const leafNode = await signLeafNodeKeyPackage({
    ...device.pkg.pub.leafNode,
    hpkePublicKey: new Uint8Array(Buffer.from(hpkeKey, 'base64')),
  }, device.pkg.priv.signaturePrivateKey, cs.signature);
  const pub = await signKeyPackage({
    version: 'mls10',
    cipherSuite: cs.name,
    initKey: device.pkg.pub.initKey,
    leafNode,
    extensions: [],
  }, device.pkg.priv.signaturePrivateKey, cs.signature);
  const encoded = base64(encodeMlsMessage({ version: 'mls10', wireformat: 'mls_key_package', keyPackage: pub }));
  return { ...device.pkg, packageId: randomUUID(), pub, encoded, keys: await readMemberPackage(encoded, device.deviceId) };
}

async function newDevice(userId = randomUUID()): Promise<Device> {
  const deviceId = randomUUID();
  return { deviceId, userId, identityKey: `identity-${deviceId}`, pkg: await newPackage(deviceId) };
}

const addProposal = (device: Device): Proposal => ({ proposalType: 'add', add: { keyPackage: device.pkg.pub } });

/** The roster as ts-mls itself holds it after a commit. */
function treeRoster(state: ClientState, devices: Map<string, Device>): MlsGroupMember[] {
  const roster: MlsGroupMember[] = [];
  for (let index = 0; index < state.ratchetTree.length; index += 2) {
    const node = state.ratchetTree[index];
    if (node?.nodeType !== 'leaf' || node.leaf.credential.credentialType !== 'basic') continue;
    const deviceId = decoder.decode(node.leaf.credential.identity);
    roster.push({ deviceId, userId: devices.get(deviceId)!.userId, leafIndex: index / 2 });
  }
  return roster;
}

/** In-memory mirror of the rows the admission transaction reads and writes. */
class ServerModel {
  channelId = randomUUID();
  now = Date.now();
  latestVersion = 0;
  active: AdmissionState['active'] = null;
  group: AdmissionState['group'] = null;
  eligible: EligibleDevice[] = [];
  members: GroupMemberState[] = [];
  packages: MemberPackageState[] = [];
  rejoinRequests: RejoinRequestState[] = [];
  previousRecipientIds: string[] = [];
  recentCommitCount = 0;
  /** UpdatePath keys the current group accepted (mls_group_node_keys). */
  nodeKeys = new Set<string>();
  heads = new Map<string, DirectoryHead>();
  devices = new Map<string, Device>();
  states = new Map<string, ClientState>();

  enroll(device: Device) {
    this.devices.set(device.deviceId, device);
    this.eligible.push({ id: device.deviceId, userId: device.userId, identityKey: device.identityKey });
    if (!this.heads.has(device.userId)) {
      this.heads.set(device.userId, { userId: device.userId, sequence: 1, hash: 'a'.repeat(64) });
    }
  }

  publish(device: Device, rejoin = false) {
    this.packages = this.packages.filter((pkg) => pkg.deviceId !== device.deviceId);
    this.packages.push({
      deviceId: device.deviceId,
      packageId: device.pkg.packageId,
      keyPackage: device.pkg.encoded,
      signature: fakeSignature,
      ...device.pkg.keys,
      rejoin,
      createdAt: new Date(this.now),
    });
  }

  revoke(device: Device) {
    this.eligible = this.eligible.filter((candidate) => candidate.id !== device.deviceId);
  }

  state(overrides: Partial<AdmissionState> = {}): AdmissionState {
    return {
      now: this.now,
      callerUserId: '',
      latestVersion: this.latestVersion,
      active: this.active,
      group: this.group,
      eligible: this.eligible,
      members: this.members,
      packages: this.packages,
      rejoinRequests: this.rejoinRequests,
      usedPackageIds: new Set(),
      reservedKeys: new Set(),
      directoryHeads: this.heads,
      previousRecipientIds: this.previousRecipientIds,
      recentCommitCount: this.recentCommitCount,
      ...overrides,
    };
  }

  envelope(
    kind: 'create' | 'commit',
    committer: Device,
    result: Awaited<ReturnType<typeof createCommit>>,
    added: Device[],
    removed: string[],
  ): MlsGroupCommit {
    const version = this.latestVersion + 1;
    const genesisVersion = kind === 'create' ? version : this.group!.genesisVersion!;
    const members = treeRoster(result.newState, this.devices);
    const commit: MlsGroupCommit = {
      channelId: this.channelId,
      version,
      previousVersion: this.active?.version ?? 0,
      previousTranscript: this.active?.transcript ?? EMPTY_TRANSCRIPT,
      groupId: mlsGroupId(this.channelId, genesisVersion),
      epoch: version - genesisVersion + 1,
      kind,
      keyCommitment: 'k'.repeat(43),
      commit: base64(encodeMlsMessage(result.commit)),
      welcome: result.welcome
        ? base64(encodeMlsMessage({ version: 'mls10', wireformat: 'mls_welcome', welcome: result.welcome }))
        : '',
      added: added.map((device) => ({
        deviceId: device.deviceId,
        userId: device.userId,
        identityKey: device.identityKey,
        packageId: device.pkg.packageId,
        keyPackage: device.pkg.encoded,
        signature: fakeSignature,
      })),
      removed: [...removed].sort(),
      members,
      directoryHeads: [...new Set(members.map((member) => member.userId))].sort()
        .map((userId) => this.heads.get(userId)!),
      committerDeviceId: committer.deviceId,
      signature: fakeSignature,
    };
    return commit;
  }

  /** As reservedCommitKeys reads them: other packages (of any device), current members and accepted nodes. */
  reserved(commit: MlsGroupCommit, decoded: DecodedGroupCommit, keys: MemberPackageKeys[]): Set<string> {
    const candidates = new Set(commitTreeKeys(decoded, keys));
    const addedIds = new Set(commit.added.map((entry) => entry.deviceId));
    const used = this.packages
      .filter((pkg) => !addedIds.has(pkg.deviceId))
      .flatMap((pkg) => [pkg.initKey, pkg.encryptionKey, pkg.signatureKey]);
    if (commit.kind === 'commit') {
      for (const member of this.members) {
        used.push(member.signatureKey, member.encryptionKey, storedPackageInitKey(member.keyPackage));
      }
      used.push(...this.nodeKeys);
    }
    return new Set(used.filter((key) => candidates.has(key)));
  }

  async admit(
    commit: MlsGroupCommit,
    route: 'commit' | 'fresh-start' = 'commit',
    overrides: Partial<AdmissionState> = {},
  ): Promise<AdmissionPlan> {
    const decoded = await decodeGroupCommit(commit.commit);
    const references = commit.welcome === '' ? null : decodeGroupWelcome(commit.welcome);
    const keys = await Promise.all(commit.added.map((entry) => readMemberPackage(entry.keyPackage, entry.deviceId)));
    assertCommitStructure(commit, decoded, references, keys);
    const committer = this.devices.get(commit.committerDeviceId)!;
    return planCommitAdmission(commit, decoded, keys, this.state({
      callerUserId: committer.userId,
      reservedKeys: this.reserved(commit, decoded, keys),
      ...overrides,
    }), route);
  }

  /** The rows admitGroupCommit writes for an accepted plan. */
  apply(commit: MlsGroupCommit, plan: AdmissionPlan) {
    if (plan.closeOldGroup) this.members = [];
    const removed = new Set(plan.removedDeviceIds);
    this.members = this.members.filter((member) => !removed.has(member.deviceId));
    if (plan.kind === 'commit' && plan.committerEncryptionKey) {
      const committer = this.members.find((member) => member.deviceId === commit.committerDeviceId)!;
      committer.encryptionKey = plan.committerEncryptionKey;
      committer.leafUpdatedAt = new Date(this.now);
    }
    plan.added.forEach((entry, index) => {
      this.members.push({
        deviceId: entry.deviceId,
        userId: entry.userId,
        leafIndex: entry.leafIndex,
        joinedVersion: commit.version,
        signatureKey: entry.keys.signatureKey,
        encryptionKey: plan.kind === 'create' && index === 0 && plan.committerEncryptionKey
          ? plan.committerEncryptionKey
          : entry.keys.encryptionKey,
        keyPackage: entry.keyPackage,
        leafUpdatedAt: new Date(this.now),
        lastSeenAt: new Date(this.now),
      });
      this.packages = this.packages.filter((pkg) => pkg.deviceId !== entry.deviceId);
    });
    if (plan.kind === 'create') {
      this.group = { genesisVersion: commit.version, pathRefreshedAt: new Date(this.now), genesisRequestedAt: this.group?.genesisRequestedAt ?? null };
      this.nodeKeys = new Set();
    } else if (plan.pathRefresh) {
      this.group = { ...this.group!, pathRefreshedAt: new Date(this.now) };
    }
    for (const key of plan.pathKeys) this.nodeKeys.add(key);
    this.active = {
      version: commit.version,
      protocolVersion: 4,
      createdAt: new Date(this.now),
      transcript: groupCommitTranscript(commit),
    };
    this.latestVersion = commit.version;
    if (plan.kind === 'commit' && plan.removedDeviceIds.length === 0) this.recentCommitCount += 1;
  }

  /** Every other current member processes the accepted commit; new members join. */
  async deliver(commit: MlsGroupCommit, result: Awaited<ReturnType<typeof createCommit>>, joined: Device[]) {
    const message = decodeMlsMessage(Buffer.from(commit.commit, 'base64'), 0)![0] as unknown as MlsPublicMessage;
    for (const member of this.members) {
      if (member.deviceId === commit.committerDeviceId || joined.some((device) => device.deviceId === member.deviceId)) continue;
      const state = this.states.get(member.deviceId)!;
      const processed = await processMessage(message, state, makePskIndex(state, {}), acceptAll, cs);
      assert.equal(processed.kind, 'newState');
      this.states.set(member.deviceId, processed.newState);
    }
    this.states.set(commit.committerDeviceId, result.newState);
    for (const device of joined) {
      if (device.deviceId === commit.committerDeviceId) continue;
      this.states.set(device.deviceId, await joinGroup(
        result.welcome!, device.pkg.pub, device.pkg.priv, emptyPskIndex, cs, undefined, undefined, clientConfig,
      ));
    }
    // Deleting the current entry while iterating a Map is safe.
    for (const deviceId of this.states.keys()) {
      if (!this.members.some((member) => member.deviceId === deviceId)) this.states.delete(deviceId);
    }
  }

  async genesis(creator: Device, others: Device[]) {
    const group = await createGroup(
      encoder.encode(mlsGroupId(this.channelId, this.latestVersion + 1)),
      creator.pkg.pub,
      creator.pkg.priv,
      [],
      cs,
      clientConfig,
    );
    const result = await createCommit({ state: group, cipherSuite: cs }, {
      wireAsPublicMessage: true,
      ratchetTreeExtension: true,
      extraProposals: others.map(addProposal),
    });
    const commit = this.envelope('create', creator, result, [creator, ...others], []);
    return { commit, result };
  }

  async commit(committer: Device, options: { add?: Device[]; remove?: Device[] } = {}) {
    const state = this.states.get(committer.deviceId)!;
    const leaves = new Map(this.members.map((member) => [member.deviceId, member.leafIndex]));
    const result = await createCommit({ state, cipherSuite: cs }, {
      wireAsPublicMessage: true,
      ratchetTreeExtension: true,
      extraProposals: [
        ...(options.remove ?? []).map((device): Proposal => ({
          proposalType: 'remove',
          remove: { removed: leaves.get(device.deviceId)! },
        })),
        ...(options.add ?? []).map(addProposal),
      ],
    });
    const commit = this.envelope(
      'commit',
      committer,
      result,
      options.add ?? [],
      (options.remove ?? []).map((device) => device.deviceId),
    );
    return { commit, result };
  }

  async accept(created: { commit: MlsGroupCommit; result: Awaited<ReturnType<typeof createCommit>> }, joined: Device[] = []) {
    const plan = await this.admit(created.commit);
    this.apply(created.commit, plan);
    await this.deliver(created.commit, created.result, joined);
    return plan;
  }
}

async function rejects(promise: Promise<unknown> | (() => unknown), code: string) {
  if (typeof promise === 'function') {
    assert.throws(promise as () => unknown, (error: Error) => error.message === code);
    return;
  }
  await assert.rejects(promise, (error: Error) => error.message === code);
}

describe('continuous group roster arithmetic', () => {
  it('fills the lowest free leaves in Add order', () => {
    assert.deepEqual(lowestFreeLeaves([0, 2, 3], 3), [1, 4, 5]);
    const current = [0, 1, 2, 3].map((leafIndex) => ({ deviceId: `d${leafIndex}`, userId: 'u', leafIndex }));
    assert.deepEqual(
      nextRoster(current, ['d1', 'd3'], [{ deviceId: 'x', userId: 'u' }, { deviceId: 'y', userId: 'u' }, { deviceId: 'z', userId: 'u' }])
        .map((member) => `${member.deviceId}@${member.leafIndex}`),
      ['d0@0', 'x@1', 'd2@2', 'y@3', 'z@4'],
    );
  });

  it('accepts create, add, remove and rejoin exactly as ts-mls assigns leaves', async () => {
    const model = new ServerModel();
    const [a, b, c, d, e] = await Promise.all([newDevice(), newDevice(), newDevice(), newDevice(), newDevice()]);
    for (const device of [a, b, c]) {
      model.enroll(device);
      model.publish(device);
    }
    const genesis = await model.genesis(a, [b, c]);
    const created = await model.accept(genesis, [b, c]);
    assert.equal(created.kind, 'create');
    assert.equal(created.genesisVersion, 1);
    assert.deepEqual(created.added.map((entry) => entry.leafIndex), [0, 1, 2]);
    assert.equal(created.pathRefresh, true);
    assert.equal(model.packages.length, 0, 'the creator package is consumed too');

    // B is revoked; D and E publish. The commit removes B and the first Add
    // reuses B's leaf.
    model.revoke(b);
    for (const device of [d, e]) {
      model.enroll(device);
      model.publish(device);
    }
    const changed = await model.accept(await model.commit(a, { remove: [b], add: [d, e] }), [d, e]);
    assert.deepEqual(changed.removedDeviceIds, [b.deviceId]);
    assert.deepEqual(changed.added.map((entry) => [entry.deviceId, entry.leafIndex]), [[d.deviceId, 1], [e.deviceId, 3]]);
    assert.ok(changed.committerEncryptionKey, 'a Remove carries an UpdatePath');

    // C lost its state and asks to be added again with a new package.
    c.pkg = await newPackage(c.deviceId);
    model.publish(c, true);
    model.rejoinRequests.push({ deviceId: c.deviceId, requestedAt: new Date(model.now), version: model.latestVersion });
    const rejoined = await model.accept(await model.commit(d, { remove: [c], add: [c] }), [c]);
    assert.deepEqual(rejoined.rejoinedDeviceIds, [c.deviceId]);
    assert.deepEqual(rejoined.added.map((entry) => entry.leafIndex), [2], 'a rejoin returns to the same leaf');
    assert.equal(deriveMembership({ ...model.state(), eligible: model.eligible }).rejoinOpenSince.size, 0);

    // Everyone agrees on the result.
    const rosters = [...model.states.values()].map((state) => JSON.stringify(treeRoster(state, model.devices)));
    assert.equal(new Set(rosters).size, 1);
  });

  it('assigns the lowest free leaves after removed trailing leaves are truncated', async () => {
    const model = new ServerModel();
    const devices = await Promise.all(Array.from({ length: 6 }, () => newDevice()));
    for (const device of devices) {
      model.enroll(device);
      model.publish(device);
    }
    await model.accept(await model.genesis(devices[0], devices.slice(1)), devices.slice(1));
    model.revoke(devices[4]);
    model.revoke(devices[5]);
    await model.accept(await model.commit(devices[0], { remove: [devices[4], devices[5]] }));
    const [g, h] = [await newDevice(), await newDevice()];
    for (const device of [g, h]) {
      model.enroll(device);
      model.publish(device);
    }
    const plan = await model.accept(await model.commit(devices[1], { add: [g, h] }), [g, h]);
    assert.deepEqual(plan.added.map((entry) => entry.leafIndex), [4, 5]);
    assert.equal(plan.pathRefresh, false, 'add-only commits carry no UpdatePath');
  });
});

describe('continuous group admission rules', () => {
  async function twoMemberGroup() {
    const model = new ServerModel();
    const [a, b] = await Promise.all([newDevice(), newDevice()]);
    for (const device of [a, b]) {
      model.enroll(device);
      model.publish(device);
    }
    await model.accept(await model.genesis(a, [b]), [b]);
    return { model, a, b };
  }

  it('keeps additions optional but requires every required remove', async () => {
    const { model, a, b } = await twoMemberGroup();
    const [c, d] = [await newDevice(), await newDevice()];
    model.enroll(c);
    model.publish(c);
    model.enroll(d);
    model.revoke(b);
    // Pending addition C may wait; the revoked member B may not.
    await rejects(model.admit((await model.commit(a, { add: [c] })).commit), 'MLS_CONFLICT');
    const removal = await model.commit(a, { remove: [b] });
    const plan = await model.admit(removal.commit);
    assert.deepEqual(plan.removedDeviceIds, [b.deviceId]);
    assert.equal(plan.added.length, 0);
    // An eligible member leaves only through its own rejoin request.
    model.eligible.push({ id: b.deviceId, userId: b.userId, identityKey: b.identityKey });
    await rejects(model.admit(removal.commit), 'MLS_CONFLICT');
  });

  it('accepts an empty commit only when the group or the committer leaf is due', async () => {
    const { model, a } = await twoMemberGroup();
    const empty = await model.commit(a);
    await rejects(model.admit(empty.commit), 'KEY_ROTATION_NOT_REQUIRED');
    model.group = { ...model.group!, pathRefreshedAt: new Date(model.now - PATH_REFRESH_INTERVAL_MS) };
    assert.equal((await model.admit(empty.commit)).pathRefresh, true);
    model.group = { ...model.group!, pathRefreshedAt: new Date(model.now) };
    model.members[0].leafUpdatedAt = new Date(model.now - LEAF_REFRESH_INTERVAL_MS);
    assert.ok((await model.admit(empty.commit)).committerEncryptionKey);
  });

  it('limits add-only and empty commits per hour but never a commit with a Remove', async () => {
    const { model, a, b } = await twoMemberGroup();
    const c = await newDevice();
    model.enroll(c);
    model.publish(c);
    model.recentCommitCount = COMMIT_RATE_LIMIT;
    await rejects(model.admit((await model.commit(a, { add: [c] })).commit), 'COMMIT_RATE_LIMITED');
    model.group = { ...model.group!, pathRefreshedAt: new Date(model.now - PATH_REFRESH_INTERVAL_MS) };
    await rejects(model.admit((await model.commit(a)).commit), 'COMMIT_RATE_LIMITED');
    // A rejoin removes and re-adds an eligible device.
    b.pkg = await newPackage(b.deviceId);
    model.publish(b, true);
    model.rejoinRequests.push({ deviceId: b.deviceId, requestedAt: new Date(model.now), version: model.latestVersion });
    assert.deepEqual((await model.admit((await model.commit(a, { remove: [b], add: [b] })).commit)).rejoinedDeviceIds, [b.deviceId]);
    model.revoke(b);
    assert.deepEqual((await model.admit((await model.commit(a, { remove: [b], add: [c] })).commit)).removedDeviceIds, [b.deviceId]);
  });

  it('reports state the client may have read earlier as 409 and malformed envelopes as 403', async () => {
    const { model, a, b } = await twoMemberGroup();
    const c = await newDevice();
    model.enroll(c);
    model.publish(c);
    const { commit } = await model.commit(a, { add: [c] });
    await model.admit(commit);

    await rejects(model.admit({ ...commit, previousTranscript: 'f'.repeat(64) }), 'MLS_CONFLICT');
    await rejects(model.admit(commit, 'commit', { latestVersion: model.latestVersion + 1 }), 'MLS_CONFLICT');
    const replaced = model.packages.map((pkg) => (pkg.deviceId === c.deviceId ? { ...pkg, packageId: randomUUID() } : pkg));
    await rejects(model.admit(commit, 'commit', { packages: replaced }), 'MLS_CONFLICT');
    const expiring = model.packages.map((pkg) => ({ ...pkg, notAfter: new Date(model.now + 30 * MINUTE) }));
    await rejects(model.admit(commit, 'commit', { packages: expiring }), 'MLS_CONFLICT');
    await rejects(model.admit(commit, 'commit', { eligible: model.eligible.filter((device) => device.id !== c.deviceId) }), 'MLS_CONFLICT');
    await rejects(model.admit(commit, 'commit', { usedPackageIds: new Set([c.pkg.packageId]) }), 'MLS_CONFLICT');
    const heads = new Map(model.heads);
    heads.set(c.userId, { userId: c.userId, sequence: 2, hash: 'b'.repeat(64) });
    await rejects(model.admit(commit, 'commit', { directoryHeads: heads }), 'MLS_CONFLICT');

    await rejects(model.admit({ ...commit, added: [{ ...commit.added[0], identityKey: 'other' }] }), 'INVALID_MLS');
    const wrongLeaf = commit.members.map((member) => (member.deviceId === c.deviceId ? { ...member, leafIndex: 5 } : member));
    await rejects(model.admit({ ...commit, members: wrongLeaf }), 'INVALID_MLS');
    await rejects(model.admit({ ...commit, epoch: commit.epoch + 1 }), 'INVALID_MLS');
    // An add-only commit by A cannot be presented as B's commit: the sender leaf is A's.
    await rejects(model.admit({ ...commit, committerDeviceId: b.deviceId }), 'INVALID_MLS');
  });

  it('checks the UpdatePath leaf against the committer', async () => {
    const { model, a, b } = await twoMemberGroup();
    model.group = { ...model.group!, pathRefreshedAt: new Date(model.now - PATH_REFRESH_INTERVAL_MS) };
    const { commit } = await model.commit(a);
    await rejects(model.admit({ ...commit, committerDeviceId: b.deviceId }), 'INVALID_MLS');
    // The leaf keeps the committer's stored signature key.
    const members = model.members.map((member) => (
      member.deviceId === a.deviceId ? { ...member, signatureKey: base64(new Uint8Array(32).fill(7)) } : member
    ));
    await rejects(model.admit(commit, 'commit', { members }), 'INVALID_MLS');
    // Its new HPKE key must not collide with another leaf.
    const decoded = await decodeGroupCommit(commit.commit);
    const colliding = model.members.map((member) => (
      member.deviceId === b.deviceId ? { ...member, encryptionKey: decoded.path!.encryptionKey } : member
    ));
    await rejects(model.admit(commit, 'commit', { members: colliding }), 'PACKAGE_KEY_CONFLICT');
    // Nor with a package waiting to be added, of any device: that device
    // could never be added afterwards. The same holds for the parent key.
    const waiting = await newDevice();
    for (const key of [decoded.path!.encryptionKey, decoded.path!.nodeKeys[0]]) {
      waiting.pkg = await packageWithLeafKey(waiting, key);
      model.publish(waiting);
      await rejects(model.admit(commit), 'PACKAGE_KEY_CONFLICT');
    }
    model.packages = model.packages.filter((pkg) => pkg.deviceId !== waiting.deviceId);
    assert.equal((await model.admit(commit)).pathKeys.length, 2);
  });

  it('keeps every key a tree node ever had out of new leaves and paths', async () => {
    const { model, a, b } = await twoMemberGroup();
    model.group = { ...model.group!, pathRefreshedAt: new Date(model.now - PATH_REFRESH_INTERVAL_MS) };
    const update = await model.commit(b);
    await model.accept(update);
    const [parentKey] = (await decodeGroupCommit(update.commit.commit)).path!.nodeKeys;
    assert.ok(model.nodeKeys.has(parentKey));
    // ts-mls accepts an Add whose leaf reuses a parent key, and every later
    // commit of the group then fails.
    const x = await newDevice();
    model.enroll(x);
    x.pkg = await packageWithLeafKey(x, parentKey);
    model.publish(x);
    await rejects(model.admit((await model.commit(a, { add: [x] })).commit), 'PACKAGE_KEY_CONFLICT');
    // A new group starts with an empty tree.
    a.pkg = await newPackage(a.deviceId);
    model.publish(a, true);
    const restart = await model.genesis(a, [x]);
    assert.deepEqual((await model.admit(restart.commit, 'fresh-start', { freshStartPermitted: true })).added
      .map((entry) => entry.deviceId), [a.deviceId, x.deviceId]);
  });

  it('rejects UpdatePath keys that repeat or have low order', async () => {
    const { model, a } = await twoMemberGroup();
    const state = model.states.get(a.deviceId)!;
    const { commit: message } = await createCommit({ state, cipherSuite: cs }, { wireAsPublicMessage: true });
    const publicMessage = (message as unknown as MlsPublicMessage).publicMessage;
    const content = publicMessage.content as typeof publicMessage.content & { contentType: 'commit' };
    const path = content.commit.path!;
    const encodeWith = (changed: typeof path) => base64(encodeMlsMessage({
      ...message,
      publicMessage: { ...publicMessage, content: { ...content, commit: { ...content.commit, path: changed } } },
    } as typeof message));
    assert.equal((await decodeGroupCommit(encodeWith(path))).path!.nodeKeys.length, 1);
    const lowOrder = new Uint8Array(32);
    lowOrder[0] = 1;
    await rejects(decodeGroupCommit(encodeWith({ ...path, nodes: [{ ...path.nodes[0], hpkePublicKey: lowOrder }] })), 'INVALID_MLS');
    await rejects(decodeGroupCommit(encodeWith({
      ...path,
      nodes: [{ ...path.nodes[0], hpkePublicKey: path.leafNode.hpkePublicKey }],
    })), 'INVALID_MLS');
    // A correctly signed leaf with a low-order key is refused too.
    const leafNode = await signLeafNodeCommit({
      ...path.leafNode,
      hpkePublicKey: lowOrder,
      groupId: content.groupId,
      leafIndex: 0,
    }, state.signaturePrivateKey, cs.signature);
    await rejects(decodeGroupCommit(encodeWith({ ...path, leafNode })), 'INVALID_MLS');
  });

  it('binds each Welcome secret to the added package in order', async () => {
    const { model, a } = await twoMemberGroup();
    const [c, d] = [await newDevice(), await newDevice()];
    for (const device of [c, d]) {
      model.enroll(device);
      model.publish(device);
    }
    const { commit } = await model.commit(a, { add: [c, d] });
    const references = decodeGroupWelcome(commit.welcome);
    assert.deepEqual(references, [c.pkg.keys.reference, d.pkg.keys.reference]);
    const other = await model.commit(a, { add: [d, c] });
    await rejects(model.admit({ ...commit, welcome: other.commit.welcome }), 'INVALID_MLS');
    await rejects(model.admit({ ...commit, welcome: '' }), 'INVALID_MLS');
  });

  it('rejects a commit that is not a plain member PublicMessage', async () => {
    const { model, a } = await twoMemberGroup();
    const state = model.states.get(a.deviceId)!;
    const privateCommit = await createCommit({ state, cipherSuite: cs }, { ratchetTreeExtension: true });
    await rejects(decodeGroupCommit(base64(encodeMlsMessage(privateCommit.commit))), 'INVALID_MLS');
    const withData = await createCommit({ state, cipherSuite: cs }, {
      wireAsPublicMessage: true,
      authenticatedData: new Uint8Array([1]),
    });
    await rejects(decodeGroupCommit(base64(encodeMlsMessage(withData.commit))), 'INVALID_MLS');
    await rejects(decodeGroupCommit(`${base64(encodeMlsMessage(withData.commit))}AA==`), 'INVALID_MLS');
  });

  it('rejects package encodings and keys that would break later commits', async () => {
    const device = await newDevice();
    const bytes = Buffer.from(device.pkg.encoded, 'base64');
    const identity = Buffer.from(device.deviceId);
    const at = bytes.indexOf(identity);
    // A two-byte length prefix still verifies, but an Add re-encodes it.
    const longPrefix = Buffer.concat([bytes.subarray(0, at - 1), Buffer.from([0x40, identity.length]), bytes.subarray(at)]);
    await rejects(readMemberPackage(longPrefix.toString('base64'), device.deviceId), 'INVALID_MLS');

    const victim = await newDevice();
    const forgedLeaf = await signLeafNodeKeyPackage({
      ...device.pkg.pub.leafNode,
      hpkePublicKey: victim.pkg.pub.leafNode.hpkePublicKey,
    }, device.pkg.priv.signaturePrivateKey, cs.signature);
    const forged = await signKeyPackage({
      version: 'mls10',
      cipherSuite: cs.name,
      initKey: device.pkg.pub.initKey,
      leafNode: forgedLeaf,
      extensions: [],
    }, device.pkg.priv.signaturePrivateKey, cs.signature);
    const forgedKeys = await readMemberPackage(
      base64(encodeMlsMessage({ version: 'mls10', wireformat: 'mls_key_package', keyPackage: forged })),
      device.deviceId,
    );
    const member = {
      signatureKey: victim.pkg.keys.signatureKey,
      encryptionKey: victim.pkg.keys.encryptionKey,
      keyPackage: victim.pkg.encoded,
    };
    assert.equal(packageKeyConflicts(forgedKeys, [member], []), true);
    assert.equal(packageKeyConflicts(forgedKeys, [], [victim.pkg.keys]), true);
    assert.equal(packageKeyConflicts(device.pkg.keys, [member], [victim.pkg.keys]), false);
    // A member's add-time init key stays reserved too.
    assert.equal(packageKeyConflicts({ ...device.pkg.keys, initKey: victim.pkg.keys.initKey }, [member], []), true);
  });

  it('refuses a key collision among the leaves a commit creates', async () => {
    const { model, a } = await twoMemberGroup();
    const c = await newDevice();
    model.enroll(c);
    model.publish(c);
    const { commit } = await model.commit(a, { add: [c] });
    const members = model.members.map((member) => (
      member.deviceId === a.deviceId ? { ...member, encryptionKey: c.pkg.keys.encryptionKey } : member
    ));
    await rejects(model.admit(commit, 'commit', { members }), 'PACKAGE_KEY_CONFLICT');
  });

  it('sends a create for an existing group to fresh start', async () => {
    const { model, a, b } = await twoMemberGroup();
    a.pkg = await newPackage(a.deviceId);
    b.pkg = await newPackage(b.deviceId);
    model.publish(a, true);
    model.publish(b, true);
    const restart = await model.genesis(a, [b]);
    assert.equal(restart.commit.previousVersion, 1);
    await rejects(model.admit(restart.commit), 'KEY_FRESH_START_REQUIRED');
    await rejects(model.admit(restart.commit, 'fresh-start', { freshStartPermitted: false }), 'KEY_FRESH_START_NOT_REQUIRED');
    const plan = await model.admit(restart.commit, 'fresh-start', { freshStartPermitted: true });
    assert.equal(plan.closeOldGroup, true);
    assert.equal(plan.genesisVersion, 2);
    await rejects(model.admit({ ...restart.commit, kind: 'commit' }, 'fresh-start', { freshStartPermitted: true }), 'INVALID_MLS');
  });

  it('waits for the earlier epoch recipients before the first group of a migrated channel', async () => {
    const model = new ServerModel();
    const [a, b] = await Promise.all([newDevice(), newDevice()]);
    model.enroll(a);
    model.enroll(b);
    model.publish(a);
    model.latestVersion = 3;
    model.active = { version: 3, protocolVersion: 3, createdAt: new Date(model.now - 60 * MINUTE), transcript: 'c'.repeat(64) };
    model.previousRecipientIds = [a.deviceId, b.deviceId];
    model.group = { genesisVersion: null, pathRefreshedAt: null, genesisRequestedAt: new Date(model.now) };
    const solo = await model.genesis(a, []);
    assert.equal(solo.commit.previousTranscript, 'c'.repeat(64));
    await rejects(model.admit(solo.commit), 'GENESIS_WAITING');
    model.publish(b);
    await rejects(model.admit(solo.commit), 'MLS_CONFLICT');
    const both = await model.genesis(a, [b]);
    assert.equal((await model.admit(both.commit)).added.length, 2);
    model.packages = model.packages.filter((pkg) => pkg.deviceId !== b.deviceId);
    model.group = { ...model.group, genesisRequestedAt: new Date(model.now - GENESIS_WAIT_MS) };
    const plan = await model.admit(solo.commit);
    assert.deepEqual(plan.added.map((entry) => entry.deviceId), [a.deviceId]);
    assert.ok(plan.committerEncryptionKey, 'a one-device genesis is an empty commit with a path');
  });

  it('names a version by a transcript that ignores the signature and key order', async () => {
    const { model, a } = await twoMemberGroup();
    const c = await newDevice();
    model.enroll(c);
    model.publish(c);
    const { commit } = await model.commit(a, { add: [c] });
    const reordered = JSON.parse(JSON.stringify(Object.fromEntries(Object.entries(commit).reverse()))) as MlsGroupCommit;
    assert.equal(groupCommitTranscript(reordered), groupCommitTranscript(commit));
    assert.equal(groupCommitTranscript({ ...commit, signature: 'B'.repeat(86) + '==' } as MlsGroupCommit), groupCommitTranscript(commit));
    assert.notEqual(groupCommitTranscript({ ...commit, keyCommitment: 'j'.repeat(43) }), groupCommitTranscript(commit));
  });
});

describe('continuous group state', () => {
  const member = (deviceId: string, userId: string, leafIndex: number, now: number): GroupMemberState => ({
    deviceId,
    userId,
    leafIndex,
    joinedVersion: 1,
    signatureKey: `s-${deviceId}`,
    encryptionKey: `e-${deviceId}`,
    keyPackage: '',
    leafUpdatedAt: new Date(now),
    lastSeenAt: new Date(now),
  });
  const pkg = (deviceId: string, now: number, rejoin = false): MemberPackageState => ({
    deviceId,
    packageId: randomUUID(),
    keyPackage: '',
    signature: fakeSignature,
    initKey: `i-${deviceId}`,
    encryptionKey: `pe-${deviceId}`,
    signatureKey: `ps-${deviceId}`,
    notBefore: new Date(now - 15 * MINUTE),
    notAfter: new Date(now + 6 * 24 * 60 * MINUTE),
    rejoin,
    createdAt: new Date(now - 20 * MINUTE),
  });

  it('derives pending additions, required removes and who may commit', () => {
    const now = Date.now();
    const channelId = randomUUID();
    const eligible = ['a', 'b', 'd', 'e'].map((id) => ({ id, userId: `u-${id}`, identityKey: id }));
    const snapshot = {
      latestVersion: 5,
      active: { version: 5, protocolVersion: 4, createdAt: new Date(now - 30 * MINUTE), transcript: 'd'.repeat(64) },
      group: { genesisVersion: 2, pathRefreshedAt: new Date(now - PATH_REFRESH_INTERVAL_MS), genesisRequestedAt: null },
      members: [member('a', 'u-a', 0, now), member('b', 'u-b', 1, now), member('c', 'u-c', 2, now)],
      packages: [
        pkg('d', now),
        // Valid (and so addable) for 35 minutes.
        { ...pkg('b', now, true), notBefore: new Date(now - 45 * MINUTE), createdAt: new Date(now - 40 * MINUTE) },
        { ...pkg('e', now), notBefore: new Date(now - 5 * MINUTE) },
      ],
      rejoinRequests: [{ deviceId: 'b', requestedAt: new Date(now - 40 * MINUTE), version: 4 }],
      previousRecipientIds: [],
    };
    const state = describeGroupState(channelId, snapshot, eligible, { userId: 'u-a', deviceId: 'a', hasRotationPermission: false, now });
    assert.deepEqual(state.pendingAddDeviceIds, ['b', 'd'], 'e has no valid package yet; b asked to rejoin');
    assert.deepEqual(state.requiredRemoveDeviceIds, ['c']);
    assert.equal(state.updateRequired, true);
    assert.equal(state.rotationRequired, true);
    assert.equal(state.canCommit, true);
    assert.equal(state.canCreate, false);
    assert.deepEqual(state.group, {
      genesisVersion: 2,
      groupId: mlsGroupId(channelId, 2),
      epoch: 4,
      transcript: 'd'.repeat(64),
      members: snapshot.members.map(({ deviceId, userId, leafIndex }) => ({ deviceId, userId, leafIndex })),
    });
    const rejoining = describeGroupState(channelId, snapshot, eligible, { userId: 'u-b', deviceId: 'b', hasRotationPermission: false, now });
    assert.equal(rejoining.canCommit, false);
    assert.equal(rejoining.ownMembership?.rejoinRequested, true);
    // Members could have added it again for 35 minutes, so it may start the conversation again.
    assert.equal(rejoining.historyRecoveryRequired, true);
    const newcomer = describeGroupState(channelId, snapshot, eligible, { userId: 'u-d', deviceId: 'd', hasRotationPermission: false, now });
    assert.equal(newcomer.ownMembership, null);
    assert.equal(newcomer.historyRecoveryRequired, false, 'a usable member was seen recently');
  });

  it('lists the earlier recipients a migrated channel still waits for', () => {
    const now = Date.now();
    const eligible = ['a', 'b', 'c'].map((id) => ({ id, userId: `u-${id}`, identityKey: id }));
    const snapshot = {
      latestVersion: 3,
      active: { version: 3, protocolVersion: 3, createdAt: new Date(now), transcript: null },
      group: { genesisVersion: null, pathRefreshedAt: null, genesisRequestedAt: new Date(now - 60 * MINUTE) },
      members: [],
      packages: [pkg('a', now)],
      rejoinRequests: [],
      previousRecipientIds: ['a', 'b', 'gone'],
    };
    const state = describeGroupState(randomUUID(), snapshot, eligible, { userId: 'u-c', deviceId: 'c', hasRotationPermission: false, now });
    assert.equal(state.group, null);
    assert.equal(state.canCreate, true);
    assert.equal(state.rotationRequired, true);
    assert.deepEqual(state.genesisWaiting, ['b']);
    assert.deepEqual(state.pendingAddDeviceIds, ['a']);
    const later = describeGroupState(randomUUID(), {
      ...snapshot,
      group: { ...snapshot.group, genesisRequestedAt: new Date(now - GENESIS_WAIT_MS) },
    }, eligible, { userId: 'u-c', deviceId: 'c', hasRotationPermission: false, now });
    assert.deepEqual(later.genesisWaiting, []);
  });

  const freshStartInput = (now: number, overrides: {
    eligible?: string[];
    members?: GroupMemberState[];
    rejoin?: RejoinRequestState[];
    packages?: MemberPackageState[];
    manager?: boolean;
    caller?: string;
    removeRequiredAt?: Date;
  }) => {
    const eligible = (overrides.eligible ?? ['a', 'b', 'x']).map((id) => ({ id, userId: `u-${id}`, identityKey: id }));
    const current = overrides.members ?? [member('a', 'u-a', 0, now), member('b', 'u-b', 1, now)];
    return {
      now,
      callerDeviceId: overrides.caller ?? 'x',
      hasRotationPermission: overrides.manager ?? false,
      view: deriveMembership({ eligible, members: current, packages: overrides.packages ?? [], rejoinRequests: overrides.rejoin ?? [], now }),
      members: current,
      activeCreatedAt: new Date(now - 60 * MINUTE),
      removeRequiredAt: overrides.removeRequiredAt ?? null,
    };
  };
  /** Valid since `validFor` ago (published then, or valid on a slower clock from then). */
  const addable = (deviceId: string, now: number, validFor: number, rejoin = false): MemberPackageState => ({
    ...pkg(deviceId, now, rejoin),
    notBefore: new Date(now - validFor - 10 * MINUTE),
    createdAt: new Date(now - validFor),
  });

  it('permits fresh start only for idle groups, old rejoin requests or stalled managers', () => {
    const now = Date.now();
    const input = (overrides: Parameters<typeof freshStartInput>[1]) => freshStartInput(now, overrides);
    const members = [member('a', 'u-a', 0, now), member('b', 'u-b', 1, now)];
    assert.equal(freshStartPermitted(input({})), false);
    const idle = members.map((candidate) => ({ ...candidate, lastSeenAt: new Date(now - 73 * 60 * MINUTE) }));
    assert.equal(freshStartPermitted(input({ members: idle })), true);
    const request = (age: number) => [{ deviceId: 'b', requestedAt: new Date(now - age), version: 1 }];
    assert.equal(freshStartPermitted(input({ caller: 'b', rejoin: request(10 * MINUTE), packages: [addable('b', now, 10 * MINUTE, true)] })), false);
    assert.equal(freshStartPermitted(input({ caller: 'b', rejoin: request(31 * MINUTE), packages: [addable('b', now, 31 * MINUTE, true)] })), true);
    assert.equal(freshStartPermitted(input({ packages: [addable('x', now, 16 * MINUTE)] })), false);
    assert.equal(freshStartPermitted(input({ packages: [addable('x', now, 16 * MINUTE)], manager: true })), true);
    assert.equal(freshStartPermitted(input({ packages: [addable('x', now, 5 * MINUTE)], manager: true })), false);
    // Published long ago, but valid on a slower clock only for ten minutes.
    const young = { ...pkg('x', now), createdAt: new Date(now - 60 * MINUTE), notBefore: new Date(now - 20 * MINUTE) };
    assert.equal(freshStartPermitted(input({ packages: [young], manager: true })), false);
  });

  it('counts a rejoin request only while its package can be added', () => {
    const now = Date.now();
    const input = (overrides: Parameters<typeof freshStartInput>[1]) => freshStartInput(now, overrides);
    const request = [{ deviceId: 'b', requestedAt: new Date(now - 60 * MINUTE), version: 1 }];
    // Expires within the hour, so no member could ever add it.
    const shortLived = { ...addable('b', now, 60 * MINUTE, true), notAfter: new Date(now + 30 * MINUTE) };
    assert.equal(canBecomeValidMemberPackage(shortLived, now), false);
    assert.equal(freshStartPermitted(input({ caller: 'b', rejoin: request, packages: [shortLived] })), false);
    assert.equal(freshStartPermitted(input({ caller: 'a', manager: true, rejoin: request, packages: [shortLived] })), false);
    // A valid package published again just now gives members the full wait.
    assert.equal(freshStartPermitted(input({ caller: 'b', rejoin: request, packages: [addable('b', now, MINUTE, true)] })), false);
    assert.equal(freshStartPermitted(input({ caller: 'a', manager: true, rejoin: request, packages: [addable('b', now, MINUTE, true)] })), false);
    assert.equal(freshStartPermitted(input({ caller: 'b', rejoin: request, packages: [addable('b', now, 31 * MINUTE, true)] })), true);
  });

  it('counts a required remove from when it arose', () => {
    const now = Date.now();
    const input = (overrides: Parameters<typeof freshStartInput>[1]) => freshStartInput(now, { eligible: ['a', 'x'], manager: true, ...overrides });
    const revokedSince = (age: number) => [
      member('a', 'u-a', 0, now),
      { ...member('b', 'u-b', 1, now), revokedAt: new Date(now - age) },
    ];
    // The last commit was an hour ago, but the device was revoked just now.
    assert.equal(freshStartPermitted(input({ members: revokedSince(5 * MINUTE) })), false);
    assert.equal(freshStartPermitted(input({ members: revokedSince(16 * MINUTE) })), true);
    // A user that lost access counts from mls_groups.remove_required_at, and not at all without it.
    assert.equal(freshStartPermitted(input({})), false);
    assert.equal(freshStartPermitted(input({ removeRequiredAt: new Date(now - 5 * MINUTE) })), false);
    assert.equal(freshStartPermitted(input({ removeRequiredAt: new Date(now - 16 * MINUTE) })), true);
  });

  it('refuses packages that can never be added', () => {
    const now = Date.now();
    const lifetime = (notBefore: number, notAfter: number) => ({ notBefore: new Date(now + notBefore), notAfter: new Date(now + notAfter) });
    assert.equal(canBecomeValidMemberPackage(lifetime(-15 * MINUTE, 7 * 24 * 60 * MINUTE), now), true);
    assert.equal(canBecomeValidMemberPackage(lifetime(0, 70 * MINUTE), now), true, 'valid from ten minutes on, for an hour');
    assert.equal(canBecomeValidMemberPackage(lifetime(0, 69 * MINUTE), now), false);
    assert.equal(canBecomeValidMemberPackage(lifetime(-7 * 24 * 60 * MINUTE, 59 * MINUTE), now), false);
  });
});
