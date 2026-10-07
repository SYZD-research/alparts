import {
  mlsGroupId,
  serializeChannelKeyFreshStart,
  serializeMlsGroupCommit,
  serializeMlsMemberPackage,
  type DirectoryHead,
  type MlsGroupCommit,
  type MlsMemberPackage,
} from '@alparts/shared';
import type { ClientState } from 'ts-mls';
import {
  api,
  ApiError,
  type ChannelKeyRecipientState,
  type MlsGroupCommitRecord,
} from './api';
import { channelKeyScopes, type ChannelKeyScopeToken } from './channel-key-scope';
import { ChannelKeyDeliveryPendingError } from './channel-key-wait';
import {
  getActiveDevice,
  signDevicePayload,
  storeGroupVersionKey,
  verifyDevicePayload,
} from './crypto.service';
import { cachedDirectory, verifiedDirectory } from './directory.service';
import { deviceMeetsPolicy, type VerifiedDirectory } from './directory-verifier';
import {
  addablePackages,
  assertChannelGroup,
  commitChannelGroup,
  createChannelGroup,
  decodeChannelCommit,
  decodeChannelGroupState,
  encodeChannelGroupState,
  eraseMlsSecrets,
  exportChannelKey,
  generateMemberPackage,
  groupLeaves,
  joinChannelGroup,
  processChannelCommit,
  readMemberPackage,
  treeAuthMap,
  type ChannelGroupCommitResult,
  type DecodedChannelCommit,
  type EpochKeyPackage,
} from './mls-crypto';
import {
  CLIENT_REJOIN_LIMIT,
  EMPTY_TRANSCRIPT,
  MEMBER_PACKAGE_REUSE_MS,
  assertChainLink,
  assertEnvelopeStructure,
  assertGroupAfterChain,
  assertKeyRecipientState,
  assertTreeMatchesRoster,
  computeGroupKeyCommitment,
  genesisRoster,
  groupGenesis,
  isGroupEquivocation,
  nextRoster,
  recentRejoins,
  rosterUsers,
  usersToVerify,
  type ChainRecord,
  type LocalGroupRecord,
  type PendingGroupRecord,
  type PreviousGroupView,
  type RejoinRecord,
} from './mls-group-model';
import {
  deleteSecurityState,
  fromBase64,
  listSecurityStateNames,
  readSecurityState,
  sha256,
  toBase64,
  writeSecurityState,
} from './security-storage';

// Continuous channel groups (group protocol 4), DESIGN §6. Every change to a
// channel's local group runs under one Web Lock per device and channel and
// reads the group from storage after acquiring it; no ClientState outlives
// the lock. Envelope checks that show the server or a committer contradicting
// verified history stop with an equivocation error; an envelope that is
// correctly signed but cannot be processed makes this device ask to be added
// again (rejoin).

/** Reads of the server's state one key request makes before it gives up. */
const MAX_KEY_ATTEMPTS = 6;
/** One commits page; the server sends at most this many. */
const COMMIT_PAGE = 16;
/** Pages one sync reads before it asks the caller to try again. */
const MAX_CATCH_UP_PAGES = 64;
/** Own packages kept so a join can still use one that was consumed. */
const MAX_LOCAL_PACKAGES = 3;
/** Background commits of pending additions wait this long, at random, so devices do not race. */
const ADDITION_DELAY_MIN_MS = 2_000;
const ADDITION_DELAY_MAX_MS = 20_000;

export type GroupSyncResult =
  | { status: 'ready'; version: number }
  | { status: 'waiting'; rejoining: boolean }
  /** This device's view changed (removed, or the server moved on); read the state again. */
  | { status: 'removed' }
  /** The server has no group for this channel yet. */
  | { status: 'none' };

export type GroupCommitResult =
  | { status: 'committed'; version: number }
  | { status: 'noop' }
  /** The local group is not at the state's version; read the state again. */
  | { status: 'stale' }
  | { status: 'conflict'; reason: string | null };

/**
 * What the key is for. Writers commit due removals and refreshes before they
 * seal anything; readers only catch up and leave those to writers [live-5].
 */
export type ChannelKeyPurpose = 'write' | 'read';

/**
 * This device asked to be added again too often. Waiting no longer helps;
 * the conversation's managers can start it again.
 */
export class ChannelGroupUnavailableError extends Error {
  readonly code = 'CHANNEL_GROUP_UNAVAILABLE';

  constructor() {
    super('CHANNEL_GROUP_UNAVAILABLE');
    this.name = 'ChannelGroupUnavailableError';
  }
}

/** The server's view moved on while a group change was prepared; read the state again. */
export class ChannelGroupChangedError extends Error {
  readonly code = 'CHANNEL_GROUP_CHANGED';

  constructor() {
    super('CHANNEL_GROUP_CHANGED');
    this.name = 'ChannelGroupChangedError';
  }
}

/** A first group cannot be made yet: other devices still have to publish their packages. */
export class ChannelGroupNotReadyError extends Error {
  readonly code = 'CHANNEL_GROUP_NOT_READY';

  constructor() {
    super('CHANNEL_GROUP_NOT_READY');
    this.name = 'ChannelGroupNotReadyError';
  }
}

interface LocalMemberPackage {
  packageId: string;
  material: EpochKeyPackage;
  createdAt: number;
  signature: string;
  rejoin: boolean;
  /** The server refused it as already used; it may have added this device. */
  consumed?: boolean;
  /** False until the server accepted it; no Welcome can use a package it never had. */
  published?: boolean;
}

interface MemberPackageRecord {
  packages: LocalMemberPackage[];
}

interface GroupWork {
  channelId: string;
  owner: { userId: string; deviceId: string };
  scope: ChannelKeyScopeToken;
}

const names = {
  group: (channelId: string) => `mls-group:${channelId}`,
  chain: (channelId: string) => `mls-chain:${channelId}`,
  pending: (channelId: string) => `mls-group-pending:${channelId}`,
  packages: (channelId: string) => `mls-member-package:${channelId}`,
  rejoins: (channelId: string) => `mls-rejoin:${channelId}`,
  key: (channelId: string, version: number) => `mls-key:${channelId}:${version}`,
  legacyHead: (channelId: string) => `mls-head:${channelId}`,
};

function groupWork(channelId: string, scope: ChannelKeyScopeToken): GroupWork {
  const device = getActiveDevice();
  return { channelId, owner: { userId: device.userId, deviceId: device.deviceId }, scope };
}

async function withGroupLock<T>(work: GroupWork, run: () => Promise<T>): Promise<T> {
  return await navigator.locks.request(`alparts-mls-group:${work.owner.deviceId}:${work.channelId}`, run);
}

async function save(work: GroupWork, name: string, value: unknown): Promise<void> {
  await writeSecurityState(work.owner, name, value, work.scope);
}

async function read<T>(work: GroupWork, name: string): Promise<T | null> {
  const value = await readSecurityState<T>(work.owner, name);
  channelKeyScopes.assertCurrent(work.scope);
  return value;
}

/** Diagnostics for developers; never shown in the UI. */
function logGroupEvent(event: string, details: Record<string, unknown>): void {
  console.warn(`[alparts] ${event}`, details);
}

const keyListeners = new Set<(channelId: string, version: number) => void>();

/** Called after this device has the key of a newer version of a channel. */
export function onChannelGroupAdvanced(listener: (channelId: string, version: number) => void): () => void {
  keyListeners.add(listener);
  return () => keyListeners.delete(listener);
}

function notifyAdvanced(channelId: string, version: number): void {
  for (const listener of keyListeners) {
    try {
      listener(channelId, version);
    } catch {
      // A listener's failure must not undo the saved version.
    }
  }
}

function minStart(current: number | null | undefined, genesis: number): number {
  return current === null || current === undefined ? genesis : Math.min(current, genesis);
}

// === Local records ===

/**
 * The chain pin. A device that followed the channel before group protocol 4
 * starts from its pinned v3 head. Until it verifies a v4 genesis the pin
 * follows that head, which still moves when an older epoch is derived late,
 * so the genesis is checked against the newest v3 envelope verified here.
 */
async function readChain(work: GroupWork): Promise<ChainRecord | null> {
  const chain = await read<ChainRecord>(work, names.chain(work.channelId));
  if (chain && chain.v4Start !== null) return chain;
  const legacy = await read<{ version: number; transcript: string }>(work, names.legacyHead(work.channelId));
  if (!legacy || (chain && legacy.version <= chain.version)) return chain;
  const next: ChainRecord = { version: legacy.version, transcript: legacy.transcript, v4Start: null, genesisVersion: null };
  await save(work, names.chain(work.channelId), next);
  return next;
}

/**
 * Group protocol 3 packages and proposals for versions after the last v3
 * version can never give a v3 key: such a version belongs to v4 or was
 * never activated. They are deleted so that nobody can build a v3 epoch
 * for a v4 version from them [sec-7]. Older ones stay until the epoch they
 * belong to is derived, so v3 history this device has not read yet stays
 * readable.
 */
async function dropLegacyPackages(work: GroupWork, lastLegacyVersion: number): Promise<void> {
  for (const prefix of [`mls-package:${work.channelId}:`, `mls-proposal:${work.channelId}:`]) {
    for (const name of await listSecurityStateNames(work.owner, prefix, 256)) {
      const version = Number(name.slice(prefix.length));
      if (!Number.isSafeInteger(version) || version > lastLegacyVersion) await deleteSecurityState(work.owner, name);
    }
  }
}

async function persistVersionKey(
  work: GroupWork,
  version: number,
  raw: Uint8Array,
  transcript: string,
  keyCommitment: string,
): Promise<void> {
  await save(work, names.key(work.channelId, version), { raw: toBase64(raw), transcript });
  await storeGroupVersionKey(work.channelId, version, raw, keyCommitment, work.scope);
}

/**
 * Save one verified version: its key first (archive record, CryptoKey,
 * commitment, recovery backup), then the group, then the chain pin. A crash
 * in between redoes the step from the older record.
 */
async function adoptVersion(
  work: GroupWork,
  record: LocalGroupRecord,
  raw: Uint8Array,
  keyCommitment: string,
  chain: ChainRecord | null,
): Promise<ChainRecord> {
  await persistVersionKey(work, record.version, raw, record.transcript, keyCommitment);
  await save(work, names.group(work.channelId), record);
  const next: ChainRecord = {
    version: record.version,
    transcript: record.transcript,
    v4Start: minStart(chain?.v4Start, record.genesisVersion),
    genesisVersion: record.genesisVersion,
  };
  await save(work, names.chain(work.channelId), next);
  notifyAdvanced(work.channelId, record.version);
  return next;
}

/** Pin a verified envelope this device does not continue from (it was removed or replaced). */
async function pinLeftVersion(work: GroupWork, chain: ChainRecord | null, record: MlsGroupCommitRecord): Promise<ChainRecord> {
  const genesisVersion = groupGenesis(record.envelope);
  const next: ChainRecord = {
    version: record.version,
    transcript: record.transcript,
    v4Start: minStart(chain?.v4Start, genesisVersion),
    genesisVersion,
    left: true,
  };
  await save(work, names.chain(work.channelId), next);
  return next;
}

async function loadGroupView(work: GroupWork): Promise<{ local: LocalGroupRecord | null; chain: ChainRecord | null }> {
  let chain = await readChain(work);
  let local = await read<LocalGroupRecord>(work, names.group(work.channelId));
  if (local && chain && (
    chain.version > local.version
    || (chain.version === local.version && chain.transcript !== local.transcript)
  )) {
    // The pin moved past this group only after the group record was deleted;
    // an older record left behind is not used again.
    await deleteSecurityState(work.owner, names.group(work.channelId));
    local = null;
  }
  if (local && (!chain || chain.version < local.version)) {
    chain = {
      version: local.version,
      transcript: local.transcript,
      v4Start: minStart(chain?.v4Start, local.genesisVersion),
      genesisVersion: local.genesisVersion,
    };
    await save(work, names.chain(work.channelId), chain);
  }
  // An own envelope at or below the verified version was settled (adopted,
  // or another envelope won); its saved state and key are not kept.
  const pending = await read<PendingGroupRecord>(work, names.pending(work.channelId));
  if (pending && pending.version <= (local?.version ?? chain?.version ?? 0)) {
    await deleteSecurityState(work.owner, names.pending(work.channelId));
  }
  if (!local) return { local, chain };
  if (!await read(work, names.key(work.channelId, local.version))) {
    // The group was saved, but its version key was not: derive it again.
    const state = decodeChannelGroupState(local.state);
    let raw: Uint8Array | null = null;
    try {
      raw = await exportChannelKey(state, local.groupId, local.version);
      await persistVersionKey(work, local.version, raw, local.transcript, await computeGroupKeyCommitment(raw));
    } finally {
      raw?.fill(0);
      eraseMlsSecrets(state);
    }
  }
  return { local, chain };
}

async function readPackages(work: GroupWork): Promise<MemberPackageRecord> {
  const record = await read<MemberPackageRecord>(work, names.packages(work.channelId));
  return { packages: Array.isArray(record?.packages) ? record.packages : [] };
}

/** A join or an own genesis used this package: forget it and every older one. */
async function forgetPackage(work: GroupWork, packageId: string): Promise<void> {
  const record = await readPackages(work);
  const index = record.packages.findIndex((candidate) => candidate.packageId === packageId);
  if (index < 0) return;
  await save(work, names.packages(work.channelId), { packages: record.packages.slice(index + 1) });
}

function latestPackage(record: MemberPackageRecord): LocalMemberPackage | undefined {
  return record.packages[record.packages.length - 1];
}

/** Unused and not yet due for replacement. */
function reusablePackage(pkg: LocalMemberPackage | undefined, now: number): pkg is LocalMemberPackage {
  return Boolean(pkg && !pkg.consumed && now - pkg.createdAt <= MEMBER_PACKAGE_REUSE_MS);
}

/**
 * The server already holds this device's newest package as one a member can
 * add: it lists the device as waiting, and the stored package was accepted,
 * is unused and is not due for replacement. Sending it again would change
 * nothing; callers that poll skip it, so no request is repeated every few
 * seconds while the device waits.
 */
async function packageListed(work: GroupWork, state: ChannelKeyRecipientState, rejoin: boolean): Promise<boolean> {
  if (!state.pendingAddDeviceIds.includes(work.owner.deviceId)) return false;
  const latest = latestPackage(await readPackages(work));
  return reusablePackage(latest, Date.now()) && latest.published !== false && (!rejoin || latest.rejoin);
}

/** `deferred`: the server asked to slow down; the package goes out on a later attempt. */
type PublishOutcome = 'published' | 'member' | 'consumed' | 'ineligible' | 'deferred';

/**
 * Publish this device's package for the channel. A stored package is sent
 * again while it is younger than six days and unconsumed; its private part
 * is kept until a join from it succeeded. `fresh` asks for a new one.
 */
async function publishPackage(work: GroupWork, options: { rejoin: boolean; fresh?: boolean }): Promise<PublishOutcome> {
  const record = await readPackages(work);
  let fresh = Boolean(options.fresh);
  for (let attempt = 0; attempt < 2; attempt++) {
    let current = latestPackage(record);
    const now = Date.now();
    if (fresh || !reusablePackage(current, now)) {
      const material = await generateMemberPackage(work.owner.deviceId);
      const packageId = crypto.randomUUID();
      // ECDSA signatures differ every time: keep the one that is published.
      const signature = await signDevicePayload(serializeMlsMemberPackage(work.channelId, {
        deviceId: work.owner.deviceId,
        packageId,
        keyPackage: material.publicPackage,
      }));
      current = { packageId, material, createdAt: now, signature, rejoin: options.rejoin, published: false };
      record.packages = [...record.packages, current].slice(-MAX_LOCAL_PACKAGES);
      await save(work, names.packages(work.channelId), record);
      fresh = false;
    }
    try {
      await api.publishMemberPackage(work.channelId, {
        packageId: current.packageId,
        keyPackage: current.material.publicPackage,
        signature: current.signature,
        ...(options.rejoin ? { rejoin: true } : {}),
      });
      channelKeyScopes.assertCurrent(work.scope);
      if (current.rejoin !== options.rejoin || current.published !== true) {
        current.rejoin = options.rejoin;
        current.published = true;
        await save(work, names.packages(work.channelId), record);
      }
      return 'published';
    } catch (error) {
      channelKeyScopes.assertCurrent(work.scope);
      if (!(error instanceof ApiError)) throw error;
      if (error.status === 429) return 'deferred';
      if (error.status === 409 && error.reason === 'ALREADY_MEMBER') return 'member';
      if (error.status === 409 && error.reason === 'PACKAGE_CONSUMED') {
        current.consumed = true;
        await save(work, names.packages(work.channelId), record);
        return 'consumed';
      }
      if (error.status === 409 && error.reason === 'PACKAGE_KEY_CONFLICT') {
        fresh = true;
        continue;
      }
      if (error.status === 409 && error.reason === 'REJOIN_LIMIT') throw new ChannelGroupUnavailableError();
      if (error.status === 403 && error.reason === 'DEVICE_APPROVAL_REQUIRED') return 'ineligible';
      throw error;
    }
  }
  return 'consumed';
}

// === Envelope verification ===

function activeAt(
  trusted: VerifiedDirectory['devices'][string] | undefined,
  sequence: number,
): boolean {
  return Boolean(
    trusted
    && trusted.approvedSequence !== null
    && trusted.approvedSequence <= sequence
    && (trusted.revokedSequence === null || trusted.revokedSequence > sequence),
  );
}

/**
 * Check members, added devices and the committer against each user's
 * directory at the envelope's head, and return the directories read.
 */
async function verifyEnvelopeDirectory(
  work: GroupWork,
  envelope: MlsGroupCommit,
  previousHeads: readonly DirectoryHead[] | null,
): Promise<{ committerIdentityKey: string; directories: Map<string, VerifiedDirectory> }> {
  const heads = new Map(envelope.directoryHeads.map((head) => [head.userId, head]));
  const directories = new Map<string, VerifiedDirectory>();
  for (const userId of usersToVerify(previousHeads, envelope)) {
    const head = heads.get(userId);
    if (!head) throw new Error('DIRECTORY_INVALID');
    const directory = await verifiedDirectory(userId, work.channelId, head);
    channelKeyScopes.assertCurrent(work.scope);
    directories.set(userId, directory);
    for (const member of envelope.members) {
      if (member.userId === userId && !activeAt(directory.devices[member.deviceId], head.sequence)) {
        throw new Error('DIRECTORY_INVALID');
      }
    }
    for (const entry of envelope.added) {
      if (entry.userId === userId && directory.devices[entry.deviceId]?.identityKey !== entry.identityKey) {
        throw new Error('DIRECTORY_INVALID');
      }
    }
  }
  const committer = envelope.members.find((member) => member.deviceId === envelope.committerDeviceId);
  const committerIdentityKey = committer
    ? directories.get(committer.userId)?.devices[committer.deviceId]?.identityKey
    : undefined;
  if (!committerIdentityKey) throw new Error('DIRECTORY_INVALID');
  return { committerIdentityKey, directories };
}

async function verifyMemberPackageEntry(channelId: string, entry: MlsMemberPackage): Promise<string> {
  if (!await verifyDevicePayload(serializeMlsMemberPackage(channelId, entry), entry.signature, entry.identityKey)) {
    throw new Error('INVALID_MLS_SIGNATURE');
  }
  let info;
  try {
    info = readMemberPackage(entry.keyPackage);
  } catch {
    throw new Error('INVALID_MLS_ROSTER');
  }
  if (info.identity !== entry.deviceId) throw new Error('INVALID_MLS_ROSTER');
  return info.signatureKey;
}

/**
 * Every check of a signed envelope that needs no group secrets (§6.3 a).
 * `previous` is the verified view the envelope continues, or null when this
 * device joins at it.
 */
async function verifyEnvelope(
  work: GroupWork,
  record: MlsGroupCommitRecord,
  previous: PreviousGroupView | null,
  chain: ChainRecord | null,
): Promise<{ decoded: DecodedChannelCommit; directories: Map<string, VerifiedDirectory>; addedKeys: Map<string, string> }> {
  const envelope = record.envelope;
  if (
    !envelope
    || record.version !== envelope.version
    || await sha256(serializeMlsGroupCommit(envelope)) !== record.transcript
  ) throw new Error('INVALID_MLS_TRANSCRIPT');
  let decoded: DecodedChannelCommit;
  try {
    decoded = decodeChannelCommit(envelope.commit);
  } catch {
    throw new Error('INVALID_MLS_GROUP');
  }
  assertEnvelopeStructure(work.channelId, envelope, decoded, previous);
  assertChainLink(chain, envelope, record.transcript);
  const { committerIdentityKey, directories } = await verifyEnvelopeDirectory(
    work,
    envelope,
    previous && envelope.kind === 'commit' ? previous.directoryHeads : null,
  );
  const addedKeys = new Map<string, string>();
  for (const entry of envelope.added) {
    addedKeys.set(entry.deviceId, await verifyMemberPackageEntry(work.channelId, entry));
  }
  if (!await verifyDevicePayload(serializeMlsGroupCommit(envelope), envelope.signature, committerIdentityKey)) {
    throw new Error('INVALID_MLS_SIGNATURE');
  }
  return { decoded, directories, addedKeys };
}

async function fetchRecord(work: GroupWork, version: number): Promise<MlsGroupCommitRecord | null> {
  const records = await api.getGroupCommits(work.channelId, version - 1, 1);
  channelKeyScopes.assertCurrent(work.scope);
  const record = records[0];
  if (!record) return null;
  if (record.version !== version) throw new Error('INVALID_MLS_TRANSCRIPT');
  return record;
}

// === Own envelopes ===

/**
 * The server's envelope at the pending version decides: the same transcript
 * means the server accepted this device's own envelope, so its saved state
 * is adopted (ts-mls cannot process an own path commit); anything else means
 * the envelope lost and is discarded.
 */
async function settlePending(
  work: GroupWork,
  pending: PendingGroupRecord,
  record: MlsGroupCommitRecord | null,
  local: LocalGroupRecord | null,
  chain: ChainRecord | null,
): Promise<{ local: LocalGroupRecord; chain: ChainRecord } | null> {
  const envelope = record?.envelope;
  const own = Boolean(
    record
    && envelope
    && record.transcript === pending.transcript
    && await sha256(serializeMlsGroupCommit(envelope)) === pending.transcript
    && envelope.version === pending.version
    && groupGenesis(envelope) === pending.genesisVersion
    && envelope.committerDeviceId === work.owner.deviceId
    && (pending.kind === 'create'
      ? envelope.kind === 'create'
      : envelope.kind === 'commit' && local?.genesisVersion === pending.genesisVersion && local.version === pending.version - 1),
  );
  if (!own || !envelope || !record) {
    await deleteSecurityState(work.owner, names.pending(work.channelId));
    return null;
  }
  assertChainLink(chain, envelope);
  assertGroupAfterChain(chain, pending.genesisVersion);
  const raw = fromBase64(pending.raw);
  try {
    if (await computeGroupKeyCommitment(raw) !== envelope.keyCommitment) {
      await deleteSecurityState(work.owner, names.pending(work.channelId));
      return null;
    }
    const next: LocalGroupRecord = {
      genesisVersion: pending.genesisVersion,
      groupId: envelope.groupId,
      version: envelope.version,
      epoch: envelope.epoch,
      transcript: record.transcript,
      members: envelope.members,
      directoryHeads: envelope.directoryHeads,
      state: pending.newState,
    };
    const nextChain = await adoptVersion(work, next, raw, envelope.keyCommitment, chain);
    await deleteSecurityState(work.owner, names.pending(work.channelId));
    if (envelope.kind === 'create') await forgetPackage(work, envelope.added[0].packageId);
    return { local: next, chain: nextChain };
  } finally {
    raw.fill(0);
  }
}

/**
 * An own first group or fresh start sent earlier without a known answer:
 * the server's envelope at its version decides. This device cannot read
 * that version when it was never in the group there, which means its own
 * envelope lost.
 */
async function settleOwnCreate(
  work: GroupWork,
  state: ChannelKeyRecipientState,
  chain: ChainRecord | null,
): Promise<{ local: LocalGroupRecord; chain: ChainRecord } | null> {
  const pending = await read<PendingGroupRecord>(work, names.pending(work.channelId));
  if (pending?.kind !== 'create' || pending.version > state.currentVersion) return null;
  return settlePending(work, pending, await fetchRecord(work, pending.version), null, chain);
}

async function submitOwnEnvelope(
  work: GroupWork,
  built: { envelope: MlsGroupCommit; transcript: string; result: ChannelGroupCommitResult; raw: Uint8Array },
  chain: ChainRecord | null,
  freshStart: boolean,
): Promise<{ local: LocalGroupRecord; chain: ChainRecord }> {
  const { envelope, transcript, result, raw } = built;
  const pending: PendingGroupRecord = {
    kind: envelope.kind,
    genesisVersion: groupGenesis(envelope),
    version: envelope.version,
    transcript,
    newState: encodeChannelGroupState(result.newState),
    raw: toBase64(raw),
  };
  // Saved before sending: after a lost response the accepted envelope is
  // recognized by its transcript and this exact state is adopted.
  await save(work, names.pending(work.channelId), pending);
  if (freshStart) {
    const freshStartSignature = await signDevicePayload(serializeChannelKeyFreshStart({
      channelId: work.channelId,
      keyVersion: envelope.version,
      keyCommitment: envelope.keyCommitment,
      deviceId: work.owner.deviceId,
    }));
    await api.submitGroupFreshStart(work.channelId, envelope, freshStartSignature);
  } else {
    await api.submitGroupCommit(work.channelId, envelope);
  }
  channelKeyScopes.assertCurrent(work.scope);
  const next: LocalGroupRecord = {
    genesisVersion: pending.genesisVersion,
    groupId: envelope.groupId,
    version: envelope.version,
    epoch: envelope.epoch,
    transcript,
    members: envelope.members,
    directoryHeads: envelope.directoryHeads,
    state: pending.newState,
  };
  const nextChain = await adoptVersion(work, next, raw, envelope.keyCommitment, chain);
  await deleteSecurityState(work.owner, names.pending(work.channelId));
  // The previous state's secrets are erased only now that the new state is kept.
  result.consumed.forEach((bytes) => bytes.fill(0));
  return { local: next, chain: nextChain };
}

async function signEnvelope(
  work: GroupWork,
  unsigned: Omit<MlsGroupCommit, 'signature'>,
): Promise<{ envelope: MlsGroupCommit; transcript: string }> {
  const envelope: MlsGroupCommit = {
    ...unsigned,
    signature: await signDevicePayload(serializeMlsGroupCommit(unsigned)),
  };
  channelKeyScopes.assertCurrent(work.scope);
  return { envelope, transcript: await sha256(serializeMlsGroupCommit(envelope)) };
}

/** Current directory heads of a roster's users, as the server requires them. */
async function currentHeads(work: GroupWork, userIds: readonly string[]): Promise<DirectoryHead[]> {
  const heads: DirectoryHead[] = [];
  for (const userId of userIds) {
    heads.push((await verifiedDirectory(userId, work.channelId)).head);
    channelKeyScopes.assertCurrent(work.scope);
  }
  return heads;
}

/**
 * Packages another member published that this device can add: the device
 * is active in its user's current directory with the same identity key, the
 * package is signed by it and names it, and its keys and lifetime suit the
 * tree. Anything else is skipped and can be added by a later commit.
 */
async function addableCandidates(
  work: GroupWork,
  candidates: readonly MlsMemberPackage[],
  state: ClientState | null,
  reservedKeys: readonly string[] = [],
): Promise<MlsMemberPackage[]> {
  const verified: MlsMemberPackage[] = [];
  const directories = new Map<string, VerifiedDirectory | null>();
  const seen = new Set<string>();
  for (const candidate of candidates) {
    if (seen.has(candidate.deviceId) || candidate.deviceId === work.owner.deviceId) continue;
    seen.add(candidate.deviceId);
    if (!directories.has(candidate.userId)) {
      directories.set(candidate.userId, await verifiedDirectory(candidate.userId, work.channelId).catch(() => null));
      channelKeyScopes.assertCurrent(work.scope);
    }
    const trusted = directories.get(candidate.userId)?.devices[candidate.deviceId];
    if (!trusted || trusted.identityKey !== candidate.identityKey || !deviceMeetsPolicy(trusted, 'active')) continue;
    try {
      await verifyMemberPackageEntry(work.channelId, candidate);
    } catch {
      continue;
    }
    verified.push(candidate);
  }
  const reserved = new Set(reservedKeys);
  const usable = new Set(addablePackages(state, verified.map((candidate) => candidate.keyPackage))
    .filter((encoded) => {
      const info = readMemberPackage(encoded);
      return ![info.initKey, info.encryptionKey, info.signatureKey].some((key) => reserved.has(key));
    }));
  return verified.filter((candidate) => usable.has(candidate.keyPackage));
}

function isLifetimeError(error: unknown): boolean {
  return error instanceof Error && /Lifetime/.test(error.message);
}

/** Publish the creator's package; anything but acceptance means the state must be read again or waited for. */
async function publishForCreate(work: GroupWork, rejoin: boolean): Promise<void> {
  const published = await publishPackage(work, { rejoin });
  // Consumed: another device's group already added this one.
  if (published === 'member' || published === 'consumed') throw new ChannelGroupChangedError();
  if (published !== 'published') throw new ChannelGroupNotReadyError();
}

/**
 * Create the channel's first group, or (fresh start) replace a group this
 * device cannot use, with every package this device can verify.
 */
async function createLocked(work: GroupWork, state: ChannelKeyRecipientState, freshStart: boolean): Promise<number> {
  const { local, chain } = await loadGroupView(work);
  const version = state.nextVersion;
  const previousVersion = state.currentVersion;
  let previousTranscript = EMPTY_TRANSCRIPT;
  if (freshStart) {
    if (!state.group) throw new Error('INVALID_MLS_GROUP');
    // Only a device the server lets start over does so; any other attempt
    // would leave a request to be added again behind for nothing [live-6].
    if (!state.historyRecoveryRequired) throw new ChannelGroupChangedError();
    previousTranscript = state.group.transcript;
  } else if (state.group) {
    throw new Error('INVALID_MLS_GROUP');
  } else {
    // A device that verified a continuous group never goes back to none.
    if (local || chain?.v4Start != null) throw new Error('MLS_DOWNGRADE');
    if (previousVersion > 0 && state.protocolVersion === 3) {
      previousTranscript = await api.getLegacyEpochTranscript(work.channelId, previousVersion);
      channelKeyScopes.assertCurrent(work.scope);
    }
    // The active version is the last one before group protocol 4.
    await dropLegacyPackages(work, previousVersion);
  }
  if (!/^[a-f0-9]{64}$/.test(previousTranscript) || version <= previousVersion) {
    throw new Error('INVALID_MLS_TRANSCRIPT');
  }
  // A new genesis continues the history this device verified.
  assertChainLink(chain, { version, previousVersion, previousTranscript });
  if (local && local.version > previousVersion) throw new Error('INVALID_MLS_TRANSCRIPT');

  // A member asks to be added again only when it holds no usable group.
  const rejoin = Boolean(state.ownMembership) && !local;
  // A package the server already lists is not sent again.
  const listedBefore = await packageListed(work, state, rejoin);
  if (!listedBefore) await publishForCreate(work, rejoin);
  // A migrated channel's first group waits for the earlier members' packages.
  if (!freshStart && state.genesisWaiting.some((deviceId) => deviceId !== work.owner.deviceId)) {
    throw new ChannelGroupNotReadyError();
  }
  let own = latestPackage(await readPackages(work));
  let listed = await api.getPendingMemberPackages(work.channelId);
  channelKeyScopes.assertCurrent(work.scope);
  const ownListed = () => {
    const entry = listed.find((candidate) => candidate.deviceId === work.owner.deviceId);
    return entry && own && entry.packageId === own.packageId && entry.keyPackage === own.material.publicPackage
      ? entry
      : null;
  };
  if (!ownListed() && listedBefore) {
    // The server holds another package of this device: send the stored one.
    await publishForCreate(work, rejoin);
    own = latestPackage(await readPackages(work));
    listed = await api.getPendingMemberPackages(work.channelId);
    channelKeyScopes.assertCurrent(work.scope);
  }
  const ownEntry = ownListed();
  // The server does not count this device's package as valid yet.
  if (!ownEntry || !own) throw new ChannelGroupNotReadyError();
  const ownInfo = readMemberPackage(own.material.publicPackage);
  const others = await addableCandidates(
    work,
    listed,
    null,
    [ownInfo.initKey, ownInfo.encryptionKey, ownInfo.signatureKey],
  );
  const added: MlsMemberPackage[] = [ownEntry, ...others];
  const authMap = new Map(added.map((entry) => [entry.deviceId, readMemberPackage(entry.keyPackage).signatureKey]));
  const groupId = mlsGroupId(work.channelId, version);
  let result: ChannelGroupCommitResult;
  try {
    result = await createChannelGroup(groupId, own.material, others.map((entry) => entry.keyPackage), authMap);
  } catch (error) {
    if (!isLifetimeError(error)) throw error;
    // A package expired while this commit was made; the next attempt skips it.
    throw new ChannelGroupNotReadyError();
  }
  let raw: Uint8Array | null = null;
  try {
    raw = await exportChannelKey(result.newState, groupId, version);
    const members = genesisRoster(added);
    assertChannelGroup(result.newState, groupId, 1);
    assertTreeMatchesRoster(groupLeaves(result.newState), members, authMap);
    const { envelope, transcript } = await signEnvelope(work, {
      channelId: work.channelId,
      version,
      previousVersion,
      previousTranscript,
      groupId,
      epoch: 1,
      kind: 'create',
      keyCommitment: await computeGroupKeyCommitment(raw),
      commit: result.commit,
      welcome: result.welcome,
      added,
      removed: [],
      members,
      directoryHeads: await currentHeads(work, rosterUsers(members)),
      committerDeviceId: work.owner.deviceId,
    });
    await submitOwnEnvelope(work, { envelope, transcript, result, raw }, chain, freshStart);
    await forgetPackage(work, own.packageId);
    return version;
  } finally {
    raw?.fill(0);
    // Kept only as the encoded record (adopted, or pending until a sync settles it).
    eraseMlsSecrets(result.newState);
  }
}

/**
 * Commit what is due on the current group: required removes, rejoins and
 * additions this device can verify, or an empty commit that refreshes the
 * group key and this device's own leaf.
 */
async function commitLocked(work: GroupWork, state: ChannelKeyRecipientState): Promise<GroupCommitResult> {
  const { local, chain } = await loadGroupView(work);
  if (
    !local
    || !state.group
    || !state.canCommit
    || local.version !== state.currentVersion
    || local.genesisVersion !== state.group.genesisVersion
  ) return { status: 'stale' };
  const memberLeaf = new Map(local.members.map((member) => [member.deviceId, member.leafIndex]));
  if (!memberLeaf.has(work.owner.deviceId) || state.requiredRemoveDeviceIds.some((id) => !memberLeaf.has(id))) {
    return { status: 'stale' };
  }
  const groupState = decodeChannelGroupState(local.state);
  // Additions are optional: packages that cannot be read or verified now
  // wait for a later commit and never hold up a removal [live-4].
  const pendingIds = new Set(state.pendingAddDeviceIds);
  let candidates: MlsMemberPackage[] = [];
  if (pendingIds.size > 0) {
    try {
      const listed = (await api.getPendingMemberPackages(work.channelId)).filter((entry) => pendingIds.has(entry.deviceId));
      channelKeyScopes.assertCurrent(work.scope);
      candidates = await addableCandidates(work, listed, groupState);
    } catch (error) {
      channelKeyScopes.assertCurrent(work.scope);
      logGroupEvent('channel_group.additions_unavailable', {
        channelId: work.channelId,
        error: error instanceof Error ? error.message : 'unknown',
      });
    }
  }
  const refreshDue = state.updateRequired || state.ownLeafRefreshDue;
  let added: MlsMemberPackage[] = [];
  let removed: string[] = [];
  let result: ChannelGroupCommitResult | null = null;
  let authMap = new Map<string, string>();
  for (const withAdditions of [true, false]) {
    // A member that asked to be added again leaves and returns in one commit.
    const rejoining = withAdditions
      ? candidates.filter((entry) => memberLeaf.has(entry.deviceId)).map((entry) => entry.deviceId)
      : [];
    removed = [...new Set([...state.requiredRemoveDeviceIds, ...rejoining])].sort();
    // An Add-only commit carries no path and refreshes nothing: when a
    // refresh is due and nobody leaves, the empty commit goes first and the
    // additions follow in the next one.
    added = withAdditions && !(removed.length === 0 && refreshDue) ? candidates : [];
    if (added.length === 0 && removed.length === 0 && !refreshDue) return { status: 'noop' };
    const removeLeaves = removed.map((id) => memberLeaf.get(id)!);
    authMap = treeAuthMap(groupState, removeLeaves);
    for (const entry of added) authMap.set(entry.deviceId, readMemberPackage(entry.keyPackage).signatureKey);
    try {
      result = await commitChannelGroup(groupState, {
        add: added.map((entry) => entry.keyPackage),
        removeLeaves,
        authMap,
      });
      break;
    } catch (error) {
      if (added.length === 0) throw error;
      // ts-mls refused a package the checks here let through (its lifetime
      // ran out meanwhile, or anything else): commit what is due without
      // additions; a later commit adds them.
      logGroupEvent('channel_group.additions_refused', {
        channelId: work.channelId,
        error: error instanceof Error ? error.name : 'unknown',
      });
    }
  }
  if (!result) return { status: 'noop' };
  const version = local.version + 1;
  const epoch = local.epoch + 1;
  let raw: Uint8Array | null = null;
  try {
    raw = await exportChannelKey(result.newState, local.groupId, version);
    const members = nextRoster(local.members, removed, added);
    assertChannelGroup(result.newState, local.groupId, epoch);
    assertTreeMatchesRoster(groupLeaves(result.newState), members, authMap);
    const { envelope, transcript } = await signEnvelope(work, {
      channelId: work.channelId,
      version,
      previousVersion: local.version,
      previousTranscript: local.transcript,
      groupId: local.groupId,
      epoch,
      kind: 'commit',
      keyCommitment: await computeGroupKeyCommitment(raw),
      commit: result.commit,
      welcome: result.welcome,
      added,
      removed,
      members,
      directoryHeads: await currentHeads(work, rosterUsers(members)),
      committerDeviceId: work.owner.deviceId,
    });
    try {
      await submitOwnEnvelope(work, { envelope, transcript, result, raw }, chain, false);
    } catch (error) {
      channelKeyScopes.assertCurrent(work.scope);
      if (error instanceof ApiError && error.status === 409) return { status: 'conflict', reason: error.reason };
      throw error;
    }
    return { status: 'committed', version };
  } finally {
    raw?.fill(0);
    // The new state lives on only as the encoded record (adopted, or pending
    // until a sync settles it); `consumed` is erased once it is adopted.
    eraseMlsSecrets(result.newState);
  }
}

// === Catch-up and joins ===

type CatchUpOutcome =
  | { kind: 'current'; local: LocalGroupRecord; chain: ChainRecord | null }
  /** Removed or replaced by a new group; `joinAt` when the same envelope adds this device. */
  | { kind: 'left'; chain: ChainRecord | null; joinAt?: MlsGroupCommitRecord }
  | { kind: 'unreadable'; version: number; committerDeviceId: string }
  /** The server did not return the next version; read the state again. */
  | { kind: 'stalled' };

async function catchUp(
  work: GroupWork,
  start: LocalGroupRecord,
  startChain: ChainRecord | null,
  target: number,
): Promise<CatchUpOutcome> {
  let local = start;
  let chain = startChain;
  for (let page = 0; local.version < target; page++) {
    if (page >= MAX_CATCH_UP_PAGES) return { kind: 'stalled' };
    const records = await api.getGroupCommits(work.channelId, local.version, COMMIT_PAGE);
    channelKeyScopes.assertCurrent(work.scope);
    if (records.length === 0) return { kind: 'stalled' };
    for (const record of records) {
      if (local.version >= target) break;
      if (record.version !== local.version + 1) throw new Error('INVALID_MLS_TRANSCRIPT');
      const pending = await read<PendingGroupRecord>(work, names.pending(work.channelId));
      if (pending && pending.version === record.version) {
        const adopted = await settlePending(work, pending, record, local, chain);
        if (adopted) {
          ({ local, chain } = adopted);
          continue;
        }
      }
      const envelope = record.envelope;
      const { decoded, addedKeys } = await verifyEnvelope(work, record, local, chain);
      const self = work.owner.deviceId;
      if (envelope.kind === 'create' || envelope.removed.includes(self)) {
        // Removed (or replaced by a fresh start): this group is never
        // processed again; keys already derived are kept.
        await deleteSecurityState(work.owner, names.group(work.channelId));
        if (envelope.added.some((entry) => entry.deviceId === self)) return { kind: 'left', chain, joinAt: record };
        return { kind: 'left', chain: await pinLeftVersion(work, chain, record) };
      }
      const unreadable = { kind: 'unreadable' as const, version: record.version, committerDeviceId: envelope.committerDeviceId };
      const state = decodeChannelGroupState(local.state);
      let processed: { newState: ClientState; consumed: Uint8Array[] } | null = null;
      let raw: Uint8Array | null = null;
      try {
        const authMap = treeAuthMap(state, decoded.removedLeaves);
        for (const [deviceId, signatureKey] of addedKeys) authMap.set(deviceId, signatureKey);
        try {
          processed = await processChannelCommit(state, envelope.commit, decoded, authMap);
          assertChannelGroup(processed.newState, envelope.groupId, envelope.epoch);
        } catch (error) {
          logGroupEvent('channel_group.unreadable_commit', {
            channelId: work.channelId,
            version: record.version,
            committerDeviceId: envelope.committerDeviceId,
            error: error instanceof Error ? error.name : 'unknown',
          });
          return unreadable;
        }
        const next = processed.newState;
        assertTreeMatchesRoster(groupLeaves(next), envelope.members, authMap);
        raw = await exportChannelKey(next, envelope.groupId, envelope.version);
        if (await computeGroupKeyCommitment(raw) !== envelope.keyCommitment) {
          logGroupEvent('channel_group.key_mismatch', {
            channelId: work.channelId,
            version: record.version,
            committerDeviceId: envelope.committerDeviceId,
          });
          return unreadable;
        }
        const nextLocal: LocalGroupRecord = {
          genesisVersion: local.genesisVersion,
          groupId: envelope.groupId,
          version: envelope.version,
          epoch: envelope.epoch,
          transcript: record.transcript,
          members: envelope.members,
          directoryHeads: envelope.directoryHeads,
          state: encodeChannelGroupState(next),
        };
        chain = await adoptVersion(work, nextLocal, raw, envelope.keyCommitment, chain);
        local = nextLocal;
      } finally {
        // Only the saved records outlive this envelope: the next one starts
        // from the stored state again.
        raw?.fill(0);
        eraseMlsSecrets(state);
        if (processed) {
          eraseMlsSecrets(processed.newState);
          processed.consumed.forEach((bytes) => bytes.fill(0));
        }
      }
    }
  }
  return { kind: 'current', local, chain };
}

type JoinOutcome =
  | { kind: 'joined'; local: LocalGroupRecord; chain: ChainRecord }
  /** This device has no usable package for the Welcome (lost state). */
  | { kind: 'lost'; version: number; committerDeviceId: string }
  | { kind: 'unreadable'; version: number; committerDeviceId: string };

/**
 * Join from the Welcome of the envelope that added this device. Members are
 * checked at the directory heads of that envelope, so a device revoked later
 * does not prevent joining at an older version; later commits remove it.
 */
async function joinAt(work: GroupWork, record: MlsGroupCommitRecord, chain: ChainRecord | null): Promise<JoinOutcome> {
  const envelope = record.envelope;
  const { directories } = await verifyEnvelope(work, record, null, chain);
  assertGroupAfterChain(chain, groupGenesis(envelope));
  const self = work.owner.deviceId;
  const failure = { version: envelope.version, committerDeviceId: envelope.committerDeviceId };
  const entryIndex = envelope.added.findIndex((entry) => entry.deviceId === self);
  if (entryIndex < 0) throw new Error('INVALID_MLS_ROSTER');
  // The creator has no Welcome of its own; without its saved state it starts over.
  if (envelope.kind === 'create' && entryIndex === 0) return { kind: 'lost', ...failure };
  const entry = envelope.added[entryIndex];
  const own = (await readPackages(work)).packages.find((candidate) => (
    candidate.packageId === entry.packageId && candidate.material.publicPackage === entry.keyPackage
  ));
  if (!own) return { kind: 'lost', ...failure };

  const rows = await api.getGroupMembers(work.channelId, envelope.version);
  channelKeyScopes.assertCurrent(work.scope);
  if (
    rows.length !== envelope.members.length
    || rows.some((row, index) => (
      row.deviceId !== envelope.members[index].deviceId
      || row.userId !== envelope.members[index].userId
      || row.leafIndex !== envelope.members[index].leafIndex
    ))
  ) throw new Error('INVALID_MLS_ROSTER');
  const heads = new Map(envelope.directoryHeads.map((head) => [head.userId, head]));
  const authMap = new Map<string, string>();
  for (const row of rows) {
    const head = heads.get(row.userId);
    let directory = directories.get(row.userId);
    if (!directory && head) {
      directory = await verifiedDirectory(row.userId, work.channelId, head);
      channelKeyScopes.assertCurrent(work.scope);
    }
    if (!head || directory?.devices[row.deviceId]?.identityKey !== row.identityKey) throw new Error('DIRECTORY_INVALID');
    authMap.set(row.deviceId, await verifyMemberPackageEntry(work.channelId, row));
  }
  for (const addedEntry of envelope.added) {
    const row = rows.find((candidate) => candidate.deviceId === addedEntry.deviceId);
    if (
      !row
      || row.packageId !== addedEntry.packageId
      || row.keyPackage !== addedEntry.keyPackage
      || row.signature !== addedEntry.signature
    ) throw new Error('INVALID_MLS_ROSTER');
  }

  let state: ClientState | null = null;
  let raw: Uint8Array | null = null;
  try {
    try {
      state = await joinChannelGroup(envelope.welcome, own.material, authMap);
      assertChannelGroup(state, envelope.groupId, envelope.epoch);
      // Only the committer chose what the Welcome holds; neither the server
      // nor other members could check it. A tree without the signed roster,
      // or with this device at another leaf, is handled like a Welcome that
      // cannot be opened: this device asks to be added again [sec-1].
      assertTreeMatchesRoster(groupLeaves(state), envelope.members, authMap);
      const ownMember = envelope.members.find((member) => member.deviceId === self);
      if (!ownMember || state.privatePath.leafIndex !== ownMember.leafIndex) throw new Error('INVALID_MLS_ROSTER');
    } catch (error) {
      logGroupEvent('channel_group.unreadable_welcome', {
        channelId: work.channelId,
        ...failure,
        error: error instanceof Error ? error.message : 'unknown',
      });
      return { kind: 'unreadable', ...failure };
    }
    raw = await exportChannelKey(state, envelope.groupId, envelope.version);
    if (await computeGroupKeyCommitment(raw) !== envelope.keyCommitment) {
      logGroupEvent('channel_group.key_mismatch', { channelId: work.channelId, ...failure });
      return { kind: 'unreadable', ...failure };
    }
    const local: LocalGroupRecord = {
      genesisVersion: groupGenesis(envelope),
      groupId: envelope.groupId,
      version: envelope.version,
      epoch: envelope.epoch,
      transcript: record.transcript,
      members: envelope.members,
      directoryHeads: envelope.directoryHeads,
      state: encodeChannelGroupState(state),
    };
    const nextChain = await adoptVersion(work, local, raw, envelope.keyCommitment, chain);
    await forgetPackage(work, own.packageId);
    return { kind: 'joined', local, chain: nextChain };
  } finally {
    raw?.fill(0);
    eraseMlsSecrets(state);
  }
}

/**
 * This device cannot use the group any more (§6.3 b): keep the keys it
 * derived, drop the group, and ask to be added again with a new package.
 * Only a request the server accepted counts towards the limit, once per
 * package: a request lost to the network is sent again with the package
 * already made for it.
 */
async function requestRejoin(
  work: GroupWork,
  state: ChannelKeyRecipientState,
  failure: { version: number; committerDeviceId: string },
): Promise<GroupSyncResult> {
  logGroupEvent('channel_group.rejoin', { channelId: work.channelId, ...failure });
  const now = Date.now();
  const counted = recentRejoins((await read<unknown[]>(work, names.rejoins(work.channelId))) ?? [], now);
  // Asked too often: waiting no longer helps, and nothing is changed.
  if (counted.length >= CLIENT_REJOIN_LIMIT) throw new ChannelGroupUnavailableError();
  await deleteSecurityState(work.owner, names.group(work.channelId));
  await deleteSecurityState(work.owner, names.pending(work.channelId));
  // A package the server never accepted cannot be in any Welcome: send it as it is.
  const latest = latestPackage(await readPackages(work));
  const unsent = Boolean(latest && latest.published === false && reusablePackage(latest, now));
  const outcome = await publishPackage(work, { rejoin: Boolean(state.ownMembership), fresh: !unsent });
  // The server's view differs from the state read before: read it again.
  if (outcome === 'member' || outcome === 'consumed') return { status: 'removed' };
  if (outcome === 'published') {
    const sent = latestPackage(await readPackages(work));
    if (sent && !counted.some((entry) => entry.packageId === sent.packageId)) {
      const next: RejoinRecord[] = [...counted, { time: now, packageId: sent.packageId }];
      await save(work, names.rejoins(work.channelId), next);
    }
  }
  return { status: 'waiting', rejoining: true };
}

async function syncLocked(work: GroupWork, initial: ChannelKeyRecipientState): Promise<GroupSyncResult> {
  let state = initial;
  let { local, chain } = await loadGroupView(work);
  const behind = (candidate: ChannelKeyRecipientState) => Boolean(
    (local && candidate.currentVersion < local.version) || (chain && candidate.currentVersion < chain.version),
  );
  if (behind(state)) {
    // Another tab may have moved on after this state was read; only a fresh
    // state that is still behind is a rollback.
    state = await api.getKeyRecipients(work.channelId);
    channelKeyScopes.assertCurrent(work.scope);
    if (behind(state)) throw new Error('INVALID_MLS_TRANSCRIPT');
  }
  if (!state.group) {
    // A device that verified a continuous group never goes back to none.
    if (local || chain?.v4Start != null) throw new Error('MLS_DOWNGRADE');
    return { status: 'none' };
  }
  if (local && state.group.genesisVersion < local.genesisVersion) throw new Error('INVALID_MLS_TRANSCRIPT');
  if (!local) assertGroupAfterChain(chain, state.group.genesisVersion);
  // Before its first continuous group this device drops v3 packages the
  // group's versions could be forged from; v3 versions before stay readable.
  if (!chain || chain.v4Start === null) await dropLegacyPackages(work, state.group.genesisVersion - 1);

  for (let round = 0; round < 4; round++) {
    if (!local) {
      const settled = await settleOwnCreate(work, state, chain);
      if (settled) ({ local, chain } = settled);
    }
    if (local) {
      const outcome = await catchUp(work, local, chain, state.currentVersion);
      if (outcome.kind === 'stalled') return { status: 'removed' };
      if (outcome.kind === 'unreadable') {
        // An own fresh start already replaced the group this device cannot
        // read: settle it instead of asking to be added again.
        const pending = await read<PendingGroupRecord>(work, names.pending(work.channelId));
        if (pending?.kind !== 'create' || pending.version !== state.group.genesisVersion) {
          return requestRejoin(work, state, outcome);
        }
        await deleteSecurityState(work.owner, names.group(work.channelId));
        local = null;
        continue;
      }
      if (outcome.kind === 'current') {
        local = outcome.local;
        chain = outcome.chain;
        return local.genesisVersion === state.group.genesisVersion && state.ownMembership
          ? { status: 'ready', version: local.version }
          : { status: 'removed' };
      }
      local = null;
      chain = outcome.chain;
      if (outcome.joinAt) {
        const joined = await joinAt(work, outcome.joinAt, chain);
        if (joined.kind !== 'joined') return requestRejoin(work, state, joined);
        ({ local, chain } = joined);
        continue;
      }
      // A membership from before this removal is out of date: read the state again.
      if (state.ownMembership && chain && state.ownMembership.joinedVersion <= chain.version) {
        return { status: 'removed' };
      }
    }

    if (!state.ownMembership) {
      if (await packageListed(work, state, false)) return { status: 'waiting', rejoining: false };
      const published = await publishPackage(work, { rejoin: false });
      return published === 'member' || published === 'consumed'
        ? { status: 'removed' }
        : { status: 'waiting', rejoining: false };
    }
    if (state.ownMembership.rejoinRequested) {
      if (!await packageListed(work, state, true)) {
        // Consumed: a member added this device again meanwhile.
        if (await publishPackage(work, { rejoin: true }) === 'consumed') return { status: 'removed' };
      }
      return { status: 'waiting', rejoining: true };
    }
    const joinedVersion = state.ownMembership.joinedVersion;
    if (chain && joinedVersion <= chain.version) {
      // A membership this device already followed past. After a verified
      // removal that is a rollback; otherwise its group record was lost.
      if (chain.left) throw new Error('INVALID_MLS_TRANSCRIPT');
      return requestRejoin(work, state, { version: joinedVersion, committerDeviceId: '' });
    }
    const record = await fetchRecord(work, joinedVersion);
    if (!record) return { status: 'removed' };
    const joined = await joinAt(work, record, chain);
    if (joined.kind !== 'joined') return requestRejoin(work, state, joined);
    ({ local, chain } = joined);
  }
  return { status: 'removed' };
}

// === Entry points ===

/**
 * Bring this device's group up to the server's current version (§6.4):
 * settle an own envelope sent earlier, catch up, join from a Welcome, or
 * publish a package and wait to be added.
 */
export async function syncChannelGroup(
  channelId: string,
  state: ChannelKeyRecipientState,
  scope: ChannelKeyScopeToken,
): Promise<GroupSyncResult> {
  const work = groupWork(channelId, scope);
  return withGroupLock(work, () => syncLocked(work, state));
}

/** A first group, or a fresh start of one (step-up). Returns the new version. */
export async function createChannelGroupVersion(
  channelId: string,
  state: ChannelKeyRecipientState,
  scope: ChannelKeyScopeToken,
  options: { freshStart?: boolean } = {},
): Promise<number> {
  const work = groupWork(channelId, scope);
  return withGroupLock(work, () => createLocked(work, state, Boolean(options.freshStart)));
}

/** Commit what is due on the current group (removes, rejoins, verified additions, refresh). */
export async function commitChannelGroupChanges(
  channelId: string,
  state: ChannelKeyRecipientState,
  scope: ChannelKeyScopeToken,
): Promise<GroupCommitResult> {
  const work = groupWork(channelId, scope);
  return withGroupLock(work, () => commitLocked(work, state));
}

/**
 * The version of this device's current group, and the lowest continuous
 * group it verified, without network or lock.
 */
export async function localGroupView(channelId: string): Promise<{ version: number | null; v4Start: number | null }> {
  const owner = getActiveDevice();
  const [local, chain] = await Promise.all([
    readSecurityState<LocalGroupRecord>(owner, names.group(channelId)),
    readSecurityState<ChainRecord>(owner, names.chain(channelId)),
  ]);
  return {
    version: local?.version ?? chain?.version ?? null,
    v4Start: chain?.v4Start ?? local?.genesisVersion ?? null,
  };
}

function isGroupStateConflict(error: unknown, reason?: string): boolean {
  return error instanceof ApiError && error.status === 409 && (reason === undefined || error.reason === reason);
}

/**
 * One attempt of ensureChannelGroupKey on a state read just before. Returns
 * the version whose key is used, or null to read the state again.
 */
async function keyVersionAttempt(
  channelId: string,
  scope: ChannelKeyScopeToken,
  state: ChannelKeyRecipientState,
  purpose: ChannelKeyPurpose,
  lastAttempt: boolean,
): Promise<number | null> {
  if (!state.group) {
    // A device that verified a continuous group never goes back to none.
    if ((await localGroupView(channelId)).v4Start !== null) throw new Error('MLS_DOWNGRADE');
    channelKeyScopes.assertCurrent(scope);
    if (!state.canCreate) throw new ChannelKeyDeliveryPendingError('waiting');
    try {
      await createChannelGroupVersion(channelId, state, scope);
    } catch (error) {
      channelKeyScopes.assertCurrent(scope);
      if (error instanceof ChannelGroupNotReadyError || isGroupStateConflict(error, 'GENESIS_WAITING')) {
        throw new ChannelKeyDeliveryPendingError('genesis-waiting');
      }
      if (!(error instanceof ChannelGroupChangedError || isGroupStateConflict(error))) throw error;
    }
    return null;
  }

  const synced = await syncChannelGroup(channelId, state, scope);
  channelKeyScopes.assertCurrent(scope);
  if (synced.status === 'waiting') {
    throw new ChannelKeyDeliveryPendingError(synced.rejoining ? 'rejoining' : 'waiting', state.historyRecoveryRequired);
  }
  // Another tab may have moved the group on: decide on a fresh state, so
  // nothing is sealed for an older version or checked against old lists.
  if (synced.status !== 'ready' || synced.version !== state.currentVersion) return null;
  if (purpose === 'read') return state.currentVersion;

  // Writes wait for these; additions never do and are committed in the background.
  const writesBlocked = state.requiredRemoveDeviceIds.length > 0 || state.updateRequired;
  if (state.canCommit && writesBlocked) {
    const committed = await commitChannelGroupChanges(channelId, state, scope);
    channelKeyScopes.assertCurrent(scope);
    if (committed.status === 'committed' || committed.status === 'stale') return null;
    // "Not required" can answer a refresh, never a removal the same state asks for.
    if (
      committed.status === 'conflict'
      && (committed.reason !== 'KEY_ROTATION_NOT_REQUIRED' || state.requiredRemoveDeviceIds.length > 0)
    ) return null;
  } else if (state.canCommit && state.ownLeafRefreshDue) {
    // Only this device's own leaf is old: writes are not blocked, so a
    // refresh that fails now is tried again on a later write.
    try {
      const committed = await commitChannelGroupChanges(channelId, state, scope);
      channelKeyScopes.assertCurrent(scope);
      if (committed.status === 'committed') return null;
      if (committed.status === 'conflict') {
        logGroupEvent('channel_group.refresh_deferred', { channelId, reason: committed.reason });
      }
    } catch (error) {
      channelKeyScopes.assertCurrent(scope);
      if (isGroupEquivocation(error)) throw error;
      logGroupEvent('channel_group.refresh_deferred', {
        channelId,
        error: error instanceof Error ? error.message : 'unknown',
      });
    }
  }

  // A member this device itself knows to be revoked is removed before
  // anything is sealed for the group, whatever the server lists [sec-3].
  const revoked = await revokedGroupMembers(channelId);
  channelKeyScopes.assertCurrent(scope);
  if (revoked.length > 0) {
    if (lastAttempt) throw new Error('DIRECTORY_INVALID');
    return null;
  }
  return state.currentVersion;
}

/**
 * The key of the channel's current version (§6.4): create the first group,
 * or catch this device's group up and, for writing, commit the removals and
 * refreshes the server asks for. A key for writing is returned only when
 * this device's own directory shows no member it knows to be revoked.
 * `loadKey` reads the key this device derived for a version.
 */
export async function ensureChannelGroupKey<K>(
  channelId: string,
  scope: ChannelKeyScopeToken,
  options: { purpose: ChannelKeyPurpose; loadKey: (version: number) => Promise<K | null> },
): Promise<{ key: K; version: number }> {
  for (let attempt = 0; attempt < MAX_KEY_ATTEMPTS; attempt += 1) {
    channelKeyScopes.assertCurrent(scope);
    const state = await api.getKeyRecipients(channelId);
    channelKeyScopes.assertCurrent(scope);
    assertKeyRecipientState(channelId, state);
    let version: number | null;
    try {
      version = await keyVersionAttempt(channelId, scope, state, options.purpose, attempt === MAX_KEY_ATTEMPTS - 1);
    } catch (error) {
      // Asked to be added again too often: earlier history stays readable
      // and sending waits; the managers can start the conversation again.
      if (error instanceof ChannelGroupUnavailableError) {
        throw new ChannelKeyDeliveryPendingError('unavailable', state.historyRecoveryRequired);
      }
      throw error;
    }
    if (version === null) continue;
    const key = await options.loadKey(version);
    channelKeyScopes.assertCurrent(scope);
    if (!key) throw new Error('Channel key is unavailable on this device');
    return { key, version };
  }
  throw new Error('Channel key state changed too many times; retry the operation');
}

/**
 * Members of this device's current group that its own verified directory
 * already shows as revoked. The server lists them as required removes; one
 * it does not list means the roster it serves is stale.
 */
export async function revokedGroupMembers(channelId: string): Promise<string[]> {
  const owner = getActiveDevice();
  const local = await readSecurityState<LocalGroupRecord>(owner, names.group(channelId));
  if (!local) return [];
  const revoked: string[] = [];
  for (const userId of rosterUsers(local.members)) {
    const directory = await cachedDirectory(userId);
    if (!directory) continue;
    for (const member of local.members) {
      if (member.userId === userId && directory.devices[member.deviceId]?.revoked) revoked.push(member.deviceId);
    }
  }
  return revoked;
}

// === Background work ===

let maintenanceTimer: ReturnType<typeof setTimeout> | null = null;
let maintenanceRunning: Promise<void> | null = null;
let maintenanceRequested = false;
const additionTimers = new Map<string, ReturnType<typeof setTimeout>>();

/**
 * Publish packages and commit pending membership changes for every channel
 * of every workspace this device sees (§6.4 background maintenance). Calls
 * are coalesced; failures are logged and never reach the UI.
 */
export function scheduleGroupMaintenance(delayMs = 500): void {
  maintenanceRequested = true;
  if (maintenanceTimer || maintenanceRunning) return;
  maintenanceTimer = setTimeout(() => {
    maintenanceTimer = null;
    void runMaintenance();
  }, delayMs);
}

/** Stop scheduled background work, e.g. when the signed-in device changes. */
export function cancelGroupMaintenance(): void {
  if (maintenanceTimer) clearTimeout(maintenanceTimer);
  maintenanceTimer = null;
  maintenanceRequested = false;
  for (const timer of additionTimers.values()) clearTimeout(timer);
  additionTimers.clear();
}

async function runMaintenance(): Promise<void> {
  if (maintenanceRunning) return;
  maintenanceRequested = false;
  maintenanceRunning = (async () => {
    let deviceId: string;
    try {
      deviceId = getActiveDevice().deviceId;
    } catch {
      return;
    }
    let cursor: string | null = null;
    for (let page = 0; page < 64; page++) {
      let work;
      try {
        work = await api.getPendingGroupWork(cursor);
      } catch (error) {
        logGroupEvent('channel_group.maintenance_failed', { error: error instanceof Error ? error.message : 'unknown' });
        return;
      }
      for (const channelId of work.needPackage) {
        try {
          if (getActiveDevice().deviceId !== deviceId) return;
          const groupWorkItem = groupWork(channelId, channelKeyScopes.capture(channelId));
          await withGroupLock(groupWorkItem, async () => {
            // A package the server reports as used added this device before;
            // the channel still needs a new one now.
            if (await publishPackage(groupWorkItem, { rejoin: false }) === 'consumed') {
              await publishPackage(groupWorkItem, { rejoin: false });
            }
          });
        } catch (error) {
          logGroupEvent('channel_group.package_failed', {
            channelId,
            error: error instanceof Error ? error.message : 'unknown',
          });
        }
      }
      for (const channelId of work.needCommit) scheduleAdditions(channelId, deviceId);
      cursor = work.cursor;
      if (!cursor) break;
    }
  })().finally(() => {
    maintenanceRunning = null;
    if (maintenanceRequested) scheduleGroupMaintenance();
  });
  await maintenanceRunning;
}

function scheduleAdditions(channelId: string, deviceId: string): void {
  if (additionTimers.has(channelId)) return;
  const delay = ADDITION_DELAY_MIN_MS + Math.floor(Math.random() * (ADDITION_DELAY_MAX_MS - ADDITION_DELAY_MIN_MS));
  additionTimers.set(channelId, setTimeout(() => {
    additionTimers.delete(channelId);
    void commitPendingWork(channelId, deviceId).catch((error) => {
      logGroupEvent('channel_group.commit_failed', {
        channelId,
        error: error instanceof Error ? error.message : 'unknown',
      });
    });
  }, delay));
}

/** After the random delay: commit only if the change is still pending and this device may commit. */
async function commitPendingWork(channelId: string, deviceId: string): Promise<void> {
  if (getActiveDevice().deviceId !== deviceId) return;
  const scope = channelKeyScopes.capture(channelId);
  const state = await api.getKeyRecipients(channelId);
  channelKeyScopes.assertCurrent(scope);
  assertKeyRecipientState(channelId, state);
  if (
    !state.group
    || !state.canCommit
    || (state.pendingAddDeviceIds.length === 0 && state.requiredRemoveDeviceIds.length === 0 && !state.updateRequired)
  ) return;
  const synced = await syncChannelGroup(channelId, state, scope);
  if (synced.status !== 'ready') return;
  await commitChannelGroupChanges(channelId, state, scope);
}
