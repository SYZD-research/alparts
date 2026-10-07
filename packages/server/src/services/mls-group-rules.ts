import { createHash } from 'node:crypto';
import {
  mlsGroupId,
  serializeMlsGroupCommit,
  type DirectoryHead,
  type MlsGroupCommit,
  type MlsGroupMember,
} from '@alparts/shared';
import type { DecodedGroupCommit, MemberPackageKeys } from '../security/mls-group-commit.js';

// Commit admission rules for continuous channel groups (group protocol 4).
// Everything here is a pure function of the envelope and a snapshot of the
// server state, so the rules are testable without a database. Errors that
// depend on state the client may have read earlier are 409 codes; INVALID_MLS
// (403) is reserved for envelopes that are invalid in every state.

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
/** A package must already be valid on a slower clock and stay valid while a commit is built. */
export const PACKAGE_NOT_BEFORE_MARGIN_MS = 10 * MINUTE;
export const PACKAGE_NOT_AFTER_MARGIN_MS = HOUR;
/** Writes stop when no commit has refreshed the group key with an UpdatePath for this long. */
export const PATH_REFRESH_INTERVAL_MS = 24 * HOUR;
/** A writer refreshes its own leaf at least this often. */
export const LEAF_REFRESH_INTERVAL_MS = 7 * 24 * HOUR;
/** A migrated channel waits this long for its earlier recipients' packages. */
export const GENESIS_WAIT_MS = 24 * HOUR;
export const FRESH_START_IDLE_MS = 72 * HOUR;
export const FRESH_START_REJOIN_WAIT_MS = 30 * MINUTE;
export const FRESH_START_STALL_MS = 15 * MINUTE;
export const COMMIT_RATE_WINDOW_MS = HOUR;
export const COMMIT_RATE_LIMIT = 60;
export const REJOIN_WINDOW_MS = 24 * HOUR;
export const REJOIN_LIMIT = 3;
export const LAST_SEEN_INTERVAL_MS = 10 * MINUTE;
export const EMPTY_TRANSCRIPT = '0'.repeat(64);

/**
 * The transcript names a version: hex SHA-256 of the signed fields. A retry
 * with the same transcript is the same commit (idempotent replay).
 */
export function groupCommitTranscript(commit: Omit<MlsGroupCommit, 'signature'>): string {
  return createHash('sha256').update(serializeMlsGroupCommit(commit)).digest('hex');
}

export interface EligibleDevice {
  id: string;
  userId: string;
  identityKey: string;
}

export interface GroupMemberState {
  deviceId: string;
  userId: string;
  leafIndex: number;
  joinedVersion: number;
  signatureKey: string;
  encryptionKey: string;
  /** Add-time package; its init key also stays reserved. Empty unless loaded for that check. */
  keyPackage: string;
  leafUpdatedAt: Date;
  lastSeenAt: Date;
  /** When the device was revoked, if it was. */
  revokedAt?: Date | null;
}

export interface MemberPackageState {
  deviceId: string;
  packageId: string;
  keyPackage: string;
  signature: string;
  initKey: string;
  encryptionKey: string;
  signatureKey: string;
  notBefore: Date;
  notAfter: Date;
  rejoin: boolean;
  createdAt: Date;
}

export interface RejoinRequestState {
  deviceId: string;
  requestedAt: Date;
  version: number;
}

export function isValidMemberPackage(
  pkg: Pick<MemberPackageState, 'notBefore' | 'notAfter'>,
  now: number,
): boolean {
  return pkg.notBefore.getTime() <= now - PACKAGE_NOT_BEFORE_MARGIN_MS
    && pkg.notAfter.getTime() >= now + PACKAGE_NOT_AFTER_MARGIN_MS;
}

/** Whether a package is valid now or will be later; a package that never is cannot be added. */
export function canBecomeValidMemberPackage(
  pkg: Pick<MemberPackageState, 'notBefore' | 'notAfter'>,
  now: number,
): boolean {
  const validFrom = Math.max(now, pkg.notBefore.getTime() + PACKAGE_NOT_BEFORE_MARGIN_MS);
  return validFrom + PACKAGE_NOT_AFTER_MARGIN_MS <= pkg.notAfter.getTime();
}

/** From when a member could add this package: published, and valid on a slower clock. */
export function packageAddableSince(pkg: Pick<MemberPackageState, 'notBefore' | 'createdAt'>): Date {
  const validFrom = pkg.notBefore.getTime() + PACKAGE_NOT_BEFORE_MARGIN_MS;
  return validFrom > pkg.createdAt.getTime() ? new Date(validFrom) : pkg.createdAt;
}

/**
 * When each current member asked to be added again. A request made before
 * the member's latest join was answered by that join and is closed.
 */
export function openRejoinRequests(
  members: readonly Pick<GroupMemberState, 'deviceId' | 'joinedVersion'>[],
  requests: readonly RejoinRequestState[],
): Map<string, Date> {
  const joinedVersion = new Map(members.map((member) => [member.deviceId, member.joinedVersion]));
  const open = new Map<string, Date>();
  for (const request of requests) {
    const joined = joinedVersion.get(request.deviceId);
    if (joined === undefined || request.version < joined) continue;
    const earliest = open.get(request.deviceId);
    if (!earliest || request.requestedAt < earliest) open.set(request.deviceId, request.requestedAt);
  }
  return open;
}

export interface GroupMembershipView {
  eligibleIds: Set<string>;
  memberIds: Set<string>;
  /** Eligible members without an open rejoin request. */
  usableMemberIds: Set<string>;
  rejoinOpenSince: Map<string, Date>;
  validPackages: Map<string, MemberPackageState>;
  /** ((E ∩ P) ∖ M) ∪ rejoin requesters with a valid rejoin package. Sorted. */
  pendingAddDeviceIds: string[];
  /** M ∖ E. Sorted. */
  requiredRemoveDeviceIds: string[];
}

export function deriveMembership(input: {
  eligible: readonly EligibleDevice[];
  members: readonly GroupMemberState[];
  packages: readonly MemberPackageState[];
  rejoinRequests: readonly RejoinRequestState[];
  now: number;
}): GroupMembershipView {
  const eligibleIds = new Set(input.eligible.map((device) => device.id));
  const memberIds = new Set(input.members.map((member) => member.deviceId));
  const rejoinOpenSince = openRejoinRequests(input.members, input.rejoinRequests);
  const validPackages = new Map(
    input.packages
      .filter((pkg) => isValidMemberPackage(pkg, input.now))
      .map((pkg) => [pkg.deviceId, pkg]),
  );
  const usableMemberIds = new Set(
    [...memberIds].filter((id) => eligibleIds.has(id) && !rejoinOpenSince.has(id)),
  );
  const pendingAddDeviceIds = [...validPackages.values()]
    .filter((pkg) => eligibleIds.has(pkg.deviceId) && (
      !memberIds.has(pkg.deviceId) || (pkg.rejoin && rejoinOpenSince.has(pkg.deviceId))
    ))
    .map((pkg) => pkg.deviceId)
    .sort();
  const requiredRemoveDeviceIds = [...memberIds].filter((id) => !eligibleIds.has(id)).sort();
  return {
    eligibleIds,
    memberIds,
    usableMemberIds,
    rejoinOpenSince,
    validPackages,
    pendingAddDeviceIds,
    requiredRemoveDeviceIds,
  };
}

/**
 * From when a member could have added a rejoin requester again: it asked,
 * and its rejoin package is valid now. Null while nobody can re-add it, so
 * an open request without a usable package never counts as waiting.
 */
export function rejoinAddableSince(
  view: Pick<GroupMembershipView, 'validPackages' | 'rejoinOpenSince'>,
  deviceId: string,
): Date | null {
  const requested = view.rejoinOpenSince.get(deviceId);
  const pkg = view.validPackages.get(deviceId);
  if (!requested || !pkg?.rejoin) return null;
  const addable = packageAddableSince(pkg);
  return addable > requested ? addable : requested;
}

/** The lowest unoccupied leaf indexes, as RFC 9420 Adds fill blank leaves. */
export function lowestFreeLeaves(occupied: Iterable<number>, count: number): number[] {
  const taken = new Set(occupied);
  const result: number[] = [];
  for (let index = 0; result.length < count; index++) {
    if (!taken.has(index)) result.push(index);
  }
  return result;
}

/** Removes free their leaves first; Adds then take the lowest free leaves in proposal order. */
export function nextRoster(
  current: readonly MlsGroupMember[],
  removed: readonly string[],
  added: readonly Pick<MlsGroupMember, 'deviceId' | 'userId'>[],
): MlsGroupMember[] {
  const removedIds = new Set(removed);
  const kept = current.filter((member) => !removedIds.has(member.deviceId));
  const leaves = lowestFreeLeaves(kept.map((member) => member.leafIndex), added.length);
  return [
    ...kept.map((member) => ({ deviceId: member.deviceId, userId: member.userId, leafIndex: member.leafIndex })),
    ...added.map((member, index) => ({ deviceId: member.deviceId, userId: member.userId, leafIndex: leaves[index] })),
  ].sort((left, right) => left.leafIndex - right.leafIndex);
}

/** A genesis places its creator at leaf 0 and every other package after it. */
export function genesisRoster(added: readonly Pick<MlsGroupMember, 'deviceId' | 'userId'>[]): MlsGroupMember[] {
  return added.map((member, leafIndex) => ({ deviceId: member.deviceId, userId: member.userId, leafIndex }));
}

export function sameRoster(left: readonly MlsGroupMember[], right: readonly MlsGroupMember[]): boolean {
  return left.length === right.length && left.every((member, index) => (
    member.deviceId === right[index].deviceId
    && member.userId === right[index].userId
    && member.leafIndex === right[index].leafIndex
  ));
}

function containsKey(keyPackage: string, key: string): boolean {
  return Buffer.from(keyPackage, 'base64').includes(Buffer.from(key, 'base64'));
}

/**
 * A package must not reuse a key of another published package or of a current
 * leaf, including the add-time init key of a member. ts-mls accepts such a
 * package and then fails every later commit of the group.
 */
export function packageKeyConflicts(
  candidate: Pick<MemberPackageState, 'initKey' | 'encryptionKey' | 'signatureKey'>,
  members: readonly Pick<GroupMemberState, 'signatureKey' | 'encryptionKey' | 'keyPackage'>[],
  otherPackages: readonly Pick<MemberPackageState, 'initKey' | 'encryptionKey' | 'signatureKey'>[],
): boolean {
  const keys = [candidate.initKey, candidate.encryptionKey, candidate.signatureKey];
  if (new Set(keys).size !== keys.length) return true;
  const published = new Set(otherPackages.flatMap((pkg) => [pkg.initKey, pkg.encryptionKey, pkg.signatureKey]));
  if (keys.some((key) => published.has(key))) return true;
  return members.some((member) => keys.some((key) => (
    key === member.signatureKey || key === member.encryptionKey || containsKey(member.keyPackage, key)
  )));
}

export interface FreshStartInput {
  now: number;
  callerDeviceId: string;
  /** MANAGE_CHANNELS, or a DM participant. */
  hasRotationPermission: boolean;
  view: GroupMembershipView;
  members: readonly GroupMemberState[];
  activeCreatedAt: Date;
  /** Since when a member's user has no longer seen the channel (mls_groups). */
  removeRequiredAt?: Date | null;
}

/**
 * Since when the earliest pending addition, rejoin request or required remove
 * could have been committed. Each counts from when a member could act on it:
 * a package from when it became valid, a rejoin from when its package did, a
 * revoked device from its revocation and a lost viewer from when access
 * ended. Nothing without a known start counts.
 */
export function pendingSince(input: FreshStartInput): Date | null {
  const times: Date[] = [];
  for (const deviceId of input.view.pendingAddDeviceIds) {
    const since = input.view.memberIds.has(deviceId)
      ? rejoinAddableSince(input.view, deviceId)
      : packageAddableSince(input.view.validPackages.get(deviceId)!);
    if (since) times.push(since);
  }
  for (const deviceId of input.view.requiredRemoveDeviceIds) {
    const member = input.members.find((candidate) => candidate.deviceId === deviceId);
    const since = member?.revokedAt ?? input.removeRequiredAt ?? null;
    if (since) times.push(since);
  }
  if (times.length === 0) return null;
  const earliest = times.reduce((left, right) => (left < right ? left : right));
  return earliest > input.activeCreatedAt ? earliest : input.activeCreatedAt;
}

/** §5.3.4: who may replace an existing group with a new one (step-up still required). */
export function freshStartPermitted(input: FreshStartInput): boolean {
  const usable = input.members.filter((member) => input.view.usableMemberIds.has(member.deviceId));
  // (a) Nobody usable can commit, or nobody usable has been seen for 72 h.
  if (usable.every((member) => input.now - member.lastSeenAt.getTime() >= FRESH_START_IDLE_MS)) return true;
  // (b) This device asked to be added again, and could have been for 30 minutes.
  const rejoin = rejoinAddableSince(input.view, input.callerDeviceId);
  if (rejoin && input.now - rejoin.getTime() >= FRESH_START_REJOIN_WAIT_MS) return true;
  // (c) A manager (or DM participant) when membership changes stalled for 15 minutes.
  if (!input.hasRotationPermission) return false;
  const since = pendingSince(input);
  return since !== null && input.now - since.getTime() >= FRESH_START_STALL_MS;
}

/** Devices that were recipients of the pre-v4 epoch and must be in the genesis. */
export function genesisWaitingDeviceIds(input: {
  previousRecipientIds: readonly string[];
  view: Pick<GroupMembershipView, 'eligibleIds' | 'validPackages'>;
  genesisRequestedAt: Date | null;
  now: number;
}): string[] {
  if (input.genesisRequestedAt && input.now - input.genesisRequestedAt.getTime() >= GENESIS_WAIT_MS) {
    return [];
  }
  return [...new Set(input.previousRecipientIds)]
    .filter((id) => input.view.eligibleIds.has(id) && !input.view.validPackages.has(id))
    .sort();
}

function strictlyIncreasing<T>(values: readonly T[], key: (value: T) => string | number): boolean {
  return values.every((value, index) => index === 0 || key(values[index - 1]) < key(value));
}

/**
 * Checks that need no server state (403 INVALID_MLS): the envelope agrees
 * with its own PublicMessage, Welcome and packages.
 */
export function assertCommitStructure(
  commit: MlsGroupCommit,
  decoded: DecodedGroupCommit,
  welcomeReferences: string[] | null,
  addedKeys: readonly MemberPackageKeys[],
): void {
  const invalid = () => { throw new Error('INVALID_MLS'); };
  const genesisVersion = commit.version - commit.epoch + 1;
  if (
    commit.epoch < 1
    || genesisVersion < 1
    || commit.previousVersion >= commit.version
    || commit.groupId !== mlsGroupId(commit.channelId, genesisVersion)
    || !Buffer.from(commit.groupId, 'utf8').equals(Buffer.from(decoded.groupId))
    || decoded.epoch !== BigInt(commit.epoch - 1)
    || addedKeys.length !== commit.added.length
  ) invalid();
  const addedIds = commit.added.map((entry) => entry.deviceId);
  if (
    new Set(addedIds).size !== addedIds.length
    || !strictlyIncreasing(commit.removed, (id) => id)
    || commit.removed.includes(commit.committerDeviceId)
    || !strictlyIncreasing(commit.members, (member) => member.leafIndex)
    || new Set(commit.members.map((member) => member.deviceId)).size !== commit.members.length
    || !strictlyIncreasing(commit.directoryHeads, (head) => head.userId)
  ) invalid();
  const memberUsers = [...new Set(commit.members.map((member) => member.userId))].sort();
  if (
    memberUsers.length !== commit.directoryHeads.length
    || memberUsers.some((userId, index) => commit.directoryHeads[index].userId !== userId)
  ) invalid();
  const proposedAdds = commit.kind === 'create' ? commit.added.slice(1) : commit.added;
  const proposedKeys = commit.kind === 'create' ? addedKeys.slice(1) : addedKeys;
  if (
    decoded.addPackages.length !== proposedAdds.length
    || decoded.addPackages.some((pkg, index) => pkg !== proposedAdds[index].keyPackage)
  ) invalid();
  if (proposedAdds.length === 0) {
    if (commit.welcome !== '' || welcomeReferences !== null) invalid();
  } else if (
    welcomeReferences === null
    || welcomeReferences.length !== proposedKeys.length
    || welcomeReferences.some((reference, index) => reference !== proposedKeys[index].reference)
  ) invalid();
  if (decoded.path && decoded.path.identity !== commit.committerDeviceId) invalid();
  if (commit.kind === 'create') {
    if (
      commit.epoch !== 1
      || commit.added.length < 1
      || commit.added[0].deviceId !== commit.committerDeviceId
      || commit.removed.length !== 0
      || decoded.removedLeaves.length !== 0
      || decoded.senderLeafIndex !== 0
      || !sameRoster(commit.members, genesisRoster(commit.added))
      // An empty genesis commit carries the creator's UpdatePath; its leaf
      // keeps the signature key of the creator's package.
      || (proposedAdds.length === 0 && !decoded.path)
      || (decoded.path && decoded.path.signatureKey !== addedKeys[0].signatureKey)
    ) invalid();
    return;
  }
  if (
    commit.epoch < 2
    || decoded.removedLeaves.length !== commit.removed.length
    || new Set(decoded.removedLeaves).size !== decoded.removedLeaves.length
    // ts-mls adds an UpdatePath to every commit with a Remove or no proposal.
    || ((commit.removed.length > 0 || commit.added.length === 0) && !decoded.path)
  ) invalid();
}

export interface AdmissionState {
  now: number;
  callerUserId: string;
  /** Highest version of the channel, whatever its status; 0 if none. */
  latestVersion: number;
  active: {
    version: number;
    protocolVersion: number;
    createdAt: Date;
    /** Transcript of the active version's signed envelope, if it has one. */
    transcript: string | null;
  } | null;
  group: {
    genesisVersion: number | null;
    pathRefreshedAt: Date | null;
    genesisRequestedAt: Date | null;
    removeRequiredAt?: Date | null;
  } | null;
  eligible: readonly EligibleDevice[];
  members: readonly GroupMemberState[];
  packages: readonly MemberPackageState[];
  rejoinRequests: readonly RejoinRequestState[];
  /** Package ids of `added` that some member row already used. */
  usedPackageIds: ReadonlySet<string>;
  /**
   * Keys no new leaf or tree node may use: those of packages this commit does
   * not add, of the current members' add-time packages, and every node key
   * the group accepted. The caller may pass only the keys of this commit
   * that are among them.
   */
  reservedKeys: ReadonlySet<string>;
  /** Current directory head of every user in the envelope's roster. */
  directoryHeads: ReadonlyMap<string, DirectoryHead>;
  /** Recipients of a pre-v4 active epoch (migration wait), else empty. */
  previousRecipientIds: readonly string[];
  /** Accepted add-only and empty commits of the channel in the last COMMIT_RATE_WINDOW_MS. */
  recentCommitCount: number;
  /** Fresh start only: whether §5.3.4 permits this caller. */
  freshStartPermitted?: boolean;
}

export interface AdmissionPlan {
  kind: 'create' | 'commit';
  freshStart: boolean;
  genesisVersion: number;
  removedDeviceIds: string[];
  /** Added packages with their leaf and the user's directory head. */
  added: Array<{
    deviceId: string;
    userId: string;
    packageId: string;
    keyPackage: string;
    signature: string;
    leafIndex: number;
    directorySequence: number;
    keys: MemberPackageKeys;
  }>;
  /** Create on an existing group: every current member leaves the old group. */
  closeOldGroup: boolean;
  /** The commit refreshed the group key (UpdatePath, or a new group). */
  pathRefresh: boolean;
  /** The committer's new leaf HPKE key, when the commit carries an UpdatePath. */
  committerEncryptionKey: string | null;
  /** Every HPKE key of the UpdatePath (leaf first), to keep reserved. */
  pathKeys: string[];
  /** Consumed rejoin requests (devices removed and re-added by this commit). */
  rejoinedDeviceIds: string[];
}

/** Every key a commit brings into the tree: its UpdatePath (leaf first), then each added package. */
export function commitTreeKeys(
  decoded: Pick<DecodedGroupCommit, 'path'>,
  addedKeys: readonly MemberPackageKeys[],
): string[] {
  return [
    ...(decoded.path ? [decoded.path.encryptionKey, ...decoded.path.nodeKeys] : []),
    ...addedKeys.flatMap((keys) => [keys.initKey, keys.encryptionKey, keys.signatureKey]),
  ];
}

export function isV4Group(state: Pick<AdmissionState, 'active' | 'group'>): boolean {
  return Boolean(state.active && state.active.protocolVersion >= 4 && state.group?.genesisVersion);
}

/**
 * The route of a create, checked before the locks (§5.3): a channel with a
 * group starts a new one only by fresh start, and fresh start needs a group.
 * The state is read without a lock after the version check, so a group
 * another device created meanwhile can already be visible. When that group
 * took this version, the commit lost a race: a version conflict (409), not
 * a wrong route.
 */
export function precheckCreateRoute(
  commit: Pick<MlsGroupCommit, 'version'>,
  route: 'commit' | 'fresh-start',
  active: { version: number; protocolVersion: number } | null,
  genesisVersion: number | null,
): void {
  const hasGroup = Boolean(active && active.protocolVersion >= 4 && genesisVersion);
  if (hasGroup && active!.version >= commit.version) throw new Error('MLS_CONFLICT');
  if (route === 'commit' && hasGroup) throw new Error('KEY_FRESH_START_REQUIRED');
  if (route === 'fresh-start' && !hasGroup) throw new Error('KEY_FRESH_START_NOT_REQUIRED');
}

/**
 * Admission rules under the key-protocol, workspace and channel locks
 * (§5.3). Returns what the accepted commit changes, or throws the code to
 * report. The version compare-and-swap is checked first by the caller.
 */
export function planCommitAdmission(
  commit: MlsGroupCommit,
  decoded: DecodedGroupCommit,
  addedKeys: readonly MemberPackageKeys[],
  state: AdmissionState,
  route: 'commit' | 'fresh-start',
): AdmissionPlan {
  const conflict = (code = 'MLS_CONFLICT') => { throw new Error(code); };
  const invalid = () => { throw new Error('INVALID_MLS'); };
  if (commit.version !== state.latestVersion + 1) conflict();
  const hasGroup = isV4Group(state);
  if (route === 'fresh-start') {
    if (commit.kind !== 'create') invalid();
    if (!hasGroup || !state.freshStartPermitted) conflict('KEY_FRESH_START_NOT_REQUIRED');
  } else if (commit.kind === 'create' && hasGroup) {
    throw new Error('KEY_FRESH_START_REQUIRED');
  }
  if (
    commit.previousVersion !== (state.active?.version ?? 0)
    || commit.previousTranscript !== (state.active?.transcript ?? EMPTY_TRANSCRIPT)
  ) conflict();

  const eligibleById = new Map(state.eligible.map((device) => [device.id, device]));
  const committer = eligibleById.get(commit.committerDeviceId);
  if (!committer || committer.userId !== state.callerUserId) conflict();
  const view = deriveMembership({
    eligible: state.eligible,
    members: state.members,
    packages: state.packages,
    rejoinRequests: state.rejoinRequests,
    now: state.now,
  });
  const removedIds = new Set(commit.removed);
  const addedIds = new Set(commit.added.map((entry) => entry.deviceId));

  // Rule 4: each added entry is an eligible device's published, valid package.
  for (const entry of commit.added) {
    const device = eligibleById.get(entry.deviceId);
    if (!device) conflict();
    if (device!.userId !== entry.userId || device!.identityKey !== entry.identityKey) invalid();
    const pkg = view.validPackages.get(entry.deviceId);
    if (
      !pkg
      || pkg.packageId !== entry.packageId
      || pkg.keyPackage !== entry.keyPackage
      || pkg.signature !== entry.signature
      || state.usedPackageIds.has(entry.packageId)
    ) conflict();
  }

  let genesisVersion: number;
  let roster: MlsGroupMember[];
  const rejoinedDeviceIds: string[] = [];
  const currentMembers = state.members.map((member) => ({
    deviceId: member.deviceId,
    userId: member.userId,
    leafIndex: member.leafIndex,
  }));
  if (commit.kind === 'create') {
    genesisVersion = commit.version;
    roster = genesisRoster(commit.added);
    if (route === 'commit' && state.active) {
      // Migration wait: still-eligible recipients of the earlier epoch join
      // the first group, unless they published nothing within 24 hours.
      for (const deviceId of new Set(state.previousRecipientIds)) {
        if (!view.eligibleIds.has(deviceId) || addedIds.has(deviceId)) continue;
        if (view.validPackages.has(deviceId)) conflict();
        const requestedAt = state.group?.genesisRequestedAt;
        if (!requestedAt || state.now - requestedAt.getTime() < GENESIS_WAIT_MS) conflict('GENESIS_WAITING');
      }
    }
  } else {
    if (!hasGroup) conflict();
    genesisVersion = state.group!.genesisVersion!;
    if (commit.groupId !== mlsGroupId(commit.channelId, genesisVersion)) invalid();
    const committerMember = state.members.find((member) => member.deviceId === commit.committerDeviceId);
    if (!committerMember || !view.usableMemberIds.has(committerMember.deviceId)) conflict();
    if (decoded.senderLeafIndex !== committerMember!.leafIndex) invalid();
    if (decoded.path && decoded.path.signatureKey !== committerMember!.signatureKey) invalid();
    for (const deviceId of commit.removed) {
      if (!view.memberIds.has(deviceId)) conflict();
      if (view.eligibleIds.has(deviceId)) {
        // An eligible device leaves only to rejoin with a new package.
        if (!view.rejoinOpenSince.has(deviceId) || !addedIds.has(deviceId)) conflict();
        rejoinedDeviceIds.push(deviceId);
      }
    }
    if (view.requiredRemoveDeviceIds.some((deviceId) => !removedIds.has(deviceId))) conflict();
    for (const deviceId of addedIds) {
      if (view.memberIds.has(deviceId) && !removedIds.has(deviceId)) conflict();
    }
    const memberLeaf = new Map(state.members.map((member) => [member.deviceId, member.leafIndex]));
    const expectedLeaves = commit.removed.map((deviceId) => memberLeaf.get(deviceId)!).sort((a, b) => a - b);
    const proposedLeaves = [...decoded.removedLeaves].sort((a, b) => a - b);
    if (expectedLeaves.some((leaf, index) => leaf !== proposedLeaves[index])) invalid();
    roster = nextRoster(currentMembers, commit.removed, commit.added);
    if (commit.added.length === 0 && commit.removed.length === 0) {
      const updateRequired = state.now - state.group!.pathRefreshedAt!.getTime() >= PATH_REFRESH_INTERVAL_MS;
      const leafDue = state.now - committerMember!.leafUpdatedAt.getTime() >= LEAF_REFRESH_INTERVAL_MS;
      if (!updateRequired && !leafDue) conflict('KEY_ROTATION_NOT_REQUIRED');
    }
    // Add-only and empty commits are bounded. A commit with a Remove (of an
    // ineligible device, or a rejoin) is never delayed.
    if (commit.removed.length === 0 && state.recentCommitCount >= COMMIT_RATE_LIMIT) {
      conflict('COMMIT_RATE_LIMITED');
    }
  }

  // Rule 5 and the roster arithmetic.
  if (!sameRoster(commit.members, roster)) invalid();
  if (roster.some((member) => !view.eligibleIds.has(member.deviceId))) conflict();

  // Rule 3: the current directory head of every user in the roster.
  for (const head of commit.directoryHeads) {
    const current = state.directoryHeads.get(head.userId);
    if (!current || current.sequence !== head.sequence || current.hash !== head.hash) conflict();
  }

  // Rule 7 and the added packages: no key this commit brings into the tree
  // is reserved elsewhere, and the new tree's keys are all distinct.
  const pathKeys = decoded.path ? [decoded.path.encryptionKey, ...decoded.path.nodeKeys] : [];
  if (commitTreeKeys(decoded, addedKeys).some((key) => state.reservedKeys.has(key))) conflict('PACKAGE_KEY_CONFLICT');
  const leafKeys: string[] = pathKeys.slice(1);
  const keepIds = new Set(roster.map((member) => member.deviceId));
  for (const member of state.members) {
    if (commit.kind === 'create' || !keepIds.has(member.deviceId) || addedIds.has(member.deviceId)) continue;
    const encryptionKey = member.deviceId === commit.committerDeviceId && decoded.path
      ? decoded.path.encryptionKey
      : member.encryptionKey;
    leafKeys.push(member.signatureKey, encryptionKey);
  }
  commit.added.forEach((entry, index) => {
    const keys = addedKeys[index];
    const encryptionKey = commit.kind === 'create' && index === 0 && decoded.path
      ? decoded.path.encryptionKey
      : keys.encryptionKey;
    leafKeys.push(keys.initKey, encryptionKey, keys.signatureKey);
  });
  if (new Set(leafKeys).size !== leafKeys.length) conflict('PACKAGE_KEY_CONFLICT');

  const leafByDevice = new Map(roster.map((member) => [member.deviceId, member.leafIndex]));
  return {
    kind: commit.kind,
    freshStart: route === 'fresh-start',
    genesisVersion,
    removedDeviceIds: [...commit.removed],
    added: commit.added.map((entry, index) => ({
      deviceId: entry.deviceId,
      userId: entry.userId,
      packageId: entry.packageId,
      keyPackage: entry.keyPackage,
      signature: entry.signature,
      leafIndex: leafByDevice.get(entry.deviceId)!,
      directorySequence: state.directoryHeads.get(entry.userId)!.sequence,
      keys: addedKeys[index],
    })),
    closeOldGroup: commit.kind === 'create' && hasGroup,
    pathRefresh: commit.kind === 'create' || decoded.path !== null,
    committerEncryptionKey: decoded.path?.encryptionKey ?? null,
    pathKeys,
    rejoinedDeviceIds,
  };
}

/** Commit version sanity used by readers: a version belongs to a group from its genesis. */
export function groupEpoch(version: number, genesisVersion: number): number {
  return version - genesisVersion + 1;
}

export interface GroupStateSnapshot {
  latestVersion: number;
  active: AdmissionState['active'];
  group: AdmissionState['group'];
  members: GroupMemberState[];
  packages: MemberPackageState[];
  rejoinRequests: RejoinRequestState[];
  previousRecipientIds: string[];
}

/** The v4 part of GET /channels/:id/key-recipients (§5.1). */
export function describeGroupState(
  channelId: string,
  snapshot: GroupStateSnapshot,
  eligible: readonly EligibleDevice[],
  caller: { userId: string; deviceId?: string; hasRotationPermission: boolean; now: number },
) {
  const now = caller.now;
  const view = deriveMembership({
    eligible,
    members: snapshot.members,
    packages: snapshot.packages,
    rejoinRequests: snapshot.rejoinRequests,
    now,
  });
  const hasGroup = isV4Group(snapshot);
  const genesisVersion = hasGroup ? snapshot.group!.genesisVersion! : null;
  const callerEligible = Boolean(caller.deviceId && eligible.some((device) => (
    device.id === caller.deviceId && device.userId === caller.userId
  )));
  const own = caller.deviceId
    ? snapshot.members.find((member) => member.deviceId === caller.deviceId && member.userId === caller.userId)
    : undefined;
  const updateRequired = Boolean(hasGroup && snapshot.group!.pathRefreshedAt
    && now - snapshot.group!.pathRefreshedAt.getTime() >= PATH_REFRESH_INTERVAL_MS);
  const canCommit = Boolean(hasGroup && own && view.usableMemberIds.has(own.deviceId));
  const canCreate = !hasGroup && callerEligible;
  const genesisWaiting = !hasGroup && snapshot.active
    ? genesisWaitingDeviceIds({
      previousRecipientIds: snapshot.previousRecipientIds,
      view,
      genesisRequestedAt: snapshot.group?.genesisRequestedAt ?? null,
      now,
    })
    : [];
  const historyRecoveryRequired = Boolean(
    hasGroup
    && callerEligible
    && !canCommit
    && freshStartPermitted({
      now,
      callerDeviceId: caller.deviceId!,
      hasRotationPermission: caller.hasRotationPermission,
      view,
      members: snapshot.members,
      activeCreatedAt: snapshot.active!.createdAt,
      removeRequiredAt: snapshot.group?.removeRequiredAt ?? null,
    }),
  );
  return {
    group: hasGroup ? {
      genesisVersion: genesisVersion!,
      groupId: mlsGroupId(channelId, genesisVersion!),
      epoch: groupEpoch(snapshot.active!.version, genesisVersion!),
      transcript: snapshot.active!.transcript ?? EMPTY_TRANSCRIPT,
      members: snapshot.members
        .map((member) => ({ deviceId: member.deviceId, userId: member.userId, leafIndex: member.leafIndex }))
        .sort((left, right) => left.leafIndex - right.leafIndex),
    } : null,
    ownMembership: own ? {
      joinedVersion: own.joinedVersion,
      leafIndex: own.leafIndex,
      rejoinRequested: view.rejoinOpenSince.has(own.deviceId),
    } : null,
    pendingAddDeviceIds: view.pendingAddDeviceIds,
    requiredRemoveDeviceIds: hasGroup ? view.requiredRemoveDeviceIds : [],
    updateRequired,
    ownLeafRefreshDue: Boolean(own && now - own.leafUpdatedAt.getTime() >= LEAF_REFRESH_INTERVAL_MS),
    canCommit,
    canCreate,
    genesisWaiting,
    rotationRequired: !hasGroup || view.requiredRemoveDeviceIds.length > 0 || updateRequired,
    historyRecoveryRequired,
    /** Not part of the response: the caller's member heartbeat. */
    ownLastSeenAt: own?.lastSeenAt ?? null,
  };
}
