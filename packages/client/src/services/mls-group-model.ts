import {
  MAX_KEY_RECIPIENTS,
  MAX_WORKSPACE_MEMBERS,
  mlsGroupId,
  type DirectoryHead,
  type MlsGroupCommit,
  type MlsGroupMember,
} from '@alparts/shared';
import type { ChannelKeyRecipientState } from './api';
import type { DecodedChannelCommit } from './mls-crypto';

// Pure rules for continuous channel groups (group protocol 4): the local
// records, the checks of a signed commit envelope against this device's
// previous view, and roster arithmetic. Nothing here touches storage, the
// network or MLS secrets.

export const EMPTY_TRANSCRIPT = '0'.repeat(64);

/**
 * Evidence that the server or a committer contradicts history this device
 * verified. Work stops and the local state is kept; these are never retried
 * into a rejoin.
 */
export const GROUP_EQUIVOCATION_ERRORS = new Set([
  'INVALID_MLS_TRANSCRIPT',
  'INVALID_MLS_SIGNATURE',
  'INVALID_MLS_ROSTER',
  'INVALID_MLS_GROUP',
  'DIRECTORY_INVALID',
  'MLS_DOWNGRADE',
]);

export function isGroupEquivocation(error: unknown): boolean {
  return error instanceof Error && GROUP_EQUIVOCATION_ERRORS.has(error.message);
}

/** `mls-group:{channelId}`: this device's current group, as of a verified version. */
export interface LocalGroupRecord {
  genesisVersion: number;
  groupId: string;
  version: number;
  epoch: number;
  transcript: string;
  /** Roster and directory heads of the verified envelope at `version`. */
  members: MlsGroupMember[];
  directoryHeads: DirectoryHead[];
  /** encodeChannelGroupState. */
  state: string;
}

/** `mls-chain:{channelId}`: the last verified version; never moves back. */
export interface ChainRecord {
  version: number;
  transcript: string;
  /** Lowest verified v4 genesis; keys from that version on come only from v4. */
  v4Start: number | null;
  /** Genesis of the group the pinned envelope belongs to; null for a pin from before v4. */
  genesisVersion: number | null;
  /** `version` removed this device from its group (or replaced the group without it). */
  left?: boolean;
}

/**
 * `mls-group-pending:{channelId}`: an own envelope saved before it was sent.
 * Until the server's envelope at `version` settles it, the same envelope is
 * only sent again, never replaced by another one for that version.
 */
export interface PendingGroupRecord {
  kind: 'create' | 'commit';
  genesisVersion: number;
  version: number;
  transcript: string;
  newState: string;
  /** base64 key of `version`. */
  raw: string;
  /** The signed envelope as it was sent. */
  envelope?: MlsGroupCommit;
  /** Sent as a fresh start (a new group replacing the current one). */
  freshStart?: boolean;
  /** When a send of it last ended without an answer; the server may still accept it. */
  unsettledAt?: number;
}

/**
 * How long after a send that got no answer the server may still accept it.
 * A request outlives neither the server's request and database timeouts nor
 * its audit queue by this much.
 */
export const OWN_ENVELOPE_IN_FLIGHT_MS = 5 * 60_000;

/** An earlier send of this envelope may still be accepted. */
export function ownEnvelopeInFlight(pending: Pick<PendingGroupRecord, 'unsettledAt'>, now: number): boolean {
  return typeof pending.unsettledAt === 'number' && now - pending.unsettledAt < OWN_ENVELOPE_IN_FLIGHT_MS;
}

/** Previous verified view a new envelope must continue. */
export type PreviousGroupView = Pick<
  LocalGroupRecord,
  'genesisVersion' | 'groupId' | 'version' | 'epoch' | 'transcript' | 'members' | 'directoryHeads'
>;

export function groupGenesis(envelope: Pick<MlsGroupCommit, 'version' | 'epoch'>): number {
  return envelope.version - envelope.epoch + 1;
}

/** The lowest free leaves, as RFC 9420 Adds fill blank leaves in proposal order. */
export function lowestFreeLeaves(occupied: Iterable<number>, count: number): number[] {
  const taken = new Set(occupied);
  const result: number[] = [];
  for (let index = 0; result.length < count; index++) {
    if (!taken.has(index)) result.push(index);
  }
  return result;
}

/** Removes free their leaves first; Adds then take the lowest free leaves in order. */
export function nextRoster(
  current: readonly MlsGroupMember[],
  removed: readonly string[],
  added: readonly Pick<MlsGroupMember, 'deviceId' | 'userId'>[],
): MlsGroupMember[] {
  const removedIds = new Set(removed);
  const kept = current.filter((member) => !removedIds.has(member.deviceId));
  const leaves = lowestFreeLeaves(kept.map((member) => member.leafIndex), added.length);
  return [
    ...kept.map(({ deviceId, userId, leafIndex }) => ({ deviceId, userId, leafIndex })),
    ...added.map(({ deviceId, userId }, index) => ({ deviceId, userId, leafIndex: leaves[index] })),
  ].sort((left, right) => left.leafIndex - right.leafIndex);
}

/** A genesis places its creator at leaf 0 and every added package after it. */
export function genesisRoster(added: readonly Pick<MlsGroupMember, 'deviceId' | 'userId'>[]): MlsGroupMember[] {
  return added.map(({ deviceId, userId }, leafIndex) => ({ deviceId, userId, leafIndex }));
}

export function sameRoster(left: readonly MlsGroupMember[], right: readonly MlsGroupMember[]): boolean {
  return left.length === right.length && left.every((member, index) => (
    member.deviceId === right[index].deviceId
    && member.userId === right[index].userId
    && member.leafIndex === right[index].leafIndex
  ));
}

/** Users of a roster, sorted: the users whose heads an envelope must carry. */
export function rosterUsers(members: readonly Pick<MlsGroupMember, 'userId'>[]): string[] {
  return [...new Set(members.map((member) => member.userId))].sort();
}

function strictlyIncreasing<T>(values: readonly T[], key: (value: T) => string | number): boolean {
  return values.every((value, index) => index === 0 || key(values[index - 1]) < key(value));
}

/**
 * The link from the pinned chain to an envelope. A device with no pin trusts
 * the first envelope it joins at; afterwards versions only move forward, and
 * an envelope directly after the pin must name the pinned transcript. The
 * pinned envelope itself may be read again with the same transcript.
 */
export function assertChainLink(
  chain: Pick<ChainRecord, 'version' | 'transcript'> | null,
  envelope: Pick<MlsGroupCommit, 'version' | 'previousVersion' | 'previousTranscript'>,
  transcript?: string,
): void {
  if (!chain) return;
  if (envelope.version === chain.version && transcript !== undefined) {
    if (transcript !== chain.transcript) throw new Error('INVALID_MLS_TRANSCRIPT');
    return;
  }
  if (
    envelope.version <= chain.version
    || envelope.previousVersion < chain.version
    || (envelope.previousVersion === chain.version && envelope.previousTranscript !== chain.transcript)
  ) throw new Error('INVALID_MLS_TRANSCRIPT');
}

/**
 * A group this device joins, or a server shows it in, either started after
 * the pinned version or is the group of the pin itself. Any other group at
 * or below the pin is a branch of verified history (for example the
 * continuation of a group a fresh start closed) [sec-4].
 */
export function assertGroupAfterChain(
  chain: Pick<ChainRecord, 'version' | 'genesisVersion'> | null,
  genesisVersion: number,
): void {
  if (chain && genesisVersion <= chain.version && genesisVersion !== (chain.genesisVersion ?? null)) {
    throw new Error('INVALID_MLS_TRANSCRIPT');
  }
}

/** Directory heads never go back within one channel's chain. */
export function assertHeadsMonotonic(
  previous: readonly DirectoryHead[],
  heads: readonly DirectoryHead[],
): void {
  const earlier = new Map(previous.map((head) => [head.userId, head]));
  for (const head of heads) {
    const before = earlier.get(head.userId);
    if (!before) continue;
    if (
      head.sequence < before.sequence
      || (head.sequence === before.sequence && head.hash !== before.hash)
    ) throw new Error('DIRECTORY_INVALID');
  }
}

/**
 * Users whose devices must be checked against the directory for this
 * envelope: new users, users whose head changed, and users of added devices
 * and of the committer. Unchanged heads keep their earlier verification.
 */
export function usersToVerify(
  previousHeads: readonly DirectoryHead[] | null,
  envelope: Pick<MlsGroupCommit, 'directoryHeads' | 'added' | 'members' | 'committerDeviceId'>,
): string[] {
  const earlier = new Map((previousHeads ?? []).map((head) => [head.userId, head]));
  const users = new Set<string>();
  for (const head of envelope.directoryHeads) {
    const before = earlier.get(head.userId);
    if (!previousHeads || !before || before.sequence !== head.sequence || before.hash !== head.hash) {
      users.add(head.userId);
    }
  }
  for (const entry of envelope.added) users.add(entry.userId);
  const committer = envelope.members.find((member) => member.deviceId === envelope.committerDeviceId);
  if (committer) users.add(committer.userId);
  return [...users].sort();
}

/**
 * Checks of a signed envelope that need no directory and no MLS secrets:
 * its own consistency, its PublicMessage, and how it continues `previous`.
 * `previous` is null when this device joins at this envelope.
 */
export function assertEnvelopeStructure(
  channelId: string,
  envelope: MlsGroupCommit,
  decoded: DecodedChannelCommit,
  previous: PreviousGroupView | null,
): void {
  const invalid = (code = 'INVALID_MLS_GROUP') => { throw new Error(code); };
  const genesisVersion = groupGenesis(envelope);
  if (
    envelope.channelId !== channelId
    || !Number.isSafeInteger(envelope.version)
    || !Number.isSafeInteger(envelope.epoch)
    || envelope.epoch < 1
    || genesisVersion < 1
    || envelope.previousVersion >= envelope.version
    || envelope.groupId !== mlsGroupId(channelId, genesisVersion)
    || decoded.groupId !== envelope.groupId
    || decoded.epoch !== envelope.epoch - 1
  ) invalid();
  const addedIds = envelope.added.map((entry) => entry.deviceId);
  if (
    envelope.members.length < 1
    || envelope.members.length > MAX_KEY_RECIPIENTS
    || envelope.directoryHeads.length > MAX_WORKSPACE_MEMBERS
    || new Set(addedIds).size !== addedIds.length
    || !strictlyIncreasing(envelope.removed, (id) => id)
    || envelope.removed.includes(envelope.committerDeviceId)
    || !strictlyIncreasing(envelope.members, (member) => member.leafIndex)
    || new Set(envelope.members.map((member) => member.deviceId)).size !== envelope.members.length
    || !strictlyIncreasing(envelope.directoryHeads, (head) => head.userId)
  ) invalid('INVALID_MLS_ROSTER');
  const users = rosterUsers(envelope.members);
  if (
    users.length !== envelope.directoryHeads.length
    || users.some((userId, index) => envelope.directoryHeads[index].userId !== userId)
  ) invalid('INVALID_MLS_ROSTER');
  const memberById = new Map(envelope.members.map((member) => [member.deviceId, member]));
  for (const entry of envelope.added) {
    if (memberById.get(entry.deviceId)?.userId !== entry.userId) invalid('INVALID_MLS_ROSTER');
  }
  const proposedAdds = envelope.kind === 'create' ? envelope.added.slice(1) : envelope.added;
  if (
    decoded.addPackages.length !== proposedAdds.length
    || decoded.addPackages.some((pkg, index) => pkg !== proposedAdds[index].keyPackage)
    || (proposedAdds.length === 0) !== (envelope.welcome === '')
  ) invalid('INVALID_MLS_ROSTER');

  if (envelope.kind === 'create') {
    if (
      envelope.epoch !== 1
      || envelope.added.length < 1
      || envelope.added[0].deviceId !== envelope.committerDeviceId
      || envelope.removed.length !== 0
      || decoded.removedLeaves.length !== 0
      || decoded.senderLeafIndex !== 0
      || !sameRoster(envelope.members, genesisRoster(envelope.added))
      || (proposedAdds.length === 0 && !decoded.hasPath)
    ) invalid('INVALID_MLS_ROSTER');
    if (previous) {
      // A new group that replaces this one starts right after it.
      if (
        envelope.previousVersion !== previous.version
        || envelope.previousTranscript !== previous.transcript
      ) invalid('INVALID_MLS_TRANSCRIPT');
      assertHeadsMonotonic(previous.directoryHeads, envelope.directoryHeads);
    }
    return;
  }

  if (envelope.kind !== 'commit' || envelope.epoch < 2) invalid();
  if (
    decoded.removedLeaves.length !== envelope.removed.length
    || ((envelope.removed.length > 0 || envelope.added.length === 0) && !decoded.hasPath)
  ) invalid('INVALID_MLS_ROSTER');
  if (!previous) {
    // Joining at this envelope: it must add this roster's new devices at
    // leaves the Welcome's tree then shows; the rest is checked after joining.
    // A commit directly follows the previous version of its group, and its
    // committer keeps its leaf, so the sender leaf is in this roster [sec-3].
    if (envelope.previousVersion !== envelope.version - 1) invalid('INVALID_MLS_TRANSCRIPT');
    if (memberById.get(envelope.committerDeviceId)?.leafIndex !== decoded.senderLeafIndex) invalid('INVALID_MLS_ROSTER');
    if (envelope.added.some((entry) => !memberById.has(entry.deviceId))) invalid('INVALID_MLS_ROSTER');
    return;
  }
  if (
    envelope.version !== previous.version + 1
    || envelope.groupId !== previous.groupId
    || envelope.epoch !== previous.epoch + 1
    || genesisVersion !== previous.genesisVersion
  ) invalid();
  if (
    envelope.previousVersion !== previous.version
    || envelope.previousTranscript !== previous.transcript
  ) invalid('INVALID_MLS_TRANSCRIPT');
  const previousLeaf = new Map(previous.members.map((member) => [member.deviceId, member.leafIndex]));
  const committerLeaf = previousLeaf.get(envelope.committerDeviceId);
  if (committerLeaf === undefined || decoded.senderLeafIndex !== committerLeaf) invalid('INVALID_MLS_ROSTER');
  const removedLeaves = envelope.removed.map((deviceId) => previousLeaf.get(deviceId));
  if (removedLeaves.some((leaf) => leaf === undefined)) invalid('INVALID_MLS_ROSTER');
  const expectedLeaves = (removedLeaves as number[]).sort((left, right) => left - right).join();
  const proposedLeaves = [...decoded.removedLeaves].sort((left, right) => left - right).join();
  if (expectedLeaves !== proposedLeaves) invalid('INVALID_MLS_ROSTER');
  // An added device that is already a member must leave in the same commit (rejoin).
  if (envelope.added.some((entry) => previousLeaf.has(entry.deviceId) && !envelope.removed.includes(entry.deviceId))) {
    invalid('INVALID_MLS_ROSTER');
  }
  if (!sameRoster(envelope.members, nextRoster(previous.members, envelope.removed, envelope.added))) {
    invalid('INVALID_MLS_ROSTER');
  }
  assertHeadsMonotonic(previous.directoryHeads, envelope.directoryHeads);
}

/**
 * After processing or joining: the tree holds exactly the envelope's roster,
 * and every leaf's signature key is the one this device authenticated.
 */
export function assertTreeMatchesRoster(
  leaves: readonly { leafIndex: number; deviceId: string; signatureKey: string }[],
  members: readonly MlsGroupMember[],
  authMap: ReadonlyMap<string, string>,
): void {
  if (
    leaves.length !== members.length
    || leaves.some((leaf, index) => (
      leaf.leafIndex !== members[index].leafIndex
      || leaf.deviceId !== members[index].deviceId
      || authMap.get(leaf.deviceId) !== leaf.signatureKey
    ))
  ) throw new Error('INVALID_MLS_ROSTER');
}

/** base64url(SHA-256(key)), as envelopes and recovery records name a key. */
export async function computeGroupKeyCommitment(raw: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', raw as Uint8Array<ArrayBuffer>));
  let binary = '';
  for (const byte of digest) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const DAY = 24 * 60 * 60_000;
/** A published package is replaced after this long; it is valid for seven days. */
export const MEMBER_PACKAGE_REUSE_MS = 6 * DAY;
/** Rejoins this device asks for per channel within REJOIN_WINDOW_MS. */
export const CLIENT_REJOIN_LIMIT = 3;
export const REJOIN_WINDOW_MS = DAY;

/** `mls-rejoin:{channelId}` entry: a rejoin package the server accepted. */
export interface RejoinRecord {
  time: number;
  packageId: string;
}

/**
 * Rejoin requests still counted at `now`, oldest first. Only packages the
 * server accepted count, each once: a request lost to the network is sent
 * again with the same package and is not counted twice.
 */
export function recentRejoins(records: readonly unknown[], now: number): RejoinRecord[] {
  const recent = records
    .filter((record): record is RejoinRecord => (
      typeof record === 'object'
      && record !== null
      && typeof (record as RejoinRecord).packageId === 'string'
      && Number.isFinite((record as RejoinRecord).time)
    ))
    .filter((record) => record.time > now - REJOIN_WINDOW_MS && record.time <= now)
    .sort((left, right) => left.time - right.time);
  const seen = new Set<string>();
  const counted: RejoinRecord[] = [];
  for (const record of recent) {
    if (seen.has(record.packageId)) continue;
    seen.add(record.packageId);
    counted.push(record);
  }
  return counted;
}

/** Version keys from the lowest verified v4 genesis on come only from v4 groups. */
export function requiresGroupKey(version: number, v4Start: number | null): boolean {
  return v4Start !== null && version >= v4Start;
}

// === Server key state ===

function isDeviceIdList(value: unknown): value is string[] {
  return Array.isArray(value)
    && value.length <= MAX_KEY_RECIPIENTS
    && value.every((id) => typeof id === 'string')
    && new Set(value).size === value.length;
}

/** Bounds and internal consistency of the server's key state for a channel. */
export function assertKeyRecipientState(channelId: string, state: ChannelKeyRecipientState): void {
  if (
    !Array.isArray(state.recipients)
    || state.recipients.length > MAX_KEY_RECIPIENTS
    || new Set(state.recipients.map((recipient) => recipient.userId)).size > MAX_WORKSPACE_MEMBERS
  ) {
    throw new Error('Server returned an unbounded channel key recipient set');
  }
  if (new Set(state.recipients.map((recipient) => recipient.deviceId)).size !== state.recipients.length) {
    throw new Error('Server returned duplicate channel key recipients');
  }
  if (
    [state.historyRecoveryRequired, state.updateRequired, state.ownLeafRefreshDue, state.canCommit, state.canCreate]
      .some((value) => typeof value !== 'boolean')
    || !isDeviceIdList(state.pendingAddDeviceIds)
    || !isDeviceIdList(state.requiredRemoveDeviceIds)
    || !isDeviceIdList(state.genesisWaiting)
  ) {
    throw new Error('Server returned an invalid channel group state');
  }
  if (
    !Number.isSafeInteger(state.currentVersion)
    || state.currentVersion < 0
    || (state.currentVersion === 0) !== (state.keyCommitment === null)
  ) {
    throw new Error('Server returned an invalid active channel key state');
  }
  if (state.pendingVersion !== null || state.pendingKeyCommitment !== null) {
    throw new Error('Server returned an invalid pending channel key state');
  }
  if (!Number.isSafeInteger(state.nextVersion) || state.nextVersion <= state.currentVersion) {
    throw new Error('Server returned a non-monotonic channel key version');
  }
  const group = state.group;
  if (!group) {
    if (state.ownMembership || state.canCommit || state.historyRecoveryRequired || state.requiredRemoveDeviceIds.length > 0) {
      throw new Error('Server returned an invalid channel group state');
    }
    return;
  }
  const members = group.members;
  if (
    !Number.isSafeInteger(group.genesisVersion)
    || group.genesisVersion < 1
    || group.genesisVersion > state.currentVersion
    || group.groupId !== mlsGroupId(channelId, group.genesisVersion)
    || group.epoch !== state.currentVersion - group.genesisVersion + 1
    || !/^[a-f0-9]{64}$/.test(group.transcript)
    || !Array.isArray(members)
    || members.length < 1
    || members.length > MAX_KEY_RECIPIENTS
    || members.some((member, index) => (
      !Number.isSafeInteger(member.leafIndex)
      || member.leafIndex < 0
      || (index > 0 && members[index - 1].leafIndex >= member.leafIndex)
    ))
    || new Set(members.map((member) => member.deviceId)).size !== members.length
    || state.canCreate
  ) {
    throw new Error('Server returned an invalid channel group state');
  }
  const own = state.ownMembership;
  if (own && (
    !Number.isSafeInteger(own.joinedVersion)
    || own.joinedVersion < group.genesisVersion
    || own.joinedVersion > state.currentVersion
    || typeof own.rejoinRequested !== 'boolean'
    || !members.some((member) => member.leafIndex === own.leafIndex)
  )) {
    throw new Error('Server returned an invalid channel group membership');
  }
  if (state.canCommit && (!own || own.rejoinRequested)) {
    throw new Error('Server returned an invalid channel group membership');
  }
}
