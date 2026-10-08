import { and, asc, desc, eq, gt, inArray, isNotNull, isNull, lte, ne, notInArray, or, sql } from 'drizzle-orm';
import {
  Permissions,
  serializeMlsGroupCommit,
  serializeMlsMemberPackage,
  type DirectoryHead,
  type MlsGroupCommit,
  type MlsMemberPackage,
} from '@alparts/shared';
import { db } from '../db/index.js';
import {
  channelKeyEpochs,
  channels,
  devices,
  mlsEpochs,
  mlsGroupMembers,
  mlsGroupNodeKeys,
  mlsGroups,
  mlsMemberPackages,
  mlsPublishedPackageIds,
  mlsRejoinRequests,
  workspaceMembers,
} from '../db/schema.js';
import { auditedTransaction, type AuditEntry } from '../middleware/audit.js';
import { actionPurpose } from '../security/action-purpose.js';
import {
  MAX_KEY_RECIPIENTS,
  MAX_MLS_GROUP_COMMIT_PAGE,
  MAX_TOTAL_CHANNELS_PER_WORKSPACE,
  MAX_WORKSPACE_MEMBERSHIPS_PER_USER,
} from '../security/limits.js';
import { verifyChannelKeyFreshStartSignature, verifyDevicePayloadSignature } from '../security/message.js';
import {
  decodeGroupCommit,
  decodeGroupWelcome,
  readMemberPackage,
  storedMemberPackageKeys,
  storedPackageInitKey,
  type DecodedGroupCommit,
  type MemberPackageKeys,
} from '../security/mls-group-commit.js';
import {
  captureChannelViewersFromSnapshot,
  getChannelAuthorizationFromStore,
  getChannelViewerIdsFromStore,
  isVisibleChannelAuthorization,
  loadWorkspaceAuthorizationSnapshot,
  lockChannelAuthorization,
  lockWorkspaceForAuthorization,
} from './authorization.service.js';
import { directoryHead } from './directory.service.js';
import { channelManagersToNotify, lockKeyProtocol } from './key.service.js';
import { assertFreshStartStepUp, type StepUpProof } from './passkey.service.js';
import { touchGroupMember } from './mls-group-heartbeat.js';
import {
  getEligibleDevicesFromStore,
  loadCurrentGroupMembers,
  loadGroupSnapshot,
} from './mls-group-state.js';
import {
  COMMIT_RATE_LIMIT,
  COMMIT_RATE_WINDOW_MS,
  LAST_SEEN_INTERVAL_MS,
  PATH_REFRESH_INTERVAL_MS,
  REJOIN_LIMIT,
  REJOIN_WINDOW_MS,
  assertCommitStructure,
  canBecomeValidMemberPackage,
  commitTreeKeys,
  deriveMembership,
  freshStartPermitted,
  groupCommitTranscript,
  groupEpoch,
  isV4Group,
  isValidMemberPackage,
  packageKeyConflicts,
  planCommitAdmission,
  precheckCreateRoute,
} from './mls-group-rules.js';

/** One commits page stays well below the response budget. */
const MAX_GROUP_COMMIT_PAGE_BYTES = 4 * 1024 * 1024;

async function lockedChannel(tx: any, channelId: string, userId: string, mode: 'share' | 'update') {
  const location = await tx.query.channels.findFirst({
    columns: { workspaceId: true },
    where: eq(channels.id, channelId),
  });
  if (!location) throw new Error('CHANNEL_NOT_FOUND');
  await lockWorkspaceForAuthorization(tx, location.workspaceId, mode);
  if (mode === 'update') await lockChannelAuthorization(tx, channelId);
  const channel = await tx.query.channels.findFirst({ where: eq(channels.id, channelId) }) as
    typeof channels.$inferSelect | undefined;
  if (!channel || channel.workspaceId !== location.workspaceId) throw new Error('CHANNEL_NOT_FOUND');
  const authorization = await getChannelAuthorizationFromStore(tx, userId, channel);
  if (!isVisibleChannelAuthorization(authorization)) throw new Error('CHANNEL_NOT_FOUND');
  return { channel, authorization };
}

async function requireBoundDevice(store: any, userId: string, deviceId: string) {
  const device = await store.query.devices.findFirst({
    where: and(
      eq(devices.id, deviceId),
      eq(devices.userId, userId),
      isNull(devices.revokedAt),
      isNotNull(devices.approvedAt),
    ),
  }) as typeof devices.$inferSelect | undefined;
  if (!device) throw new Error('DEVICE_APPROVAL_REQUIRED');
  return device;
}

async function latestVersion(store: any, channelId: string): Promise<number> {
  const latest = await store.query.channelKeyEpochs.findFirst({
    columns: { version: true },
    where: eq(channelKeyEpochs.channelId, channelId),
    orderBy: [desc(channelKeyEpochs.version)],
  }) as { version: number } | undefined;
  return latest?.version ?? 0;
}

async function storedTranscript(store: any, channelId: string, version: number): Promise<string | null> {
  const row = await store.query.mlsEpochs.findFirst({
    columns: { transcript: true },
    where: and(eq(mlsEpochs.channelId, channelId), eq(mlsEpochs.version, version)),
  }) as { transcript: string } | undefined;
  return row?.transcript ?? null;
}

// === Member packages ===

export interface MemberPackageInput {
  packageId: string;
  keyPackage: string;
  signature: string;
  rejoin?: boolean;
}

/**
 * Publish this device's one-time package for a channel (§5.2). A current
 * member may publish only to ask to be added again (rejoin), a few times a day.
 */
export async function publishMemberPackage(
  channelId: string,
  userId: string,
  deviceId: string,
  input: MemberPackageInput,
): Promise<{ created: boolean }> {
  const keys = await readMemberPackage(input.keyPackage, deviceId);
  // A package that is never valid long enough cannot be added; as a rejoin
  // package it would only keep a request open.
  if (!canBecomeValidMemberPackage(keys, Date.now())) throw new Error('INVALID_MLS');
  const device = await requireBoundDevice(db, userId, deviceId);
  if (!verifyDevicePayloadSignature(
    device.identityKey,
    serializeMlsMemberPackage(channelId, { deviceId, packageId: input.packageId, keyPackage: input.keyPackage }),
    input.signature,
  )) throw new Error('INVALID_MLS');
  const result = await auditedTransaction(async (tx) => {
    // Same order as commit admission: key protocol, then the workspace.
    await lockKeyProtocol(tx);
    const { channel } = await lockedChannel(tx, channelId, userId, 'share');
    const eligible = await getEligibleDevicesFromStore(tx, channel);
    if (!eligible.some((candidate) => candidate.id === deviceId && candidate.userId === userId)) {
      throw new Error('DEVICE_APPROVAL_REQUIRED');
    }
    const members = await loadCurrentGroupMembers(tx, channelId, true);
    const member = members.find((candidate) => candidate.deviceId === deviceId);
    if (member && !input.rejoin) throw new Error('ALREADY_MEMBER');
    const rejoin = Boolean(member && input.rejoin);
    const existing = await tx.query.mlsMemberPackages.findFirst({
      where: and(eq(mlsMemberPackages.channelId, channelId), eq(mlsMemberPackages.deviceId, deviceId)),
    }) as typeof mlsMemberPackages.$inferSelect | undefined;
    const resent = existing?.packageId === input.packageId && existing.keyPackage === input.keyPackage;
    // Re-sending the stored package (its signature may be a fresh one over
    // the same bytes) changes nothing and notifies nobody.
    if (resent && existing!.rejoin === rejoin) return { created: false, rejoin, workspaceId: channel.workspaceId };
    // Any other use of a known package id is refused: another device's, a
    // replaced or consumed package, or other bytes under the same id.
    if (!resent) {
      const published = await tx.query.mlsPublishedPackageIds.findFirst({
        columns: { packageId: true },
        where: eq(mlsPublishedPackageIds.packageId, input.packageId),
      });
      if (published) throw new Error('PACKAGE_CONSUMED');
    }

    const candidateKeys = [keys.initKey, keys.encryptionKey, keys.signatureKey];
    const conflicting = await tx.select({
      initKey: mlsMemberPackages.initKey,
      encryptionKey: mlsMemberPackages.encryptionKey,
      signatureKey: mlsMemberPackages.signatureKey,
    }).from(mlsMemberPackages).where(and(
      eq(mlsMemberPackages.channelId, channelId),
      ne(mlsMemberPackages.deviceId, deviceId),
      or(
        inArray(mlsMemberPackages.initKey, candidateKeys),
        inArray(mlsMemberPackages.encryptionKey, candidateKeys),
        inArray(mlsMemberPackages.signatureKey, candidateKeys),
      ),
    )).limit(1);
    // A parent node of the current tree keeps its key without a member row.
    const group = await tx.query.mlsGroups.findFirst({
      columns: { genesisVersion: true },
      where: eq(mlsGroups.channelId, channelId),
    }) as { genesisVersion: number | null } | undefined;
    const nodeKeys = group?.genesisVersion ? await tx.select({ key: mlsGroupNodeKeys.key })
      .from(mlsGroupNodeKeys)
      .where(and(
        eq(mlsGroupNodeKeys.channelId, channelId),
        eq(mlsGroupNodeKeys.genesisVersion, group.genesisVersion),
        inArray(mlsGroupNodeKeys.key, candidateKeys),
      ))
      .limit(1) : [];
    if (nodeKeys.length > 0 || packageKeyConflicts(keys, members, conflicting)) throw new Error('PACKAGE_KEY_CONFLICT');

    const now = new Date();
    const active = await tx.query.channelKeyEpochs.findFirst({
      columns: { version: true, protocolVersion: true },
      where: and(eq(channelKeyEpochs.channelId, channelId), eq(channelKeyEpochs.status, 'active')),
    }) as { version: number; protocolVersion: number } | undefined;
    if (rejoin) {
      const windowStart = new Date(now.getTime() - REJOIN_WINDOW_MS);
      const [recent] = await tx.select({ count: sql<number>`count(*)::int` })
        .from(mlsRejoinRequests)
        .where(and(
          eq(mlsRejoinRequests.channelId, channelId),
          eq(mlsRejoinRequests.deviceId, deviceId),
          gt(mlsRejoinRequests.requestedAt, windowStart),
        ));
      if (Number(recent.count) >= REJOIN_LIMIT) throw new Error('REJOIN_LIMIT');
      // Requests older than the limit window are kept only while they say
      // since when this member waits: the oldest open one.
      await tx.execute(sql`
        delete from mls_rejoin_requests r
        where r.channel_id = ${channelId} and r.device_id = ${deviceId}
          and r.requested_at <= ${windowStart}
          and (r.version < ${member!.joinedVersion} or r.requested_at > (
            select min(o.requested_at) from mls_rejoin_requests o
            where o.channel_id = r.channel_id and o.device_id = r.device_id
              and o.version >= ${member!.joinedVersion}
          ))
      `);
      await tx.insert(mlsRejoinRequests).values({
        channelId,
        deviceId,
        requestedAt: now,
        version: active?.version ?? member!.joinedVersion,
      });
    }
    if (active && active.protocolVersion < 4) {
      // A migrated channel waits for its earlier recipients from the first package on.
      await tx.insert(mlsGroups).values({ channelId, genesisRequestedAt: now }).onConflictDoUpdate({
        target: mlsGroups.channelId,
        set: { genesisRequestedAt: sql`coalesce(${mlsGroups.genesisRequestedAt}, excluded.genesis_requested_at)` },
      });
    }
    const row = {
      packageId: input.packageId,
      keyPackage: input.keyPackage,
      signature: input.signature,
      initKey: keys.initKey,
      encryptionKey: keys.encryptionKey,
      signatureKey: keys.signatureKey,
      notBefore: keys.notBefore,
      notAfter: keys.notAfter,
      rejoin,
      createdAt: now,
    };
    await tx.insert(mlsMemberPackages).values({ channelId, deviceId, ...row }).onConflictDoUpdate({
      target: [mlsMemberPackages.channelId, mlsMemberPackages.deviceId],
      set: row,
    });
    // A re-sent package that only changes its rejoin flag keeps its record.
    await tx.insert(mlsPublishedPackageIds)
      .values({ packageId: input.packageId, channelId, deviceId, publishedAt: now })
      .onConflictDoNothing();
    return { created: true, rejoin, workspaceId: channel.workspaceId };
  }, (published) => ({
    actorId: userId,
    action: published.created ? 'channel.mls.member_package' : 'channel.mls.member_package.replay',
    targetType: 'channel',
    targetId: channelId,
    details: { workspaceId: published.workspaceId, rejoin: published.rejoin },
  }));
  return { created: result.created };
}

/** Packages a member may add now: the state's pendingAddDeviceIds (§5.2). */
export async function listPendingPackages(
  channelId: string,
  userId: string,
  deviceId: string,
): Promise<MlsMemberPackage[]> {
  return db.transaction(async (tx) => {
    const { channel } = await lockedChannel(tx, channelId, userId, 'share');
    const eligible = await getEligibleDevicesFromStore(tx, channel);
    if (!eligible.some((candidate) => candidate.id === deviceId && candidate.userId === userId)) {
      throw new Error('DEVICE_APPROVAL_REQUIRED');
    }
    const snapshot = await loadGroupSnapshot(tx, channelId, eligible.map((candidate) => candidate.id));
    const view = deriveMembership({
      eligible,
      members: snapshot.members,
      packages: snapshot.packages,
      rejoinRequests: snapshot.rejoinRequests,
      now: Date.now(),
    });
    const byId = new Map(eligible.map((candidate) => [candidate.id, candidate]));
    return view.pendingAddDeviceIds.map((id) => {
      const pkg = view.validPackages.get(id)!;
      const owner = byId.get(id)!;
      return {
        deviceId: id,
        userId: owner.userId,
        identityKey: owner.identityKey,
        packageId: pkg.packageId,
        keyPackage: pkg.keyPackage,
        signature: pkg.signature,
      };
    });
  });
}

// === Commit admission ===

export interface FreshStartRequest {
  signature: string;
  stepUpProof?: StepUpProof;
}

export interface AdmittedCommit {
  version: number;
  epoch: number;
  replay: boolean;
  workspaceId: string;
  /** Fresh start only: managers (or the other DM participants) to tell. */
  notifyUserIds: string[];
}

/**
 * Lock-free checks of state a valid commit needs, so that its packages and
 * tree are only examined for a plausible commit. Admission checks all of it
 * again under the locks.
 */
async function precheckGroupState(commit: MlsGroupCommit, route: 'commit' | 'fresh-start', deviceId: string) {
  if (commit.kind === 'commit') {
    if (route === 'fresh-start') throw new Error('INVALID_MLS');
    const member = await db.query.mlsGroupMembers.findFirst({
      columns: { leafIndex: true },
      where: and(
        eq(mlsGroupMembers.channelId, commit.channelId),
        eq(mlsGroupMembers.deviceId, deviceId),
        isNull(mlsGroupMembers.removedVersion),
      ),
    });
    if (!member) throw new Error('MLS_CONFLICT');
    return;
  }
  // Read after the version check: a group created in between shows up here
  // with the version this commit wanted.
  const active = await db.query.channelKeyEpochs.findFirst({
    columns: { version: true, protocolVersion: true },
    where: and(eq(channelKeyEpochs.channelId, commit.channelId), eq(channelKeyEpochs.status, 'active')),
  });
  const group = await db.query.mlsGroups.findFirst({
    columns: { genesisVersion: true },
    where: eq(mlsGroups.channelId, commit.channelId),
  });
  precheckCreateRoute(commit, route, active ?? null, group?.genesisVersion ?? null);
}

/**
 * The keys of each added package, from its published row. The entry must be
 * that row byte for byte (rule 4, checked again under the locks); the row was
 * fully validated when it was published.
 */
async function publishedPackageKeys(commit: MlsGroupCommit): Promise<MemberPackageKeys[]> {
  if (commit.added.length === 0) return [];
  const packageIds = [...new Set(commit.added.map((entry) => entry.packageId))];
  const rows = await db.select({
    deviceId: mlsMemberPackages.deviceId,
    packageId: mlsMemberPackages.packageId,
    keyPackage: mlsMemberPackages.keyPackage,
    signature: mlsMemberPackages.signature,
    initKey: mlsMemberPackages.initKey,
    encryptionKey: mlsMemberPackages.encryptionKey,
    signatureKey: mlsMemberPackages.signatureKey,
    notBefore: mlsMemberPackages.notBefore,
    notAfter: mlsMemberPackages.notAfter,
  }).from(mlsMemberPackages)
    .where(and(eq(mlsMemberPackages.channelId, commit.channelId), inArray(mlsMemberPackages.packageId, packageIds)))
    .limit(packageIds.length);
  const byId = new Map(rows.map((row) => [row.packageId, row]));
  const keys: MemberPackageKeys[] = [];
  for (const entry of commit.added) {
    const row = byId.get(entry.packageId);
    if (
      !row
      || row.deviceId !== entry.deviceId
      || row.keyPackage !== entry.keyPackage
      || row.signature !== entry.signature
    ) throw new Error('MLS_CONFLICT');
    keys.push(await storedMemberPackageKeys(row));
  }
  return keys;
}

/**
 * Add-only and empty commits accepted in the last hour (§5.3 rule 8).
 * Versions are consecutive, so only the last COMMIT_RATE_LIMIT versions are
 * read. A Remove commit among them lets one more through; those are bounded
 * by revocations, lost access and rejoin requests.
 */
async function recentRoutineCommits(tx: any, channelId: string, latest: number, now: number): Promise<number> {
  const [recent] = await tx.select({ count: sql<number>`count(*)::int` })
    .from(channelKeyEpochs)
    .innerJoin(mlsEpochs, and(
      eq(mlsEpochs.channelId, channelKeyEpochs.channelId),
      eq(mlsEpochs.version, channelKeyEpochs.version),
    ))
    .where(and(
      eq(channelKeyEpochs.channelId, channelId),
      gt(channelKeyEpochs.version, latest - COMMIT_RATE_LIMIT),
      eq(channelKeyEpochs.protocolVersion, 4),
      gt(channelKeyEpochs.createdAt, new Date(now - COMMIT_RATE_WINDOW_MS)),
      sql`${mlsEpochs.envelope}->>'kind' = 'commit'`,
      sql`jsonb_array_length(${mlsEpochs.envelope}->'removed') = 0`,
    ));
  return Number(recent.count);
}

/**
 * The keys this commit brings into the tree that are already used elsewhere
 * (rule 7, [live-9]): by a package it does not add (of any device), by a
 * current member's leaf or add-time package, or by a node the current group
 * accepted earlier. Only matches are returned.
 */
async function reservedCommitKeys(
  tx: any,
  commit: MlsGroupCommit,
  decoded: DecodedGroupCommit,
  addedKeys: readonly MemberPackageKeys[],
  genesisVersion: number | null,
): Promise<Set<string>> {
  const keys = [...new Set(commitTreeKeys(decoded, addedKeys))];
  const reserved = new Set<string>();
  if (keys.length === 0) return reserved;
  const wanted = new Set(keys);
  const addedDeviceIds = commit.added.map((entry) => entry.deviceId);
  const packages = await tx.select({
    initKey: mlsMemberPackages.initKey,
    encryptionKey: mlsMemberPackages.encryptionKey,
    signatureKey: mlsMemberPackages.signatureKey,
  }).from(mlsMemberPackages).where(and(
    eq(mlsMemberPackages.channelId, commit.channelId),
    addedDeviceIds.length > 0 ? notInArray(mlsMemberPackages.deviceId, addedDeviceIds) : undefined,
    or(
      inArray(mlsMemberPackages.initKey, keys),
      inArray(mlsMemberPackages.encryptionKey, keys),
      inArray(mlsMemberPackages.signatureKey, keys),
    ),
  )).limit(keys.length) as Array<{ initKey: string; encryptionKey: string; signatureKey: string }>;
  for (const row of packages) {
    for (const key of [row.initKey, row.encryptionKey, row.signatureKey]) if (wanted.has(key)) reserved.add(key);
  }
  // A new group starts with an empty tree; the old group's keys do not matter.
  if (commit.kind === 'create' || !genesisVersion) return reserved;
  const members = await tx.select({
    signatureKey: mlsGroupMembers.signatureKey,
    encryptionKey: mlsGroupMembers.encryptionKey,
    keyPackage: mlsGroupMembers.keyPackage,
  }).from(mlsGroupMembers)
    .where(and(eq(mlsGroupMembers.channelId, commit.channelId), isNull(mlsGroupMembers.removedVersion)))
    .limit(MAX_KEY_RECIPIENTS + 1) as Array<{ signatureKey: string; encryptionKey: string; keyPackage: string }>;
  if (members.length > MAX_KEY_RECIPIENTS) throw new Error('KEY_RECIPIENT_INVARIANT_EXCEEDED');
  for (const member of members) {
    // The committer's path replaces its own leaf key; the rules keep the
    // rest of the new tree distinct.
    for (const key of [member.signatureKey, member.encryptionKey, storedPackageInitKey(member.keyPackage)]) {
      if (wanted.has(key)) reserved.add(key);
    }
  }
  const nodes = await tx.select({ key: mlsGroupNodeKeys.key })
    .from(mlsGroupNodeKeys)
    .where(and(
      eq(mlsGroupNodeKeys.channelId, commit.channelId),
      eq(mlsGroupNodeKeys.genesisVersion, genesisVersion),
      inArray(mlsGroupNodeKeys.key, keys),
    ))
    .limit(keys.length) as Array<{ key: string }>;
  for (const node of nodes) reserved.add(node.key);
  return reserved;
}

function groupCommitAudit(
  userId: string,
  commit: MlsGroupCommit,
  transcript: string,
  accepted: { replay: boolean; workspaceId: string; kind?: string; added?: string[]; removed?: string[] },
): AuditEntry {
  return {
    actorId: userId,
    action: accepted.replay ? 'channel.key.group.replay' : `channel.key.group.${accepted.kind}`,
    targetType: 'channel',
    targetId: commit.channelId,
    details: {
      workspaceId: accepted.workspaceId,
      version: commit.version,
      epoch: commit.epoch,
      committerDeviceId: commit.committerDeviceId,
      transcript,
      ...(accepted.replay ? {} : { added: accepted.added, removed: accepted.removed }),
    },
  };
}

/**
 * Order one group commit (§5.3). Before any lock the checks run cheapest
 * first: the caller's own device and signature, a retried commit, the
 * version, membership and the published packages, and only then the MLS
 * message itself. Under the locks the version compare-and-swap comes first
 * and the remaining checks are comparisons against stored rows.
 */
export async function admitGroupCommit(
  userId: string,
  deviceId: string,
  commit: MlsGroupCommit,
  freshStart: FreshStartRequest | null,
): Promise<AdmittedCommit> {
  const route = freshStart ? 'fresh-start' : 'commit';
  if (commit.committerDeviceId !== deviceId) throw new Error('INVALID_MLS');
  const committer = await requireBoundDevice(db, userId, deviceId);
  if (!verifyDevicePayloadSignature(committer.identityKey, serializeMlsGroupCommit(commit), commit.signature)) {
    throw new Error('INVALID_MLS');
  }
  const transcript = groupCommitTranscript(commit);
  const replay = (workspaceId: string): AdmittedCommit => ({
    version: commit.version,
    epoch: commit.epoch,
    replay: true,
    workspaceId,
    notifyUserIds: [],
  });
  // A lost response is retried with the same bytes (DATA-04). It is answered
  // before anything that depends on time or on the packages it consumed.
  if (await storedTranscript(db, commit.channelId, commit.version) === transcript) {
    return auditedTransaction(async (tx) => {
      const channel = await tx.query.channels.findFirst({
        columns: { workspaceId: true },
        where: eq(channels.id, commit.channelId),
      }) as { workspaceId: string } | undefined;
      if (!channel) throw new Error('CHANNEL_NOT_FOUND');
      return replay(channel.workspaceId);
    }, (accepted) => groupCommitAudit(userId, commit, transcript, accepted));
  }
  if (freshStart && !verifyChannelKeyFreshStartSignature(committer.identityKey, {
    channelId: commit.channelId,
    keyVersion: commit.version,
    keyCommitment: commit.keyCommitment,
    deviceId,
  }, freshStart.signature)) throw new Error('INVALID_KEY_FRESH_START');
  if (commit.version !== await latestVersion(db, commit.channelId) + 1) throw new Error('MLS_CONFLICT');
  await precheckGroupState(commit, route, deviceId);
  const addedKeys = await publishedPackageKeys(commit);
  const decoded = await decodeGroupCommit(commit.commit);
  const welcomeReferences = commit.welcome === '' ? null : decodeGroupWelcome(commit.welcome);
  assertCommitStructure(commit, decoded, welcomeReferences, addedKeys);
  const now = Date.now();

  const result = await auditedTransaction<AdmittedCommit & { kind: string; added: string[]; removed: string[] }>(async (tx) => {
    await lockKeyProtocol(tx);
    const { channel, authorization } = await lockedChannel(tx, commit.channelId, userId, 'update');
    const latest = await latestVersion(tx, commit.channelId);
    if (commit.version !== latest + 1) {
      if (await storedTranscript(tx, commit.channelId, commit.version) === transcript) {
        return { ...replay(channel.workspaceId), kind: 'replay', added: [], removed: [] };
      }
      throw new Error('MLS_CONFLICT');
    }
    if (freshStart) {
      await assertFreshStartStepUp(tx, freshStart.stepUpProof, userId, deviceId,
        actionPurpose('POST', `/api/channels/${commit.channelId}/mls/group/fresh-start`, {
          commit, freshStartSignature: freshStart.signature,
        }));
    }
    const eligible = await getEligibleDevicesFromStore(tx, channel);
    const snapshot = await loadGroupSnapshot(tx, commit.channelId, eligible.map((candidate) => candidate.id));
    const addedPackageIds = commit.added.map((entry) => entry.packageId);
    const used = addedPackageIds.length === 0 ? [] : await tx.select({ packageId: mlsGroupMembers.packageId })
      .from(mlsGroupMembers)
      .where(inArray(mlsGroupMembers.packageId, addedPackageIds))
      .limit(addedPackageIds.length) as Array<{ packageId: string }>;
    const heads = new Map<string, DirectoryHead>();
    for (const head of commit.directoryHeads) heads.set(head.userId, await directoryHead(tx, head.userId));
    const hasGroup = isV4Group(snapshot);
    const hasRotationPermission = channel.type === 'dm'
      || (authorization.permissions & Permissions.MANAGE_CHANNELS) === Permissions.MANAGE_CHANNELS;
    const plan = planCommitAdmission(commit, decoded, addedKeys, {
      ...snapshot,
      now,
      callerUserId: userId,
      eligible,
      usedPackageIds: new Set(used.map((row) => row.packageId)),
      reservedKeys: await reservedCommitKeys(
        tx, commit, decoded, addedKeys, hasGroup ? snapshot.group!.genesisVersion : null,
      ),
      directoryHeads: heads,
      recentCommitCount: hasGroup ? await recentRoutineCommits(tx, commit.channelId, latest, now) : 0,
      freshStartPermitted: freshStart && hasGroup
        ? freshStartPermitted({
          now,
          callerDeviceId: deviceId,
          hasRotationPermission,
          view: deriveMembership({
            eligible,
            members: snapshot.members,
            packages: snapshot.packages,
            rejoinRequests: snapshot.rejoinRequests,
            now,
          }),
          members: snapshot.members,
          activeCreatedAt: snapshot.active!.createdAt,
          removeRequiredAt: snapshot.group!.removeRequiredAt ?? null,
        })
        : false,
    }, route);

    const acceptedAt = new Date();
    const version = commit.version;
    let removedDeviceIds = plan.removedDeviceIds;
    if (plan.closeOldGroup) {
      // Fresh start: every member of the old group leaves it with this version.
      const closed = await tx.update(mlsGroupMembers).set({ removedVersion: version }).where(and(
        eq(mlsGroupMembers.channelId, commit.channelId),
        isNull(mlsGroupMembers.removedVersion),
      )).returning({ deviceId: mlsGroupMembers.deviceId }) as Array<{ deviceId: string }>;
      removedDeviceIds = closed.map((row) => row.deviceId).sort();
    } else if (plan.removedDeviceIds.length > 0) {
      const removed = await tx.update(mlsGroupMembers).set({ removedVersion: version }).where(and(
        eq(mlsGroupMembers.channelId, commit.channelId),
        inArray(mlsGroupMembers.deviceId, plan.removedDeviceIds),
        isNull(mlsGroupMembers.removedVersion),
      )).returning({ deviceId: mlsGroupMembers.deviceId });
      if (removed.length !== plan.removedDeviceIds.length) throw new Error('MLS_GROUP_INVARIANT_EXCEEDED');
    }
    await tx.update(channelKeyEpochs).set({ status: 'retired' }).where(and(
      eq(channelKeyEpochs.channelId, commit.channelId),
      eq(channelKeyEpochs.status, 'active'),
    ));
    // An accepted commit is active at once; nothing waits for acknowledgements.
    await tx.insert(channelKeyEpochs).values({
      channelId: commit.channelId,
      version,
      protocolVersion: 4,
      status: 'active',
      keyCommitment: commit.keyCommitment,
      distributorDeviceId: deviceId,
      activatedAt: acceptedAt,
    });
    await tx.insert(mlsEpochs).values({ channelId: commit.channelId, version, transcript, envelope: commit });
    if (plan.added.length > 0) {
      await tx.insert(mlsGroupMembers).values(plan.added.map((entry, index) => ({
        channelId: commit.channelId,
        genesisVersion: plan.genesisVersion,
        deviceId: entry.deviceId,
        userId: entry.userId,
        leafIndex: entry.leafIndex,
        joinedVersion: version,
        packageId: entry.packageId,
        keyPackage: entry.keyPackage,
        packageSignature: entry.signature,
        joinedDirectorySequence: entry.directorySequence,
        signatureKey: entry.keys.signatureKey,
        // A genesis creator's leaf follows its own UpdatePath, when it has one.
        encryptionKey: plan.kind === 'create' && index === 0 && plan.committerEncryptionKey
          ? plan.committerEncryptionKey
          : entry.keys.encryptionKey,
        leafUpdatedAt: acceptedAt,
        lastSeenAt: acceptedAt,
      })));
      const devicePackage = new Map(plan.added.map((entry) => [entry.packageId, entry.deviceId]));
      const consumed = await tx.delete(mlsMemberPackages).where(and(
        eq(mlsMemberPackages.channelId, commit.channelId),
        inArray(mlsMemberPackages.packageId, [...devicePackage.keys()]),
      )).returning({ deviceId: mlsMemberPackages.deviceId, packageId: mlsMemberPackages.packageId }) as Array<{
        deviceId: string;
        packageId: string;
      }>;
      if (
        consumed.length !== plan.added.length
        || consumed.some((row) => devicePackage.get(row.packageId) !== row.deviceId)
      ) throw new Error('MLS_GROUP_INVARIANT_EXCEEDED');
      // Requests answered by this join stay only while they count against the limit.
      await tx.delete(mlsRejoinRequests).where(and(
        eq(mlsRejoinRequests.channelId, commit.channelId),
        inArray(mlsRejoinRequests.deviceId, plan.added.map((entry) => entry.deviceId)),
        lte(mlsRejoinRequests.requestedAt, new Date(acceptedAt.getTime() - REJOIN_WINDOW_MS)),
      ));
    }
    if (plan.pathKeys.length > 0) {
      await tx.insert(mlsGroupNodeKeys).values(plan.pathKeys.map((key) => ({
        channelId: commit.channelId,
        genesisVersion: plan.genesisVersion,
        key,
      })));
    }
    if (plan.kind === 'commit' && plan.committerEncryptionKey) {
      await tx.update(mlsGroupMembers).set({
        encryptionKey: plan.committerEncryptionKey,
        leafUpdatedAt: acceptedAt,
      }).where(and(
        eq(mlsGroupMembers.channelId, commit.channelId),
        eq(mlsGroupMembers.deviceId, deviceId),
        isNull(mlsGroupMembers.removedVersion),
      ));
    }
    // Every member is eligible after an accepted commit, so no remove is due.
    if (plan.kind === 'create') {
      await tx.insert(mlsGroups).values({
        channelId: commit.channelId,
        genesisVersion: version,
        pathRefreshedAt: acceptedAt,
      }).onConflictDoUpdate({
        target: mlsGroups.channelId,
        set: { genesisVersion: version, pathRefreshedAt: acceptedAt, removeRequiredAt: null },
      });
    } else {
      await tx.update(mlsGroups).set({
        removeRequiredAt: null,
        ...(plan.pathRefresh ? { pathRefreshedAt: acceptedAt } : {}),
      }).where(eq(mlsGroups.channelId, commit.channelId));
    }
    await tx.execute(sql`insert into channel_directory_heads (channel_id, user_id, sequence)
      values ${sql.join(commit.directoryHeads.map((head) => sql`(${commit.channelId}, ${head.userId}, ${head.sequence})`), sql`, `)}
      on conflict (channel_id, user_id) do update set sequence = greatest(channel_directory_heads.sequence, excluded.sequence)`);
    // The pre-v4 flag no longer gates writes once a group commit is active.
    await tx.update(channels).set({ keyRotationRequired: false }).where(eq(channels.id, commit.channelId));
    return {
      version,
      epoch: groupEpoch(version, plan.genesisVersion),
      replay: false,
      workspaceId: channel.workspaceId,
      notifyUserIds: plan.freshStart ? await freshStartNotifyUserIds(tx, channel, userId) : [],
      kind: plan.freshStart ? 'fresh_start' : plan.kind,
      added: plan.added.map((entry) => entry.deviceId),
      removed: removedDeviceIds,
    };
  }, (accepted) => groupCommitAudit(userId, commit, transcript, accepted));
  return {
    version: result.version,
    epoch: result.epoch,
    replay: result.replay,
    workspaceId: result.workspaceId,
    notifyUserIds: result.notifyUserIds,
  };
}

/** A DM tells its other participants; a channel tells its managers. */
async function freshStartNotifyUserIds(
  tx: any,
  channel: typeof channels.$inferSelect,
  actorId: string,
): Promise<string[]> {
  if (channel.type === 'dm') {
    return (await getChannelViewerIdsFromStore(tx, channel)).filter((id) => id !== actorId).sort();
  }
  return channelManagersToNotify(tx, channel.workspaceId, actorId);
}

// === Reading the commit log ===

export interface GroupCommitRecord {
  version: number;
  transcript: string;
  envelope: MlsGroupCommit;
}

/**
 * Accepted v4 commits after `after`, in order, that this device may see: a
 * version where it was a member, or the version that removed it (§5.2). The
 * page ends at the first version it may not see.
 */
export async function listGroupCommits(
  channelId: string,
  userId: string,
  deviceId: string,
  after: number,
  limit: number,
): Promise<GroupCommitRecord[]> {
  const page = Math.min(Math.max(limit, 1), MAX_MLS_GROUP_COMMIT_PAGE);
  const { commits, lastSeenAt } = await db.transaction(async (tx) => {
    await lockedChannel(tx, channelId, userId, 'share');
    await requireBoundDevice(tx, userId, deviceId);
    const rows = await tx.select({
      version: channelKeyEpochs.version,
      transcript: mlsEpochs.transcript,
      envelope: mlsEpochs.envelope,
    }).from(channelKeyEpochs)
      .innerJoin(mlsEpochs, and(
        eq(mlsEpochs.channelId, channelKeyEpochs.channelId),
        eq(mlsEpochs.version, channelKeyEpochs.version),
      ))
      .where(and(
        eq(channelKeyEpochs.channelId, channelId),
        eq(channelKeyEpochs.protocolVersion, 4),
        gt(channelKeyEpochs.version, after),
      ))
      .orderBy(asc(channelKeyEpochs.version))
      .limit(page) as Array<{ version: number; transcript: string; envelope: MlsGroupCommit }>;
    if (rows.length === 0) return { commits: [], lastSeenAt: null };
    const first = rows[0].version;
    const last = rows[rows.length - 1].version;
    // At most one membership starts at each version, so this is bounded by the page.
    const memberships = await tx.select({
      joinedVersion: mlsGroupMembers.joinedVersion,
      removedVersion: mlsGroupMembers.removedVersion,
      lastSeenAt: mlsGroupMembers.lastSeenAt,
    }).from(mlsGroupMembers)
      .where(and(
        eq(mlsGroupMembers.channelId, channelId),
        eq(mlsGroupMembers.deviceId, deviceId),
        eq(mlsGroupMembers.userId, userId),
        lte(mlsGroupMembers.joinedVersion, last),
        or(isNull(mlsGroupMembers.removedVersion), sql`${mlsGroupMembers.removedVersion} >= ${first}`),
      ))
      .limit(page + 2) as Array<{ joinedVersion: number; removedVersion: number | null; lastSeenAt: Date }>;
    const visible = (version: number) => memberships.some((membership) => (
      membership.joinedVersion <= version
      && (membership.removedVersion === null || version <= membership.removedVersion)
    ));
    const result: GroupCommitRecord[] = [];
    let bytes = 0;
    for (const row of rows) {
      if (!visible(row.version)) break;
      bytes += Buffer.byteLength(JSON.stringify(row.envelope));
      if (result.length > 0 && bytes > MAX_GROUP_COMMIT_PAGE_BYTES) break;
      result.push(row);
    }
    const current = memberships.find((membership) => membership.removedVersion === null);
    return { commits: result, lastSeenAt: current?.lastSeenAt ?? null };
  });
  if (lastSeenAt && Date.now() - lastSeenAt.getTime() >= LAST_SEEN_INTERVAL_MS) {
    await touchGroupMember(channelId, deviceId);
  }
  return commits;
}

/** The roster at `version` with each member's add-time package, for a device that was a member then. */
export async function listGroupMembers(
  channelId: string,
  userId: string,
  deviceId: string,
  version: number,
) {
  return db.transaction(async (tx) => {
    await lockedChannel(tx, channelId, userId, 'share');
    await requireBoundDevice(tx, userId, deviceId);
    const atVersion = and(
      eq(mlsGroupMembers.channelId, channelId),
      lte(mlsGroupMembers.joinedVersion, version),
      or(isNull(mlsGroupMembers.removedVersion), gt(mlsGroupMembers.removedVersion, version)),
    );
    const own = await tx.query.mlsGroupMembers.findFirst({
      columns: { deviceId: true },
      where: and(atVersion, eq(mlsGroupMembers.deviceId, deviceId), eq(mlsGroupMembers.userId, userId)),
    });
    if (!own) throw new Error('MLS_NOT_FOUND');
    const rows = await tx.select({
      deviceId: mlsGroupMembers.deviceId,
      userId: mlsGroupMembers.userId,
      identityKey: devices.identityKey,
      leafIndex: mlsGroupMembers.leafIndex,
      joinedVersion: mlsGroupMembers.joinedVersion,
      packageId: mlsGroupMembers.packageId,
      keyPackage: mlsGroupMembers.keyPackage,
      signature: mlsGroupMembers.packageSignature,
      joinedDirectorySequence: mlsGroupMembers.joinedDirectorySequence,
    }).from(mlsGroupMembers)
      .innerJoin(devices, eq(devices.id, mlsGroupMembers.deviceId))
      .where(atVersion)
      .orderBy(asc(mlsGroupMembers.leafIndex))
      .limit(MAX_KEY_RECIPIENTS + 1);
    if (rows.length > MAX_KEY_RECIPIENTS) throw new Error('KEY_RECIPIENT_INVARIANT_EXCEEDED');
    return rows;
  });
}

// === Background work across workspaces ===

/**
 * For this device, across the user's workspaces (§5.2 GET /mls/group/pending):
 * channels where it should publish a package, and channels where it is a
 * usable member and a commit is due. One page covers whole workspaces.
 */
export async function pendingGroupWork(userId: string, deviceId: string, cursor?: string) {
  const empty = { needPackage: [] as string[], needCommit: [] as string[], cursor: null as string | null };
  const device = await db.query.devices.findFirst({
    columns: { id: true },
    where: and(
      eq(devices.id, deviceId),
      eq(devices.userId, userId),
      isNull(devices.revokedAt),
      isNotNull(devices.approvedAt),
    ),
  });
  if (!device) return empty;
  const memberships = await db.query.workspaceMembers.findMany({
    columns: { workspaceId: true },
    where: eq(workspaceMembers.userId, userId),
    orderBy: [asc(workspaceMembers.workspaceId)],
    limit: MAX_WORKSPACE_MEMBERSHIPS_PER_USER + 1,
  });
  if (memberships.length > MAX_WORKSPACE_MEMBERSHIPS_PER_USER) throw new Error('WORKSPACE_MEMBERSHIP_INVARIANT_EXCEEDED');
  const workspaceIds = memberships.map((row) => row.workspaceId).filter((id) => !cursor || id > cursor);
  const result = { ...empty, needPackage: [] as string[], needCommit: [] as string[] };
  let processedChannels = 0;
  for (const [index, workspaceId] of workspaceIds.entries()) {
    if (processedChannels >= MAX_TOTAL_CHANNELS_PER_WORKSPACE) {
      result.cursor = workspaceIds[index - 1];
      break;
    }
    const work = await workspaceGroupWork(workspaceId, userId, deviceId);
    processedChannels += work.channelCount;
    result.needPackage.push(...work.needPackage);
    result.needCommit.push(...work.needCommit);
  }
  return result;
}

async function workspaceGroupWork(workspaceId: string, userId: string, deviceId: string) {
  const none = { channelCount: 0, needPackage: [] as string[], needCommit: [] as string[] };
  const snapshot = await loadWorkspaceAuthorizationSnapshot(db, workspaceId);
  if (!snapshot) return none;
  const viewers = captureChannelViewersFromSnapshot(snapshot);
  const visible = snapshot.channels
    .filter((channel) => channel.type !== 'voice' && (viewers.get(channel.id) ?? []).includes(userId))
    .map((channel) => channel.id)
    .sort();
  if (visible.length === 0) return none;
  const now = Date.now();
  const ownRows = await db.select({
    channelId: mlsGroupMembers.channelId,
    joinedVersion: mlsGroupMembers.joinedVersion,
  }).from(mlsGroupMembers).where(and(
    eq(mlsGroupMembers.deviceId, deviceId),
    isNull(mlsGroupMembers.removedVersion),
    inArray(mlsGroupMembers.channelId, visible),
  ));
  const ownPackages = await db.select({
    channelId: mlsMemberPackages.channelId,
    notBefore: mlsMemberPackages.notBefore,
    notAfter: mlsMemberPackages.notAfter,
  }).from(mlsMemberPackages).where(and(
    eq(mlsMemberPackages.deviceId, deviceId),
    inArray(mlsMemberPackages.channelId, visible),
  ));
  const memberChannels = new Set(ownRows.map((row) => row.channelId));
  const packaged = new Set(ownPackages.filter((row) => isValidMemberPackage(row, now)).map((row) => row.channelId));
  const needPackage = visible.filter((id) => !memberChannels.has(id) && !packaged.has(id));
  if (memberChannels.size === 0) return { channelCount: visible.length, needPackage, needCommit: [] };

  // A member that asked to be added again cannot commit.
  const ownRejoin = await db.execute(sql`
    select distinct r.channel_id as "channelId" from mls_rejoin_requests r
    join mls_group_members m on m.channel_id = r.channel_id and m.device_id = r.device_id
      and m.removed_version is null and r.version >= m.joined_version
    where r.device_id = ${deviceId} and r.channel_id in (${sql.join([...memberChannels].map((id) => sql`${id}`), sql`, `)})
  `) as { rows: Array<{ channelId: string }> };
  const blocked = new Set(ownRejoin.rows.map((row) => row.channelId));
  const usable = [...memberChannels].filter((id) => !blocked.has(id)).sort();
  if (usable.length === 0) return { channelCount: visible.length, needPackage, needCommit: [] };
  const channelList = sql.join(usable.map((id) => sql`${id}`), sql`, `);
  const groups = await db.select({
    channelId: mlsGroups.channelId,
    pathRefreshedAt: mlsGroups.pathRefreshedAt,
  }).from(mlsGroups).where(inArray(mlsGroups.channelId, usable));
  const due = new Set<string>(groups
    .filter((group) => group.pathRefreshedAt && now - group.pathRefreshedAt.getTime() >= PATH_REFRESH_INTERVAL_MS)
    .map((group) => group.channelId));
  // Required removes: a member whose device is no longer approved, or whose
  // user no longer sees the channel.
  const memberUsers = await db.execute(sql`
    select m.channel_id as "channelId", m.user_id as "userId",
      bool_or(d.revoked_at is not null or d.approved_at is null) as "ineligible"
    from mls_group_members m join devices d on d.id = m.device_id
    where m.removed_version is null and m.channel_id in (${channelList})
    group by m.channel_id, m.user_id
  `) as { rows: Array<{ channelId: string; userId: string; ineligible: boolean }> };
  for (const row of memberUsers.rows) {
    if (row.ineligible || !(viewers.get(row.channelId) ?? []).includes(row.userId)) due.add(row.channelId);
  }
  // Pending additions: eligible devices with a valid package that are not
  // members, or members that asked to be added again.
  const packages = await db.execute(sql`
    select p.channel_id as "channelId", d.user_id as "userId", p.not_before as "notBefore",
      p.not_after as "notAfter", p.rejoin, m.device_id is not null as "member",
      exists (select 1 from mls_rejoin_requests r where r.channel_id = p.channel_id
        and r.device_id = p.device_id and r.version >= m.joined_version) as "rejoinOpen"
    from mls_member_packages p
    join devices d on d.id = p.device_id and d.revoked_at is null and d.approved_at is not null
    left join mls_group_members m on m.channel_id = p.channel_id and m.device_id = p.device_id
      and m.removed_version is null
    where p.channel_id in (${channelList})
  `) as { rows: Array<{
    channelId: string;
    userId: string;
    notBefore: Date | string;
    notAfter: Date | string;
    rejoin: boolean;
    member: boolean;
    rejoinOpen: boolean;
  }> };
  for (const row of packages.rows) {
    if (
      isValidMemberPackage({ notBefore: new Date(row.notBefore), notAfter: new Date(row.notAfter) }, now)
      && (viewers.get(row.channelId) ?? []).includes(row.userId)
      && (!row.member || (row.rejoin && row.rejoinOpen))
    ) due.add(row.channelId);
  }
  return {
    channelCount: visible.length,
    needPackage,
    needCommit: usable.filter((id) => due.has(id)),
  };
}

// === Realtime recipients ===

/**
 * For each channel, current viewers that have an eligible device: they can
 * publish packages or commit. Users whose only devices are revoked or
 * unapproved are left out (§5.6).
 */
export async function keyStateRecipients(channelIds: readonly string[]): Promise<Map<string, string[]>> {
  const result = new Map<string, string[]>();
  const ids = [...new Set(channelIds)];
  if (ids.length === 0) return result;
  const rows = await db.select({ id: channels.id, workspaceId: channels.workspaceId })
    .from(channels)
    .where(inArray(channels.id, ids));
  const byWorkspace = new Map<string, string[]>();
  for (const row of rows) byWorkspace.set(row.workspaceId, [...(byWorkspace.get(row.workspaceId) ?? []), row.id]);
  for (const [workspaceId, workspaceChannelIds] of byWorkspace) {
    const snapshot = await loadWorkspaceAuthorizationSnapshot(db, workspaceId, workspaceChannelIds);
    if (!snapshot) continue;
    const viewers = captureChannelViewersFromSnapshot(snapshot);
    const users = [...new Set([...viewers.values()].flat())];
    const withDevice = users.length === 0 ? new Set<string>() : new Set((await db.selectDistinct({ userId: devices.userId })
      .from(devices)
      .where(and(inArray(devices.userId, users), isNull(devices.revokedAt), isNotNull(devices.approvedAt))))
      .map((row) => row.userId));
    for (const channelId of workspaceChannelIds) {
      result.set(channelId, (viewers.get(channelId) ?? []).filter((id) => withDevice.has(id)));
    }
  }
  return result;
}

/** Channels a user sees in the given workspaces, for a newly approved device. */
export async function visibleKeyChannelIds(userId: string, workspaceIds: readonly string[]): Promise<string[]> {
  const result: string[] = [];
  for (const workspaceId of [...new Set(workspaceIds)].sort()) {
    const snapshot = await loadWorkspaceAuthorizationSnapshot(db, workspaceId);
    if (!snapshot) continue;
    const viewers = captureChannelViewersFromSnapshot(snapshot);
    for (const channel of snapshot.channels) {
      if (channel.type !== 'voice' && (viewers.get(channel.id) ?? []).includes(userId)) result.push(channel.id);
    }
  }
  return result;
}
