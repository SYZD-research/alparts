import { and, asc, desc, eq, inArray, isNotNull, isNull, sql } from 'drizzle-orm';
import {
  channelKeyEpochRecipients,
  channelKeyEpochs,
  channels,
  devices,
  mlsEpochs,
  mlsGroupMembers,
  mlsGroups,
  mlsMemberPackages,
} from '../db/schema.js';
import { getChannelViewerIdsFromStore } from './authorization.service.js';
import { MAX_KEY_RECIPIENTS } from '../security/limits.js';
import {
  type EligibleDevice,
  type GroupMemberState,
  type GroupStateSnapshot,
  type MemberPackageState,
  type RejoinRequestState,
} from './mls-group-rules.js';

/**
 * Approved, non-revoked devices of the channel's current viewers. Rows are
 * locked FOR SHARE so a concurrent revocation (FOR UPDATE) linearizes.
 */
export async function getEligibleDevicesFromStore(
  store: any,
  channel: typeof channels.$inferSelect,
): Promise<EligibleDevice[]> {
  const recipientUserIds = await getChannelViewerIdsFromStore(store, channel);
  if (recipientUserIds.length === 0) return [];
  const result = await store.select({ id: devices.id, userId: devices.userId, identityKey: devices.identityKey })
    .from(devices)
    .where(and(inArray(devices.userId, recipientUserIds), isNull(devices.revokedAt), isNotNull(devices.approvedAt)))
    .orderBy(asc(devices.id))
    .limit(MAX_KEY_RECIPIENTS + 1)
    .for('share') as EligibleDevice[];
  if (result.length > MAX_KEY_RECIPIENTS) throw new Error('KEY_RECIPIENT_INVARIANT_EXCEEDED');
  return result;
}

/**
 * Current members of the channel's group. Their add-time packages are only
 * read where init keys must stay reserved (publication and admission).
 */
export async function loadCurrentGroupMembers(
  store: any,
  channelId: string,
  withPackages = false,
): Promise<GroupMemberState[]> {
  const rows = await store.select({
    deviceId: mlsGroupMembers.deviceId,
    userId: mlsGroupMembers.userId,
    leafIndex: mlsGroupMembers.leafIndex,
    joinedVersion: mlsGroupMembers.joinedVersion,
    signatureKey: mlsGroupMembers.signatureKey,
    encryptionKey: mlsGroupMembers.encryptionKey,
    keyPackage: withPackages ? mlsGroupMembers.keyPackage : sql<string>`''`,
    leafUpdatedAt: mlsGroupMembers.leafUpdatedAt,
    lastSeenAt: mlsGroupMembers.lastSeenAt,
    revokedAt: devices.revokedAt,
  }).from(mlsGroupMembers)
    .innerJoin(devices, eq(devices.id, mlsGroupMembers.deviceId))
    .where(and(eq(mlsGroupMembers.channelId, channelId), isNull(mlsGroupMembers.removedVersion)))
    .orderBy(asc(mlsGroupMembers.leafIndex))
    .limit(MAX_KEY_RECIPIENTS + 1) as GroupMemberState[];
  if (rows.length > MAX_KEY_RECIPIENTS) throw new Error('KEY_RECIPIENT_INVARIANT_EXCEEDED');
  return rows;
}

/**
 * Everything the v4 state and the admission rules read about one channel.
 * Packages are loaded for the given (eligible) devices only; no other
 * package can be added.
 */
export async function loadGroupSnapshot(
  store: any,
  channelId: string,
  packageDeviceIds: readonly string[],
): Promise<GroupStateSnapshot> {
  const activeEpoch = await store.query.channelKeyEpochs.findFirst({
    columns: { version: true, protocolVersion: true, createdAt: true },
    where: and(eq(channelKeyEpochs.channelId, channelId), eq(channelKeyEpochs.status, 'active')),
  }) as { version: number; protocolVersion: number; createdAt: Date } | undefined;
  const latestEpoch = await store.query.channelKeyEpochs.findFirst({
    columns: { version: true },
    where: eq(channelKeyEpochs.channelId, channelId),
    orderBy: [desc(channelKeyEpochs.version)],
  }) as { version: number } | undefined;
  const transcriptRow = activeEpoch ? await store.query.mlsEpochs.findFirst({
    columns: { transcript: true },
    where: and(eq(mlsEpochs.channelId, channelId), eq(mlsEpochs.version, activeEpoch.version)),
  }) as { transcript: string } | undefined : undefined;
  const group = await store.query.mlsGroups.findFirst({
    where: eq(mlsGroups.channelId, channelId),
  }) as typeof mlsGroups.$inferSelect | undefined;
  const members = await loadCurrentGroupMembers(store, channelId);
  const packages = packageDeviceIds.length === 0 ? [] : await store.select({
    deviceId: mlsMemberPackages.deviceId,
    packageId: mlsMemberPackages.packageId,
    keyPackage: mlsMemberPackages.keyPackage,
    signature: mlsMemberPackages.signature,
    initKey: mlsMemberPackages.initKey,
    encryptionKey: mlsMemberPackages.encryptionKey,
    signatureKey: mlsMemberPackages.signatureKey,
    notBefore: mlsMemberPackages.notBefore,
    notAfter: mlsMemberPackages.notAfter,
    rejoin: mlsMemberPackages.rejoin,
    createdAt: mlsMemberPackages.createdAt,
  }).from(mlsMemberPackages)
    .where(and(
      eq(mlsMemberPackages.channelId, channelId),
      inArray(mlsMemberPackages.deviceId, [...packageDeviceIds]),
    ))
    .orderBy(asc(mlsMemberPackages.deviceId))
    .limit(packageDeviceIds.length + 1) as MemberPackageState[];
  // Only requests made since the member's current join are open; the
  // oldest open request of each member says since when it waits.
  const rejoinRows = members.length === 0 ? { rows: [] } : await store.execute(sql`
    select distinct on (r.device_id) r.device_id as "deviceId", r.requested_at as "requestedAt", r.version
    from mls_rejoin_requests r
    join mls_group_members m on m.channel_id = r.channel_id and m.device_id = r.device_id
      and m.removed_version is null and r.version >= m.joined_version
    where r.channel_id = ${channelId}
    order by r.device_id, r.requested_at asc
    limit ${MAX_KEY_RECIPIENTS + 1}
  `) as { rows: Array<{ deviceId: string; requestedAt: Date | string; version: number }> };
  if (rejoinRows.rows.length > MAX_KEY_RECIPIENTS) throw new Error('KEY_RECIPIENT_INVARIANT_EXCEEDED');
  const rejoinRequests: RejoinRequestState[] = rejoinRows.rows.map((row) => ({
    deviceId: row.deviceId,
    requestedAt: new Date(row.requestedAt),
    version: Number(row.version),
  }));
  const previousRecipients = activeEpoch && activeEpoch.protocolVersion < 4
    ? await store.select({ deviceId: channelKeyEpochRecipients.deviceId })
      .from(channelKeyEpochRecipients)
      .where(and(
        eq(channelKeyEpochRecipients.channelId, channelId),
        eq(channelKeyEpochRecipients.version, activeEpoch.version),
      ))
      .limit(MAX_KEY_RECIPIENTS + 1) as Array<{ deviceId: string }>
    : [];
  if (previousRecipients.length > MAX_KEY_RECIPIENTS) throw new Error('KEY_RECIPIENT_INVARIANT_EXCEEDED');
  return {
    latestVersion: latestEpoch?.version ?? 0,
    active: activeEpoch ? {
      version: activeEpoch.version,
      protocolVersion: activeEpoch.protocolVersion,
      createdAt: activeEpoch.createdAt,
      transcript: transcriptRow?.transcript ?? null,
    } : null,
    group: group ? {
      genesisVersion: group.genesisVersion,
      pathRefreshedAt: group.pathRefreshedAt,
      genesisRequestedAt: group.genesisRequestedAt,
      removeRequiredAt: group.removeRequiredAt,
    } : null,
    members,
    packages,
    rejoinRequests,
    previousRecipientIds: previousRecipients.map((row) => row.deviceId),
  };
}
