import { and, eq, isNull, sql } from 'drizzle-orm';
import { channelKeyEpochs, channels, devices, mlsGroupMembers, mlsGroups } from '../db/schema.js';
import { getChannelViewerIdsFromStore } from './authorization.service.js';
import { MAX_KEY_RECIPIENTS } from '../security/limits.js';
import { PATH_REFRESH_INTERVAL_MS } from './mls-group-rules.js';

/** The write used an older key version; the body names the current one. */
export function keyVersionStale(currentVersion: number): Error {
  return Object.assign(new Error('KEY_VERSION_STALE'), { currentVersion });
}

export interface GroupWriteInput {
  channel: typeof channels.$inferSelect;
  userId: string;
  deviceId: string;
  keyVersion: number;
  /** Attachment finalization: the key version of the message it belongs to. */
  parentKeyVersion?: number;
}

/**
 * Whether ciphertext under `keyVersion` may be stored now (§5.4). The caller
 * holds the workspace SHARE lock, so membership and role changes (UPDATE)
 * cannot interleave; member device rows are locked FOR SHARE so a revocation
 * (FOR UPDATE) either commits first or waits for this write.
 *
 * Messages, edits and deletes use exactly the active version. An attachment
 * keeps its message's version while nobody has left the group since then.
 */
export async function authorizeGroupWrite(store: any, input: GroupWriteInput): Promise<void> {
  const active = await store.query.channelKeyEpochs.findFirst({
    columns: { version: true, protocolVersion: true },
    where: and(eq(channelKeyEpochs.channelId, input.channel.id), eq(channelKeyEpochs.status, 'active')),
  }) as { version: number; protocolVersion: number } | undefined;
  // New writes always use a continuous group; earlier versions are history.
  if (!active || active.protocolVersion < 4) throw new Error('KEY_ROTATION_REQUIRED');
  const group = await store.query.mlsGroups.findFirst({
    where: eq(mlsGroups.channelId, input.channel.id),
  }) as typeof mlsGroups.$inferSelect | undefined;
  if (!group?.genesisVersion || !group.pathRefreshedAt) throw new Error('KEY_ROTATION_REQUIRED');
  const attachment = input.parentKeyVersion !== undefined;
  if (attachment) {
    if (input.keyVersion !== input.parentKeyVersion) throw new Error('INVALID_KEY_VERSION');
    if (input.keyVersion < group.genesisVersion || input.keyVersion > active.version) {
      throw new Error('KEY_ROTATION_REQUIRED');
    }
  } else if (input.keyVersion !== active.version) {
    throw keyVersionStale(active.version);
  }

  const members = await store.select({
    deviceId: mlsGroupMembers.deviceId,
    userId: mlsGroupMembers.userId,
    approvedAt: devices.approvedAt,
    revokedAt: devices.revokedAt,
  }).from(mlsGroupMembers)
    .innerJoin(devices, eq(devices.id, mlsGroupMembers.deviceId))
    .where(and(eq(mlsGroupMembers.channelId, input.channel.id), isNull(mlsGroupMembers.removedVersion)))
    .limit(MAX_KEY_RECIPIENTS + 1)
    .for('share', { of: devices }) as Array<{
      deviceId: string;
      userId: string;
      approvedAt: Date | null;
      revokedAt: Date | null;
    }>;
  if (members.length > MAX_KEY_RECIPIENTS) throw new Error('KEY_RECIPIENT_INVARIANT_EXCEEDED');
  if (!members.some((member) => member.deviceId === input.deviceId && member.userId === input.userId)) {
    throw new Error(attachment ? 'KEY_ROTATION_REQUIRED' : 'INVALID_KEY_VERSION');
  }
  // Every member must still be an eligible device (M ⊆ E): a revoked device or
  // a user who lost the channel blocks writes until a commit removes it.
  const viewers = new Set(await getChannelViewerIdsFromStore(store, input.channel));
  if (members.some((member) => !member.approvedAt || member.revokedAt || !viewers.has(member.userId))) {
    throw new Error('KEY_ROTATION_REQUIRED');
  }
  if (attachment) {
    // A device removed after the message's version must not receive the file
    // key. A rejoin removes and re-adds the same device in one commit.
    const removed = await store.execute(sql`
      select 1 from mls_group_members removed
      where removed.channel_id = ${input.channel.id}
        and removed.removed_version > ${input.keyVersion}
        and removed.removed_version <= ${active.version}
        and not exists (
          select 1 from mls_group_members readded
          where readded.channel_id = removed.channel_id
            and readded.device_id = removed.device_id
            and readded.joined_version = removed.removed_version
        )
      limit 1
    `) as { rows: unknown[] };
    if (removed.rows.length > 0) throw new Error('KEY_ROTATION_REQUIRED');
    return;
  }
  if (Date.now() - group.pathRefreshedAt.getTime() >= PATH_REFRESH_INTERVAL_MS) {
    throw new Error('KEY_ROTATION_REQUIRED');
  }
}
