import { and, eq, inArray, sql, type SQL } from 'drizzle-orm';
import {
  channelKeyEpochRecipients,
  channelKeyEpochs,
  channelKeys,
  channels,
  devices,
} from '../db/schema.js';
import {
  MAX_KEY_RECIPIENTS,
  MAX_TOTAL_CHANNELS_PER_WORKSPACE,
} from '../security/limits.js';

export interface RequiredRecipientState {
  requiredForActivation: boolean;
  acceptedDeliveryId: string | null;
}

export function areRequiredRecipientsAcknowledged(recipients: RequiredRecipientState[]): boolean {
  const required = recipients.filter((recipient) => recipient.requiredForActivation);
  return required.length > 0 && required.every((recipient) => recipient.acceptedDeliveryId !== null);
}

export function nextChannelKeyVersion(latestVersion: number | null | undefined): number {
  return (latestVersion ?? 0) + 1;
}

/** A channel-local, recipient-bounded revocation check used on every write. */
export async function hasRevokedEpochRecipient(
  store: any,
  channelId: string,
  version: number,
): Promise<boolean> {
  const rows = await store.select({
    deviceId: channelKeyEpochRecipients.deviceId,
    revokedAt: devices.revokedAt,
  })
    .from(channelKeyEpochRecipients)
    .innerJoin(devices, eq(devices.id, channelKeyEpochRecipients.deviceId))
    .where(and(
      eq(channelKeyEpochRecipients.channelId, channelId),
      eq(channelKeyEpochRecipients.version, version),
    ))
    .limit(MAX_KEY_RECIPIENTS + 1)
    .for('share') as Array<{ deviceId: string; revokedAt: Date | null }>;
  if (rows.length > MAX_KEY_RECIPIENTS) throw new Error('KEY_RECIPIENT_INVARIANT_EXCEEDED');
  return rows.some((row) => row.revokedAt !== null);
}

/** Make a frozen provisional recipient snapshot permanently unusable. */
export async function abortPendingChannelKeyEpochs(
  store: any,
  candidateChannelIds: string[],
): Promise<string[]> {
  const channelIds = [...new Set(candidateChannelIds)].sort();
  if (channelIds.length === 0) return [];
  if (channelIds.length > MAX_TOTAL_CHANNELS_PER_WORKSPACE) {
    throw new Error('KEY_EPOCH_ABORT_LIMIT');
  }

  const aborted = await store.update(channelKeyEpochs)
    .set({ status: 'aborted', abortedAt: new Date() })
    .where(and(
      inArray(channelKeyEpochs.channelId, channelIds),
      eq(channelKeyEpochs.status, 'pending'),
    ))
    .returning({
      channelId: channelKeyEpochs.channelId,
      version: channelKeyEpochs.version,
    }) as Array<{ channelId: string; version: number }>;
  if (aborted.length === 0) return [];

  // Pending epochs never authorize ciphertext. Clean every returned epoch in
  // three set operations, independent of epoch count.
  const epochValues = sql.join(aborted.map((epoch) => (
    sql`(${epoch.channelId}::uuid, ${epoch.version}::integer)`
  )), sql`, `);
  await deleteEpochRecipients(store, sql`(channel_id, version) in (values ${epochValues})`);
  return [...new Set(aborted.map((row) => row.channelId))].sort();
}

/**
 * Delete the recipients of the epochs `scope` selects (a condition on
 * channel_id and version), with their deliveries. The acknowledgement FK
 * requires clearing accepted delivery references before key rows, while key
 * rows must be removed before recipient rows. Keeping these as ordered SQL
 * statements avoids PostgreSQL data-modifying CTE execution-order ambiguity.
 */
export async function deleteEpochRecipients(store: any, scope: SQL): Promise<void> {
  await store.execute(sql`
    update ${channelKeyEpochRecipients}
    set accepted_delivery_id = null,
        acknowledgement_signature = null,
        acknowledged_at = null
    where ${scope}
  `);
  await store.execute(sql`delete from ${channelKeys} where ${scope}`);
  await store.execute(sql`delete from ${channelKeyEpochRecipients} where ${scope}`);
}

/**
 * Since when each current member's user no longer sees the channel (fresh
 * start rule c counts that member's removal from it). A user who lost the
 * channel in this change starts counting now, even if its members carry an
 * older time; one who lost it earlier keeps counting from then; a user who sees
 * the channel counts nothing. A commit ends those members, and the new rows of
 * a later membership start without a time.
 */
export async function refreshMemberAccessLoss(
  store: any,
  channelId: string,
  viewerUserIds: readonly string[],
  lostUserIds: readonly string[],
): Promise<void> {
  const among = (userIds: readonly string[]) => (userIds.length === 0
    ? sql`false`
    : sql`m.user_id in (${sql.join(userIds.map((id) => sql`${id}`), sql`, `)})`);
  const sees = among(viewerUserIds);
  const lostNow = among(lostUserIds);
  await store.execute(sql`
    update mls_group_members m set access_lost_at = case
      when ${sees} then null
      when ${lostNow} then now()
      else coalesce(m.access_lost_at, now())
    end
    where m.channel_id = ${channelId} and m.removed_version is null
      and (m.access_lost_at is not null or not ${sees})
  `);
}

/** Viewer/device loss both aborts a provisional epoch and blocks active writes. */
export async function requireChannelKeyRotation(
  store: any,
  candidateChannelIds: string[],
): Promise<{ keyedChannelIds: string[]; abortedChannelIds: string[] }> {
  const channelIds = [...new Set(candidateChannelIds)].sort();
  if (channelIds.length === 0) return { keyedChannelIds: [], abortedChannelIds: [] };

  const keyedRows = await store.selectDistinct({ channelId: channelKeyEpochs.channelId })
    .from(channelKeyEpochs)
    .where(inArray(channelKeyEpochs.channelId, channelIds)) as Array<{ channelId: string }>;
  const keyedChannelIds = keyedRows.map((row) => row.channelId).sort();
  if (keyedChannelIds.length === 0) return { keyedChannelIds, abortedChannelIds: [] };

  await store.update(channels)
    .set({ keyRotationRequired: true })
    .where(inArray(channels.id, keyedChannelIds));
  const abortedChannelIds = await abortPendingChannelKeyEpochs(store, keyedChannelIds);

  return {
    keyedChannelIds,
    abortedChannelIds,
  };
}
