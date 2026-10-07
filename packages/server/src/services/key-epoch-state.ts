import { and, eq, inArray, sql } from 'drizzle-orm';
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
  // three set operations, independent of epoch count. The acknowledgement FK
  // requires clearing accepted delivery references before key rows, while key
  // rows must be removed before recipient rows. Keeping these as ordered SQL
  // statements avoids PostgreSQL data-modifying CTE execution-order ambiguity.
  const epochValues = () => sql.join(aborted.map((epoch) => (
    sql`(${epoch.channelId}::uuid, ${epoch.version}::integer)`
  )), sql`, `);
  await store.execute(sql`
    update ${channelKeyEpochRecipients} as recipient
    set accepted_delivery_id = null,
        acknowledgement_signature = null,
        acknowledged_at = null
    from (values ${epochValues()}) as aborted(channel_id, version)
    where recipient.channel_id = aborted.channel_id
      and recipient.version = aborted.version
  `);
  await store.execute(sql`
    delete from ${channelKeys} as delivery
    using (values ${epochValues()}) as aborted(channel_id, version)
    where delivery.channel_id = aborted.channel_id
      and delivery.version = aborted.version
  `);
  await store.execute(sql`
    delete from ${channelKeyEpochRecipients} as recipient
    using (values ${epochValues()}) as aborted(channel_id, version)
    where recipient.channel_id = aborted.channel_id
      and recipient.version = aborted.version
  `);
  return [...new Set(aborted.map((row) => row.channelId))].sort();
}

/**
 * Since when a continuous group has a member whose user no longer sees the
 * channel (fresh start rule c counts from it). Set when the first such member
 * appears and cleared when access returns; an accepted commit clears it too,
 * as it must remove those members.
 */
export async function refreshGroupRemoveRequirement(
  store: any,
  channelId: string,
  viewerUserIds: readonly string[],
): Promise<void> {
  const lostAccess = viewerUserIds.length === 0
    ? sql`true`
    : sql`m.user_id not in (${sql.join(viewerUserIds.map((id) => sql`${id}`), sql`, `)})`;
  await store.execute(sql`
    update mls_groups g set remove_required_at = case
      when exists (
        select 1 from mls_group_members m
        where m.channel_id = g.channel_id and m.removed_version is null and ${lostAccess}
      ) then coalesce(g.remove_required_at, now())
      else null
    end
    where g.channel_id = ${channelId} and g.genesis_version is not null
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
