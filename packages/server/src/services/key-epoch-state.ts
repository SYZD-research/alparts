import { and, eq, inArray } from 'drizzle-orm';
import {
  channelKeyEpochRecipients,
  channelKeyEpochs,
  channelKeys,
  channels,
} from '../db/schema.js';

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

/** Make a frozen provisional recipient snapshot permanently unusable. */
export async function abortPendingChannelKeyEpochs(
  store: any,
  candidateChannelIds: string[],
): Promise<string[]> {
  const channelIds = [...new Set(candidateChannelIds)].sort();
  if (channelIds.length === 0) return [];

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
  // Pending epochs never authorize ciphertext. Discard their provisional
  // recipient/candidate material so repeated aborts cannot accumulate O(N^2)
  // delivery rows; retain the epoch record to prevent version reuse.
  for (const epoch of aborted) {
    await store.update(channelKeyEpochRecipients).set({
      acceptedDeliveryId: null,
      acknowledgementSignature: null,
      acknowledgedAt: null,
    }).where(and(
      eq(channelKeyEpochRecipients.channelId, epoch.channelId),
      eq(channelKeyEpochRecipients.version, epoch.version),
    ));
    await store.delete(channelKeys).where(and(
      eq(channelKeys.channelId, epoch.channelId),
      eq(channelKeys.version, epoch.version),
    ));
    await store.delete(channelKeyEpochRecipients).where(and(
      eq(channelKeyEpochRecipients.channelId, epoch.channelId),
      eq(channelKeyEpochRecipients.version, epoch.version),
    ));
  }
  return [...new Set(aborted.map((row) => row.channelId))].sort();
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
