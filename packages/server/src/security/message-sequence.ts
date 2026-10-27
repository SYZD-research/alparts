import { z } from 'zod';
import { MAX_DEVICE_SEQUENCE, MAX_SEEN_HEADS } from '@alparts/shared';
import { canonicalUuid } from './canonical-id.js';

const deviceSeq = z.number().int().min(1).max(MAX_DEVICE_SEQUENCE);

/**
 * The v6 fields every signed write carries (REST and socket): the device's
 * number for the event and the events of other devices it was written after.
 * Their meaning is checked by message.service (admitSequencedEvent).
 */
export const sequencedEventFields = {
  deviceSeq,
  seenHeads: z.array(z.object({
    deviceId: canonicalUuid,
    deviceSeq,
    idempotencyKey: canonicalUuid,
  }).strict()).max(MAX_SEEN_HEADS),
};

/** v6 edits: the signed key of the version the edit replaces. */
export const supersedesField = { supersedes: canonicalUuid };
