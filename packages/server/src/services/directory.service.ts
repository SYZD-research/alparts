import { createHash } from 'node:crypto';
import { and, asc, desc, eq, gt, isNotNull, isNull, lte } from 'drizzle-orm';
import {
  DIRECTORY_GENESIS,
  serializeDirectoryEntry,
  serializeDeviceDecision,
  type DirectoryEntry,
  type DirectoryEvent,
  type DirectoryHead,
} from '@alparts/shared';
import { db } from '../db/index.js';
import { deviceDirectoryEvents, devices } from '../db/schema.js';
import { verifyDevicePayloadSignature } from '../security/message.js';

export async function directoryHead(
  store: any,
  userId: string,
  ceiling = 8192,
): Promise<DirectoryHead> {
  const [entry] = await store
    .select()
    .from(deviceDirectoryEvents)
    .where(
      and(eq(deviceDirectoryEvents.userId, userId), lte(deviceDirectoryEvents.sequence, ceiling)),
    )
    .orderBy(desc(deviceDirectoryEvents.sequence))
    .limit(1);
  return entry
    ? { userId, sequence: entry.sequence, hash: entry.hash }
    : { userId, sequence: 0, hash: DIRECTORY_GENESIS };
}

/** Caller holds the key-protocol lock. Events and security mutations commit together. */
export async function appendDirectoryEvent(store: any, userId: string, event: DirectoryEvent) {
  const head = await directoryHead(store, userId);
  if (head.sequence >= 8192) throw new Error('DIRECTORY_LIMIT');
  const entry = {
    userId,
    sequence: head.sequence + 1,
    previousHash: head.hash,
    event,
  };
  const hash = createHash('sha256').update(serializeDirectoryEntry(entry)).digest('hex');
  await store.insert(deviceDirectoryEvents).values({ ...entry, hash });
  return { userId, sequence: entry.sequence, hash };
}

export async function readDirectory(
  userId: string,
  after: number,
  ceiling = 8192,
  store: typeof db = db,
) {
  return store.transaction(
    async (tx) => {
      const head = await directoryHead(tx, userId, ceiling);
      const entries = await tx
        .select()
        .from(deviceDirectoryEvents)
        .where(
          and(
            eq(deviceDirectoryEvents.userId, userId),
            gt(deviceDirectoryEvents.sequence, after),
            lte(deviceDirectoryEvents.sequence, head.sequence),
          ),
        )
        .orderBy(asc(deviceDirectoryEvents.sequence))
        .limit(64);
      return { head, entries: entries as DirectoryEntry[] };
    },
    { isolationLevel: 'repeatable read', accessMode: 'read only' },
  );
}

export async function assertDeviceDecision(
  store: any,
  userId: string,
  actorDeviceId: string,
  head: DirectoryHead,
  event: DirectoryEvent,
) {
  const actual = await directoryHead(store, userId);
  if (head.userId !== userId || head.sequence !== actual.sequence || head.hash !== actual.hash)
    throw new Error('DIRECTORY_CONFLICT');
  const [actor] = await store
    .select()
    .from(devices)
    .where(
      and(
        eq(devices.id, actorDeviceId),
        eq(devices.userId, userId),
        isNull(devices.revokedAt),
        isNotNull(devices.approvedAt),
      ),
    )
    .for('share');
  if (
    !actor ||
    event.actorDeviceId !== actorDeviceId ||
    !verifyDevicePayloadSignature(
      actor.identityKey,
      serializeDeviceDecision(head, event),
      event.signature,
    )
  )
    throw new Error('DEVICE_APPROVAL_REQUIRED');
}
