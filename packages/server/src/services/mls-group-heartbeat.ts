import { and, eq, isNull, lt } from 'drizzle-orm';
import { mlsGroupMembers } from '../db/schema.js';
import { auditGuardedTransaction } from '../middleware/audit.js';
import { logError } from '../security/logger.js';
import { LAST_SEEN_INTERVAL_MS } from './mls-group-rules.js';

/**
 * Record that a current member device is online. Fresh start of an idle group
 * (§5.3.4 a) counts from this heartbeat, so it is written at most every ten
 * minutes and never fails the read that triggered it.
 */
export async function touchGroupMember(channelId: string, deviceId: string): Promise<void> {
  try {
    await auditGuardedTransaction(async (tx) => {
      const now = new Date();
      await tx.update(mlsGroupMembers).set({ lastSeenAt: now }).where(and(
        eq(mlsGroupMembers.channelId, channelId),
        eq(mlsGroupMembers.deviceId, deviceId),
        isNull(mlsGroupMembers.removedVersion),
        lt(mlsGroupMembers.lastSeenAt, new Date(now.getTime() - LAST_SEEN_INTERVAL_MS)),
      ));
    });
  } catch (error) {
    logError('mls.group.last_seen', error);
  }
}
