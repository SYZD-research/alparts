import { and, desc, eq, like, lt, not, or, sql } from 'drizzle-orm';
import { db } from '../db/index.js';
import { auditLogs } from '../db/schema.js';
import { audit, getAuditIntegrityStatus } from '../middleware/audit.js';
import {
  getChannelAuthorizationFromSnapshot,
  isVisibleChannelAuthorization,
  loadWorkspaceAuthorizationSnapshot,
  lockWorkspaceForAuthorization,
} from './authorization.service.js';

// A member's own channel settings and bookmarks are never shown in the log.
const PERSONAL_ACTIONS = ['channel.preference.%', 'message.bookmark.%'];
// Activity inside a channel (messages, DMs, membership, keys, group packages,
// files) is shown only to viewers who can see that channel, and to the member
// who did it. A device publishes a group package for every channel it can
// see, so those rows would otherwise show who is in private channels and DMs.
const CHANNEL_ACTIVITY_ACTIONS = [
  'message.%', 'dm.%', 'channel.member.%', 'channel.key.%', 'channel.mls.%', 'forum.post.%', 'attachment.%',
];

function workspaceAuditScope(workspaceId: string) {
  return or(
    and(eq(auditLogs.targetType, 'workspace'), eq(auditLogs.targetId, workspaceId)),
    sql`${auditLogs.details} ->> 'workspaceId' = ${workspaceId}`,
  );
}

function viewerAuditScope(viewerId: string, visibleChannelIds: readonly string[]) {
  const channel = sql`coalesce(${auditLogs.details} ->> 'channelId', case when ${auditLogs.targetType} = 'channel' then ${auditLogs.targetId}::text end)`;
  const visibleChannel = visibleChannelIds.length
    ? sql`${channel} in (${sql.join(visibleChannelIds.map((id) => sql`${id}`), sql`, `)})`
    : sql`false`;
  return and(
    not(or(...PERSONAL_ACTIONS.map((pattern) => like(auditLogs.action, pattern)))!),
    or(
      not(or(...CHANNEL_ACTIVITY_ACTIONS.map((pattern) => like(auditLogs.action, pattern)))!),
      eq(auditLogs.actorId, viewerId),
      visibleChannel,
    ),
  );
}

async function visibleChannelIds(workspaceId: string, viewerId: string): Promise<string[]> {
  return db.transaction(async (transaction) => {
    await lockWorkspaceForAuthorization(transaction, workspaceId, 'share');
    const snapshot = await loadWorkspaceAuthorizationSnapshot(transaction, workspaceId);
    if (!snapshot) return [];
    return snapshot.channels
      .filter((channel) => isVisibleChannelAuthorization(
        getChannelAuthorizationFromSnapshot(snapshot, viewerId, channel, {}, false),
      ))
      .map((channel) => channel.id);
  });
}

export async function listWorkspaceAuditLogs(
  workspaceId: string,
  actorId: string,
  options: { cursor?: string; limit?: number },
) {
  const limit = Math.min(Math.max(options.limit ?? 50, 1), 100);
  const scope = and(
    workspaceAuditScope(workspaceId),
    viewerAuditScope(actorId, await visibleChannelIds(workspaceId, actorId)),
  );
  let cursorCondition;
  if (options.cursor) {
    const [cursor] = await db.select({ id: auditLogs.id, createdAt: auditLogs.createdAt })
      .from(auditLogs)
      .where(and(scope, eq(auditLogs.id, options.cursor)))
      .limit(1);
    if (!cursor) throw new Error('INVALID_CURSOR');
    cursorCondition = or(
      lt(auditLogs.createdAt, cursor.createdAt),
      and(eq(auditLogs.createdAt, cursor.createdAt), lt(auditLogs.id, cursor.id)),
    );
  }

  const rows = await db.select()
    .from(auditLogs)
    .where(cursorCondition ? and(scope, cursorCondition) : scope)
    .orderBy(desc(auditLogs.createdAt), desc(auditLogs.id))
    .limit(limit + 1);
  const data = rows.slice(0, limit).map(formatAuditLog);
  const hasMore = rows.length > limit;

  // Access to the security record is itself security-relevant. Await this
  // append so a response is never returned without a durable access record.
  await audit({
    actorId,
    action: 'audit.view',
    targetType: 'workspace',
    targetId: workspaceId,
    details: { workspaceId, resultCount: data.length, paginated: Boolean(options.cursor) },
  });

  return {
    data,
    hasMore,
    cursor: hasMore ? data.at(-1)?.id ?? null : null,
  };
}

export async function getAuditIntegrity(workspaceId: string, actorId: string) {
  const integrity = await getAuditIntegrityStatus();
  await audit({
    actorId,
    action: 'audit.integrity.view',
    targetType: 'workspace',
    targetId: workspaceId,
    details: { workspaceId, valid: integrity.valid },
  });
  return integrity;
}

function formatAuditLog(row: typeof auditLogs.$inferSelect) {
  return {
    id: row.id,
    actorId: row.actorId,
    action: row.action,
    targetType: row.targetType,
    targetId: row.targetId,
    details: row.details,
    prevHash: row.prevHash,
    hash: row.hash,
    createdAt: row.createdAt.toISOString(),
  };
}
