import { and, eq, inArray, sql } from 'drizzle-orm';
import { Permissions } from '@alparts/shared';
import { db } from '../db/index.js';
import {
  channelMembers,
  channels,
  dmConversations,
  dmMembers,
  users,
  workspaces,
} from '../db/schema.js';
import { auditedTransaction } from '../middleware/audit.js';
import {
  MAX_DMS_PER_USER_PER_WORKSPACE,
  MAX_DMS_PER_WORKSPACE,
  MAX_WORKSPACE_MEMBERS,
} from '../security/limits.js';
import {
  getChannelAuthorizationFromStore,
  getChannelAuthorizationFromSnapshot,
  getWorkspaceAuthorizationFromSnapshot,
  isVisibleChannelAuthorization,
  loadWorkspaceAuthorizationSnapshot,
  lockWorkspaceForAuthorization,
} from './authorization.service.js';

export async function createDm(workspaceId: string, actorId: string, requestedUserIds: string[]) {
  const userIds = [...new Set([actorId, ...requestedUserIds])].sort();
  if (userIds.length < 2) throw new Error('DM_REQUIRES_RECIPIENT');
  const result = await auditedTransaction<{ channelId: string; created: boolean }>(async (tx) => {
    const locked = await tx.execute(sql`select id from ${workspaces} where ${workspaces.id} = ${workspaceId} for update`);
    if (locked.rowCount === 0) throw new Error('DM_MEMBER_NOT_FOUND');
    // The normalized member-set lock prevents two tabs/processes from creating
    // duplicate conversations for the same exact group concurrently.
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`dm:${workspaceId}:${userIds.join(':')}`})::bigint)`);

    const snapshot = await loadWorkspaceAuthorizationSnapshot(tx, workspaceId);
    if (!snapshot) throw new Error('DM_MEMBER_NOT_FOUND');
    for (const userId of userIds) {
      const authorization = getWorkspaceAuthorizationFromSnapshot(snapshot, userId);
      if (!authorization || (authorization.permissionMask & Permissions.VIEW_CHANNELS) !== Permissions.VIEW_CHANNELS) {
        throw new Error('DM_MEMBER_NOT_FOUND');
      }
    }

    const existingDms = snapshot.channels.filter((channel) => channel.type === 'dm');
    for (const candidate of existingDms) {
      const candidateUserIds = [...(snapshot.privateMemberIdsByChannelId.get(candidate.id) ?? [])].sort();
      if (candidateUserIds.length === userIds.length && candidateUserIds.every((id, index) => id === userIds[index])) {
        return { channelId: candidate.id, created: false };
      }
    }

    if (existingDms.length >= MAX_DMS_PER_WORKSPACE) throw new Error('DM_WORKSPACE_LIMIT_REACHED');
    const actorDms = await tx.select({ id: dmConversations.id })
      .from(dmConversations)
      .innerJoin(channels, eq(dmConversations.channelId, channels.id))
      .where(and(
        eq(channels.workspaceId, workspaceId),
        eq(channels.type, 'dm'),
        eq(dmConversations.createdBy, actorId),
      ))
      .limit(MAX_DMS_PER_USER_PER_WORKSPACE + 1);
    if (actorDms.length >= MAX_DMS_PER_USER_PER_WORKSPACE) throw new Error('DM_USER_LIMIT_REACHED');

    const [channel] = await tx.insert(channels).values({
      workspaceId,
      name: 'direct-message',
      type: 'dm',
      isPrivate: true,
      position: 0,
    }).returning();
    await tx.insert(channelMembers).values(userIds.map((userId) => ({ channelId: channel.id, userId })));
    const [conversation] = await tx.insert(dmConversations).values({ channelId: channel.id, createdBy: actorId }).returning();
    await tx.insert(dmMembers).values(userIds.map((userId) => ({ conversationId: conversation.id, userId })));
    return { channelId: channel.id, created: true };
  }, (committed) => ({
    actorId,
    action: committed.created ? 'dm.create' : 'dm.reuse',
    targetType: 'channel',
    targetId: committed.channelId,
    details: { workspaceId, memberCount: userIds.length },
  }));
  return getDmByChannelId(result.channelId, actorId);
}

export async function listDms(workspaceId: string, userId: string) {
  return db.transaction(async (transaction) => {
    await lockWorkspaceForAuthorization(transaction, workspaceId, 'share');
    const snapshot = await loadWorkspaceAuthorizationSnapshot(transaction, workspaceId);
    if (!snapshot) return [];
    const visibleChannels = snapshot.channels
      .filter((channel) => channel.type === 'dm')
      .filter((channel) => isVisibleChannelAuthorization(
        getChannelAuthorizationFromSnapshot(snapshot, userId, channel, {}, false),
      ));
    const memberIds = [...new Set(visibleChannels.flatMap((channel) => (
      [...(snapshot.privateMemberIdsByChannelId.get(channel.id) ?? [])]
    )))];
    const memberRows = memberIds.length === 0 ? [] : await transaction.query.users.findMany({
      columns: { id: true, displayName: true, avatarUrl: true, status: true, createdAt: true },
      where: inArray(users.id, memberIds),
      limit: MAX_WORKSPACE_MEMBERS + 1,
    });
    if (memberRows.length > MAX_WORKSPACE_MEMBERS) throw new Error('WORKSPACE_MEMBER_INVARIANT_EXCEEDED');
    const usersById = new Map(memberRows.map((user: any) => [user.id, user]));
    return visibleChannels.map((channel: any) => ({
      id: channel.id,
      channelId: channel.id,
      workspaceId: channel.workspaceId,
      createdAt: channel.createdAt.toISOString(),
      members: [...(snapshot.privateMemberIdsByChannelId.get(channel.id) ?? [])]
        .sort()
        .flatMap((memberId) => {
          const user = usersById.get(memberId) as any;
          return user ? [{
            id: user.id,
            displayName: user.displayName,
            avatarUrl: user.avatarUrl,
            status: user.status,
            createdAt: user.createdAt.toISOString(),
          }] : [];
        }),
    }));
  });
}

async function getDmByChannelId(channelId: string, userId: string) {
  const channel = await db.query.channels.findFirst({ where: eq(channels.id, channelId) });
  if (!channel || channel.type !== 'dm') throw new Error('DM_NOT_FOUND');
  if (!isVisibleChannelAuthorization(await getChannelAuthorizationFromStore(db, userId, channel))) {
    throw new Error('DM_NOT_FOUND');
  }
  const memberships = await db.query.channelMembers.findMany({
    columns: { userId: true },
    where: eq(channelMembers.channelId, channelId),
    limit: MAX_WORKSPACE_MEMBERS + 1,
  });
  if (memberships.length > MAX_WORKSPACE_MEMBERS) throw new Error('WORKSPACE_MEMBER_INVARIANT_EXCEEDED');
  const memberRows = await db.query.users.findMany({
    columns: { id: true, displayName: true, avatarUrl: true, status: true, createdAt: true },
    where: inArray(users.id, memberships.map((membership) => membership.userId)),
    limit: MAX_WORKSPACE_MEMBERS + 1,
  });
  if (memberRows.length > MAX_WORKSPACE_MEMBERS) throw new Error('WORKSPACE_MEMBER_INVARIANT_EXCEEDED');
  return {
    id: channel.id,
    channelId: channel.id,
    workspaceId: channel.workspaceId,
    createdAt: channel.createdAt.toISOString(),
    members: memberRows.map((user) => ({
      id: user.id,
      displayName: user.displayName,
      avatarUrl: user.avatarUrl,
      status: user.status,
      createdAt: user.createdAt.toISOString(),
    })),
  };
}
