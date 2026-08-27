import { and, eq, inArray, sql } from 'drizzle-orm';
import { Permissions } from '@alparts/shared';
import { db } from '../db/index.js';
import {
  channelMembers,
  channels,
  dmConversations,
  dmMembers,
  users,
  workspaceMembers,
  workspaces,
} from '../db/schema.js';
import { auditedTransaction } from '../middleware/audit.js';
import { MAX_CHANNELS_PER_WORKSPACE } from '../security/limits.js';
import {
  getChannelAuthorizationFromStore,
  getWorkspaceAuthorizationFromStore,
  isVisibleChannelAuthorization,
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

    for (const userId of userIds) {
      const authorization = await getWorkspaceAuthorizationFromStore(tx, workspaceId, userId);
      if (!authorization || (authorization.permissionMask & Permissions.VIEW_CHANNELS) !== Permissions.VIEW_CHANNELS) {
        throw new Error('DM_MEMBER_NOT_FOUND');
      }
    }

    const actorMemberships = await tx.query.channelMembers.findMany({
      columns: { channelId: true },
      where: eq(channelMembers.userId, actorId),
    }) as Array<{ channelId: string }>;
    if (actorMemberships.length > 0) {
      const candidates = await tx.query.channels.findMany({
        columns: { id: true },
        where: and(
          eq(channels.workspaceId, workspaceId),
          eq(channels.type, 'dm'),
          inArray(channels.id, actorMemberships.map((membership) => membership.channelId)),
        ),
      }) as Array<{ id: string }>;
      for (const candidate of candidates) {
        const members = await tx.query.channelMembers.findMany({
          columns: { userId: true },
          where: eq(channelMembers.channelId, candidate.id),
        }) as Array<{ userId: string }>;
        const candidateUserIds = members.map((member) => member.userId).sort();
        if (candidateUserIds.length === userIds.length && candidateUserIds.every((id, index) => id === userIds[index])) {
          return { channelId: candidate.id, created: false };
        }
      }
    }

    const existingChannels = await tx.query.channels.findMany({
      columns: { id: true },
      where: eq(channels.workspaceId, workspaceId),
      limit: MAX_CHANNELS_PER_WORKSPACE + 1,
    });
    if (existingChannels.length >= MAX_CHANNELS_PER_WORKSPACE) throw new Error('CHANNEL_LIMIT_REACHED');

    const [channel] = await tx.insert(channels).values({
      workspaceId,
      name: 'direct-message',
      type: 'dm',
      isPrivate: true,
      position: 0,
    }).returning();
    await tx.insert(channelMembers).values(userIds.map((userId) => ({ channelId: channel.id, userId })));
    const [conversation] = await tx.insert(dmConversations).values({ channelId: channel.id }).returning();
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
  const memberships = await db.query.channelMembers.findMany({
    columns: { channelId: true },
    where: eq(channelMembers.userId, userId),
  });
  if (memberships.length === 0) return [];
  const rows = await db.query.channels.findMany({
    where: and(
      eq(channels.workspaceId, workspaceId),
      eq(channels.type, 'dm'),
      inArray(channels.id, memberships.map((membership) => membership.channelId)),
    ),
  });
  const visible = [];
  for (const channel of rows) {
    if (isVisibleChannelAuthorization(await getChannelAuthorizationFromStore(db, userId, channel))) {
      visible.push(await getDmByChannelId(channel.id, userId));
    }
  }
  return visible;
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
  });
  const memberRows = await db.query.users.findMany({
    columns: { id: true, displayName: true, avatarUrl: true, status: true, createdAt: true },
    where: inArray(users.id, memberships.map((membership) => membership.userId)),
  });
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
