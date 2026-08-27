import { db } from '../db/index.js';
import {
  workspaces,
  workspaceMembers,
  roles,
  memberRoles,
  channels,
  categories,
  channelMembers,
  messages,
  readPositions,
  channelPreferences,
  messageBookmarks,
  channelKeys,
  devices,
  dmConversations,
  dmMembers,
} from '../db/schema.js';
import { eq, and, inArray } from 'drizzle-orm';
import { sql } from 'drizzle-orm';
import { DefaultRoles, Permissions } from '@alparts/shared';
import { auditedTransaction } from '../middleware/audit.js';
import {
  applyViewerEffectsAndRotation,
  captureChannelViewersFromStore,
  getWorkspaceAuthorizationFromStore,
} from './authorization.service.js';

export async function createWorkspace(name: string, ownerId: string, iconUrl?: string) {
  const workspace = await auditedTransaction(async (tx) => {
    const [created] = await tx.insert(workspaces).values({
      name,
      ownerId,
      iconUrl: iconUrl || null,
    }).returning();
    const [member] = await tx.insert(workspaceMembers).values({ workspaceId: created.id, userId: ownerId }).returning();
    const roleEntries = Object.entries(DefaultRoles).map(([roleName, perms]) => ({
      workspaceId: created.id,
      name: roleName,
      permissions: perms,
      position: defaultRolePosition(roleName),
    }));
    const createdRoles = await tx.insert(roles).values(roleEntries).returning();
    const ownerRole = createdRoles.find((role: { name: string }) => role.name === 'Owner');
    if (!ownerRole) throw new Error('OWNER_ROLE_MISSING');
    await tx.insert(memberRoles).values({ memberId: member.id, roleId: ownerRole.id });
    const [defaultCategory] = await tx.insert(categories).values({
      workspaceId: created.id,
      name: 'General',
      position: 0,
    }).returning();
    await tx.insert(channels).values({
      workspaceId: created.id,
      categoryId: defaultCategory.id,
      name: 'general',
      type: 'text',
      position: 0,
    });
    return created;
  }, (created) => ({
    actorId: ownerId,
    action: 'workspace.create',
    targetType: 'workspace',
    targetId: created.id,
    details: { name },
  }));

  return workspace;
}

function defaultRolePosition(roleName: string): number {
  if (roleName === 'Owner') return 100;
  if (roleName === 'Administrator') return 90;
  if (roleName === 'SecurityManager') return 80;
  if (roleName === 'Member') return 50;
  return 20;
}

export async function getUserWorkspaces(userId: string) {
  const memberships = await db.query.workspaceMembers.findMany({
    where: eq(workspaceMembers.userId, userId),
    with: {
      workspace: true,
    },
  });

  return memberships.map(m => ({
    id: m.workspace.id,
    name: m.workspace.name,
    iconUrl: m.workspace.iconUrl,
    ownerId: m.workspace.ownerId,
    createdAt: m.workspace.createdAt.toISOString(),
  }));
}

export async function getWorkspaceById(workspaceId: string) {
  const workspace = await db.query.workspaces.findFirst({
    where: eq(workspaces.id, workspaceId),
  });
  if (!workspace) return null;
  return {
    id: workspace.id,
    name: workspace.name,
    iconUrl: workspace.iconUrl,
    ownerId: workspace.ownerId,
    createdAt: workspace.createdAt.toISOString(),
  };
}

export async function getWorkspaceMembers(workspaceId: string) {
  const members = await db.query.workspaceMembers.findMany({
    where: eq(workspaceMembers.workspaceId, workspaceId),
    with: {
      user: true,
      memberRoles: {
        with: {
          role: true,
        },
      },
    },
  });

  return members.map((m: any) => ({
    id: m.id,
    workspaceId: m.workspaceId,
    userId: m.userId,
    user: {
      id: m.user.id,
      displayName: m.user.displayName,
      avatarUrl: m.user.avatarUrl,
      status: m.user.status,
      createdAt: m.user.createdAt.toISOString(),
    },
    roles: m.memberRoles.map((mr: any) => ({
      id: mr.role.id,
      workspaceId: mr.role.workspaceId,
      name: mr.role.name,
      permissions: mr.role.permissions.toString(),
      position: mr.role.position,
    })),
    joinedAt: m.joinedAt.toISOString(),
  }));
}

export async function removeMember(workspaceId: string, userId: string, actorId: string) {
  const result = await auditedTransaction(async (tx) => {
    const workspace = await lockWorkspace(tx, workspaceId);
    await assertMemberRemovalAuthorized(tx, workspaceId, actorId, userId);
    if (workspace.ownerId === userId) throw new Error('OWNER_CANNOT_BE_REMOVED');
    const member = await tx.query.workspaceMembers.findFirst({
      where: and(eq(workspaceMembers.workspaceId, workspaceId), eq(workspaceMembers.userId, userId)),
    });
    if (!member) throw new Error('MEMBER_NOT_FOUND');
    const workspaceChannels = await tx.query.channels.findMany({
      columns: { id: true },
      where: eq(channels.workspaceId, workspaceId),
    });
    const channelIds: string[] = workspaceChannels.map((channel: { id: string }) => channel.id);
    for (const channelId of [...channelIds].sort()) {
      await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${channelId})::bigint)`);
    }
    const explicitPrivateMemberships = channelIds.length === 0 ? [] : await tx.select({ channelId: channelMembers.channelId })
      .from(channelMembers)
      .innerJoin(channels, and(eq(channels.id, channelMembers.channelId), eq(channels.isPrivate, true)))
      .where(and(eq(channelMembers.userId, userId), inArray(channelMembers.channelId, channelIds)));
    const before = await captureChannelViewersFromStore(tx, workspaceId, channelIds);
    // Realtime removal must tell the client which locally persisted channel
    // state to erase without revealing private/overridden channels it never
    // knew. Include currently visible channels plus durable evidence of prior
    // authorization or interaction.
    const knownChannelIds = new Set<string>();
    for (const [channelId, viewerIds] of before) {
      if (viewerIds.includes(userId)) knownChannelIds.add(channelId);
    }
    for (const membership of explicitPrivateMemberships) knownChannelIds.add(membership.channelId);
    if (channelIds.length > 0) {
      const authoredChannels = await tx.selectDistinct({ channelId: messages.channelId })
        .from(messages)
        .where(and(eq(messages.authorId, userId), inArray(messages.channelId, channelIds)));
      const readChannels = await tx.selectDistinct({ channelId: readPositions.channelId })
        .from(readPositions)
        .where(and(eq(readPositions.userId, userId), inArray(readPositions.channelId, channelIds)));
      const preferenceChannels = await tx.selectDistinct({ channelId: channelPreferences.channelId })
        .from(channelPreferences)
        .where(and(eq(channelPreferences.userId, userId), inArray(channelPreferences.channelId, channelIds)));
      const bookmarkedChannels = await tx.selectDistinct({ channelId: messages.channelId })
        .from(messageBookmarks)
        .innerJoin(messages, eq(messageBookmarks.messageId, messages.id))
        .where(and(eq(messageBookmarks.userId, userId), inArray(messages.channelId, channelIds)));
      const keyedChannels = await tx.selectDistinct({ channelId: channelKeys.channelId })
        .from(channelKeys)
        .innerJoin(devices, eq(channelKeys.deviceId, devices.id))
        .where(and(eq(devices.userId, userId), inArray(channelKeys.channelId, channelIds)));
      for (const row of [
        ...authoredChannels,
        ...readChannels,
        ...preferenceChannels,
        ...bookmarkedChannels,
        ...keyedChannels,
      ]) {
        knownChannelIds.add(row.channelId);
      }
    }

    if (channelIds.length > 0) {
      const workspaceDmRows = await tx.select({ conversationId: dmConversations.id })
        .from(dmConversations)
        .innerJoin(channels, eq(dmConversations.channelId, channels.id))
        .where(and(
          eq(channels.workspaceId, workspaceId),
          inArray(channels.id, channelIds),
        ));
      if (workspaceDmRows.length > 0) {
        await tx.delete(dmMembers).where(and(
          eq(dmMembers.userId, userId),
          inArray(dmMembers.conversationId, workspaceDmRows.map((row: { conversationId: string }) => row.conversationId)),
        ));
      }
      await tx.delete(channelMembers).where(and(
        eq(channelMembers.userId, userId),
        inArray(channelMembers.channelId, channelIds),
      ));
    }
    await tx.delete(memberRoles).where(eq(memberRoles.memberId, member.id));
    await tx.delete(workspaceMembers).where(eq(workspaceMembers.id, member.id));
    const after = await captureChannelViewersFromStore(tx, workspaceId, channelIds);
    const roomEffects = await applyViewerEffectsAndRotation(tx, before, after);
    const keyedChannelIds = roomEffects.filter((effect) => effect.rotationRequired).map((effect) => effect.channelId);
    return {
      allChannelIds: channelIds,
      revokedChannelIds: [...knownChannelIds].sort(),
      keyedChannelIds,
      roomEffects,
    };
  }, (committed) => ({
    actorId,
    action: 'workspace.member.remove',
    targetType: 'workspace',
    targetId: workspaceId,
    details: {
      removedUserId: userId,
      removedChannelCount: committed.allChannelIds.length,
      revokedChannelCount: committed.revokedChannelIds.length,
      rekeyChannelCount: committed.keyedChannelIds.length,
    },
  }));
  return { removedUserId: userId, ...result };
}

async function lockWorkspace(store: any, workspaceId: string) {
  const locked = await store.execute(sql`select * from ${workspaces} where ${workspaces.id} = ${workspaceId} for update`);
  if (locked.rowCount === 0) throw new Error('WORKSPACE_NOT_FOUND');
  const workspace = await store.query.workspaces.findFirst({ where: eq(workspaces.id, workspaceId) });
  if (!workspace) throw new Error('WORKSPACE_NOT_FOUND');
  return workspace;
}

async function assertMemberRemovalAuthorized(
  store: any,
  workspaceId: string,
  actorId: string,
  targetId: string,
) {
  const actor = await getWorkspaceAuthorizationFromStore(store, workspaceId, actorId);
  const target = await getWorkspaceAuthorizationFromStore(store, workspaceId, targetId);
  if (!actor || !target) throw new Error('NOT_AUTHORIZED');
  if ((actor.permissionMask & Permissions.KICK_MEMBERS) !== Permissions.KICK_MEMBERS) {
    throw new Error('NOT_AUTHORIZED');
  }
  if (actor.isOwner) return;
  const actorPosition = Math.max(-1, ...actor.roles.map((role: { position: number }) => role.position));
  const targetPosition = target.isOwner
    ? Number.POSITIVE_INFINITY
    : Math.max(-1, ...target.roles.map((role: { position: number }) => role.position));
  if (actorPosition <= targetPosition) throw new Error('NOT_AUTHORIZED');
}
