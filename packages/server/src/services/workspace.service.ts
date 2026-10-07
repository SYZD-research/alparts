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
  mlsGroupMembers,
  dmConversations,
  dmMembers,
  profileFlags,
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
import {
  MAX_ROLE_ASSIGNMENTS_PER_MEMBER,
  MAX_DMS_PER_WORKSPACE,
  MAX_TOTAL_CHANNELS_PER_WORKSPACE,
  MAX_WORKSPACE_MEMBERS,
  MAX_WORKSPACES_OWNED_PER_USER,
  MAX_WORKSPACE_MEMBERSHIPS_PER_USER,
} from '../security/limits.js';

export async function createWorkspace(name: string, ownerId: string, iconUrl?: string) {
  const workspace = await auditedTransaction(async (tx) => {
    // Workspace creation and invitation acceptance share this account-scoped
    // lock. Without it, accepts in different workspaces can race the same
    // per-account membership limit.
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`workspace-memberships:${ownerId}`})::bigint)`);
    const owned = await tx.query.workspaces.findMany({
      columns: { id: true },
      where: eq(workspaces.ownerId, ownerId),
      limit: MAX_WORKSPACES_OWNED_PER_USER + 1,
    });
    if (owned.length >= MAX_WORKSPACES_OWNED_PER_USER) throw new Error('WORKSPACE_LIMIT_REACHED');
    const memberships = await tx.query.workspaceMembers.findMany({
      columns: { id: true },
      where: eq(workspaceMembers.userId, ownerId),
      limit: MAX_WORKSPACE_MEMBERSHIPS_PER_USER + 1,
    });
    if (memberships.length >= MAX_WORKSPACE_MEMBERSHIPS_PER_USER) {
      throw new Error('WORKSPACE_MEMBERSHIP_LIMIT_REACHED');
    }
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
    limit: MAX_WORKSPACE_MEMBERSHIPS_PER_USER + 1,
  });
  if (memberships.length > MAX_WORKSPACE_MEMBERSHIPS_PER_USER) {
    throw new Error('WORKSPACE_MEMBERSHIP_INVARIANT_EXCEEDED');
  }

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
    },
    limit: MAX_WORKSPACE_MEMBERS + 1,
  });
  if (members.length > MAX_WORKSPACE_MEMBERS) throw new Error('WORKSPACE_MEMBER_INVARIANT_EXCEEDED');
  const memberIds = members.map((member) => member.id);
  const assignments = memberIds.length === 0 ? [] : await db.query.memberRoles.findMany({
    where: inArray(memberRoles.memberId, memberIds),
    with: { role: true },
    limit: MAX_WORKSPACE_MEMBERS * MAX_ROLE_ASSIGNMENTS_PER_MEMBER + 1,
  });
  if (assignments.length > MAX_WORKSPACE_MEMBERS * MAX_ROLE_ASSIGNMENTS_PER_MEMBER) {
    throw new Error('ROLE_ASSIGNMENT_INVARIANT_EXCEEDED');
  }
  const assignmentsByMember = new Map<string, typeof assignments>();
  for (const assignment of assignments) {
    if (!assignment.role || assignment.role.workspaceId !== workspaceId) {
      throw new Error('ROLE_ASSIGNMENT_INVARIANT_EXCEEDED');
    }
    const current = assignmentsByMember.get(assignment.memberId) ?? [];
    current.push(assignment);
    if (current.length > MAX_ROLE_ASSIGNMENTS_PER_MEMBER) {
      throw new Error('ROLE_ASSIGNMENT_INVARIANT_EXCEEDED');
    }
    assignmentsByMember.set(assignment.memberId, current);
  }

  const memberUserIds = members.map((m: any) => m.userId as string);
  const flaggedUserIds = new Set(memberUserIds.length === 0 ? [] : (await db.select({ userId: profileFlags.userId })
    .from(profileFlags)
    .where(and(eq(profileFlags.workspaceId, workspaceId), inArray(profileFlags.userId, memberUserIds)))
    .limit(MAX_WORKSPACE_MEMBERS + 1) as Array<{ userId: string }>).map((row) => row.userId));

  return members.map((m: any) => ({
    id: m.id,
    workspaceId: m.workspaceId,
    userId: m.userId,
    profileFlagged: flaggedUserIds.has(m.userId),
    user: {
      id: m.user.id,
      displayName: m.user.displayName,
      avatarUrl: m.user.avatarUrl,
      status: m.user.status,
      createdAt: m.user.createdAt.toISOString(),
    },
    roles: (assignmentsByMember.get(m.id) ?? []).map((mr: any) => ({
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
      limit: MAX_TOTAL_CHANNELS_PER_WORKSPACE + 1,
    });
    if (workspaceChannels.length > MAX_TOTAL_CHANNELS_PER_WORKSPACE) throw new Error('CHANNEL_INVARIANT_EXCEEDED');
    const channelIds: string[] = workspaceChannels.map((channel: { id: string }) => channel.id);
    for (const channelId of [...channelIds].sort()) {
      await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${channelId})::bigint)`);
    }
    const explicitPrivateMemberships = channelIds.length === 0 ? [] : await tx.select({ channelId: channelMembers.channelId })
      .from(channelMembers)
      .innerJoin(channels, and(eq(channels.id, channelMembers.channelId), eq(channels.isPrivate, true)))
      .where(and(eq(channelMembers.userId, userId), inArray(channelMembers.channelId, channelIds)))
      .limit(MAX_TOTAL_CHANNELS_PER_WORKSPACE + 1);
    if (explicitPrivateMemberships.length > MAX_TOTAL_CHANNELS_PER_WORKSPACE) {
      throw new Error('PRIVATE_MEMBERSHIP_INVARIANT_EXCEEDED');
    }
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
      // A device of the user was in the channel's group (group protocol 4).
      const groupChannels = await tx.selectDistinct({ channelId: mlsGroupMembers.channelId })
        .from(mlsGroupMembers)
        .where(and(eq(mlsGroupMembers.userId, userId), inArray(mlsGroupMembers.channelId, channelIds)));
      for (const row of [
        ...authoredChannels,
        ...readChannels,
        ...preferenceChannels,
        ...bookmarkedChannels,
        ...keyedChannels,
        ...groupChannels,
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
        ))
        .limit(MAX_DMS_PER_WORKSPACE + 1);
      if (workspaceDmRows.length > MAX_DMS_PER_WORKSPACE) throw new Error('DM_INVARIANT_EXCEEDED');
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
