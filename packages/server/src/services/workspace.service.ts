import { db } from '../db/index.js';
import { workspaces, workspaceMembers, roles, memberRoles, channels, categories } from '../db/schema.js';
import { eq, and } from 'drizzle-orm';
import { DefaultRoles } from '@alparts/shared';
import { audit } from '../middleware/audit.js';

export async function createWorkspace(name: string, ownerId: string, iconUrl?: string) {
  const [workspace] = await db.insert(workspaces).values({
    name,
    ownerId,
    iconUrl: iconUrl || null,
  }).returning();

  const [member] = await db.insert(workspaceMembers).values({
    workspaceId: workspace.id,
    userId: ownerId,
  }).returning();

  const roleEntries = Object.entries(DefaultRoles).map(([roleName, perms]) => ({
    workspaceId: workspace.id,
    name: roleName,
    permissions: perms,
    position: roleName === 'Owner' ? 100 : roleName === 'Administrator' ? 90 : 50,
  }));

  const createdRoles = await db.insert(roles).values(roleEntries).returning();

  const ownerRole = createdRoles.find(r => r.name === 'Owner');
  if (ownerRole) {
    await db.insert(memberRoles).values({
      memberId: member.id,
      roleId: ownerRole.id,
    });
  }

  const [defaultCategory] = await db.insert(categories).values({
    workspaceId: workspace.id,
    name: 'General',
    position: 0,
  }).returning();

  await db.insert(channels).values({
    workspaceId: workspace.id,
    categoryId: defaultCategory.id,
    name: 'general',
    type: 'text',
    position: 0,
  });

  await audit({
    actorId: ownerId,
    action: 'workspace.create',
    targetType: 'workspace',
    targetId: workspace.id,
    details: { name },
  });

  return workspace;
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
      email: m.user.email,
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

export async function addMember(workspaceId: string, userId: string, actorId: string) {
  const [member] = await db.insert(workspaceMembers).values({
    workspaceId,
    userId,
  }).returning();

  const memberRole = await db.query.roles.findFirst({
    where: and(
      eq(roles.workspaceId, workspaceId),
      eq(roles.name, 'Member'),
    ),
  });
  if (memberRole) {
    await db.insert(memberRoles).values({
      memberId: member.id,
      roleId: memberRole.id,
    });
  }

  await audit({
    actorId,
    action: 'workspace.member.add',
    targetType: 'workspace',
    targetId: workspaceId,
    details: { addedUserId: userId },
  });

  return member;
}
