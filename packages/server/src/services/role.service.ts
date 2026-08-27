import { and, desc, eq, gt, inArray, isNull, ne, sql } from 'drizzle-orm';
import { DefaultRoles, Permissions } from '@alparts/shared';
import { db } from '../db/index.js';
import {
  channelKeys,
  categoryRolePermissionOverrides,
  channelRolePermissionOverrides,
  channels,
  memberRoles,
  roles,
  workspaceInvitations,
  workspaceMembers,
  workspaces,
} from '../db/schema.js';
import { auditedTransaction } from '../middleware/audit.js';
import {
  applyViewerEffectsAndRotation,
  captureChannelViewersFromStore,
  computeAuthorizationRevisionFromStore,
  lockWorkspaceForAuthorization,
} from './authorization.service.js';

export const ALL_PERMISSION_MASK = Object.values(Permissions).reduce((mask, permission) => mask | permission, 0);
const standardRoleNames = new Set(Object.keys(DefaultRoles).map((name) => name.toLowerCase()));

interface RoleMutation {
  roleId: string;
  included?: boolean;
  permissions?: number;
}

interface RolePreviewInput {
  operation: 'role.update' | 'role.delete' | 'role.assign' | 'role.unassign';
  roleId: string;
  userId?: string;
  permissions?: number;
}

export function assertValidPermissionMask(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || (value & ~ALL_PERMISSION_MASK) !== 0) {
    throw new Error('INVALID_PERMISSIONS');
  }
}

export function assertValidRolePosition(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > 1_000_000) {
    throw new Error('INVALID_POSITION');
  }
}

export async function listRoles(workspaceId: string) {
  const rows = await db.query.roles.findMany({
    where: eq(roles.workspaceId, workspaceId),
    orderBy: [desc(roles.position), desc(roles.id)],
  });
  return rows.map(formatRole);
}

export async function getEffectivePermissions(workspaceId: string, userId: string) {
  const evaluated = await evaluateMember(db, workspaceId, userId);
  if (!evaluated) throw new Error('MEMBER_NOT_FOUND');
  return evaluated;
}

export async function createRole(
  workspaceId: string,
  actorId: string,
  input: { name: string; permissions: number; position: number },
) {
  assertValidPermissionMask(input.permissions);
  assertValidRolePosition(input.position);
  const role = await auditedTransaction(async (transaction) => {
    await lockWorkspace(transaction, workspaceId);
    const actor = await getRoleManager(transaction, workspaceId, actorId);
    assertRoleNameAvailable(input.name);
    assertCanCreateOrAssign(actor, input.permissions, input.position);
    await assertNoCaseInsensitiveRoleName(transaction, workspaceId, input.name);
    const [created] = await transaction.insert(roles).values({ workspaceId, ...input }).returning();
    return created;
  }, (created) => ({
    actorId,
    action: 'role.create',
    targetType: 'role',
    targetId: created.id,
    details: { workspaceId, name: created.name, permissions: created.permissions, position: created.position },
  }));
  return formatRole(role);
}

export async function updateRole(
  workspaceId: string,
  roleId: string,
  actorId: string,
  updates: { name?: string; permissions?: number; position?: number },
  expectedAuthorizationRevision: string,
) {
  if (updates.permissions !== undefined) assertValidPermissionMask(updates.permissions);
  if (updates.position !== undefined) assertValidRolePosition(updates.position);
  const result = await auditedTransaction(async (transaction) => {
    await lockWorkspace(transaction, workspaceId);
    await assertAuthorizationRevision(transaction, workspaceId, expectedAuthorizationRevision);
    const actor = await getRoleManager(transaction, workspaceId, actorId);
    const existing = await findWorkspaceRole(transaction, workspaceId, roleId);
    if (!existing) throw new Error('ROLE_NOT_FOUND');
    assertRoleCanBeManaged(actor, existing);
    if (existing.name === 'Owner') throw new Error('OWNER_ROLE_PROTECTED');
    if (updates.name && updates.name !== existing.name) {
      if (isStandardRole(existing.name)) throw new Error('STANDARD_ROLE_PROTECTED');
      assertRoleNameAvailable(updates.name);
      await assertNoCaseInsensitiveRoleName(transaction, workspaceId, updates.name, roleId);
    }
    const nextPermissions = updates.permissions ?? existing.permissions;
    const nextPosition = updates.position ?? existing.position;
    assertCanCreateOrAssign(actor, nextPermissions, nextPosition);

    const assignedMembers = await transaction.query.memberRoles.findMany({
      where: eq(memberRoles.roleId, roleId),
      with: { member: true },
    });
    const affectedBefore = [];
    for (const assignment of assignedMembers) {
      if (!assignment.member || assignment.member.workspaceId !== workspaceId) continue;
      const evaluated = await evaluateMember(transaction, workspaceId, assignment.member.userId);
      if (evaluated) affectedBefore.push(evaluated);
    }
    const channelViewersBefore = await captureChannelViewersFromStore(transaction, workspaceId);

    const [updated] = await transaction.update(roles)
      .set(updates)
      .where(and(eq(roles.id, roleId), eq(roles.workspaceId, workspaceId)))
      .returning();
    if (!updated) throw new Error('ROLE_NOT_FOUND');

    const affectedAfter = [];
    for (const before of affectedBefore) {
      const evaluated = await evaluateMember(transaction, workspaceId, before.userId);
      if (evaluated) affectedAfter.push(evaluated);
    }
    const accessChanges = compareAccess(affectedBefore, affectedAfter);
    const channelViewersAfter = await captureChannelViewersFromStore(transaction, workspaceId);
    const roomEffects = await applyViewerEffectsAndRotation(transaction, channelViewersBefore, channelViewersAfter);
    return { existing, updated, affectedBefore, affectedAfter, accessChanges, roomEffects };
  }, (committed) => ({
    actorId,
    action: 'role.update',
    targetType: 'role',
    targetId: roleId,
    details: {
      workspaceId,
      before: { name: committed.existing.name, permissions: committed.existing.permissions, position: committed.existing.position },
      after: { name: committed.updated.name, permissions: committed.updated.permissions, position: committed.updated.position },
      affectedUserIds: committed.affectedAfter.map((member) => member.userId),
      lostAccessUserIds: committed.accessChanges.lostAccessUserIds,
    },
  }));
  return {
    role: formatRole(result.updated),
    affectedMembers: pairEvaluations(result.affectedBefore, result.affectedAfter),
    ...result.accessChanges,
    roomEffects: result.roomEffects,
    allChannelIds: [...new Set(result.roomEffects.map((effect) => effect.channelId))],
    keyedChannelIds: result.roomEffects.filter((effect) => effect.rotationRequired).map((effect) => effect.channelId),
  };
}

export async function deleteRole(
  workspaceId: string,
  roleId: string,
  actorId: string,
  expectedAuthorizationRevision: string,
) {
  const deleted = await auditedTransaction(async (transaction) => {
    await lockWorkspace(transaction, workspaceId);
    await assertAuthorizationRevision(transaction, workspaceId, expectedAuthorizationRevision);
    const actor = await getRoleManager(transaction, workspaceId, actorId);
    const existing = await findWorkspaceRole(transaction, workspaceId, roleId);
    if (!existing) throw new Error('ROLE_NOT_FOUND');
    assertRoleCanBeManaged(actor, existing);
    await assertRoleDeletable(transaction, workspaceId, existing);
    await transaction.delete(roles).where(and(eq(roles.id, roleId), eq(roles.workspaceId, workspaceId)));
    return existing;
  }, (removed) => ({
    actorId,
    action: 'role.delete',
    targetType: 'role',
    targetId: roleId,
    details: { workspaceId, name: removed.name, permissions: removed.permissions, position: removed.position },
  }));
  return { roleId, workspaceId };
}

export async function changeRoleAssignment(
  workspaceId: string,
  userId: string,
  roleId: string,
  actorId: string,
  action: 'assign' | 'unassign',
  expectedAuthorizationRevision: string,
) {
  const result = await auditedTransaction(async (transaction) => {
    await lockWorkspace(transaction, workspaceId);
    await assertAuthorizationRevision(transaction, workspaceId, expectedAuthorizationRevision);
    const actor = await getRoleManager(transaction, workspaceId, actorId);
    const role = await findWorkspaceRole(transaction, workspaceId, roleId);
    if (!role) throw new Error('ROLE_NOT_FOUND');
    if (role.name === 'Owner') throw new Error('OWNER_ROLE_PROTECTED');
    assertRoleCanBeManaged(actor, role);
    if (action === 'assign') assertCanCreateOrAssign(actor, role.permissions, role.position);
    const member = await transaction.query.workspaceMembers.findFirst({
      where: and(eq(workspaceMembers.workspaceId, workspaceId), eq(workspaceMembers.userId, userId)),
    });
    if (!member) throw new Error('MEMBER_NOT_FOUND');
    const before = await evaluateMember(transaction, workspaceId, userId);
    if (!before) throw new Error('MEMBER_NOT_FOUND');
    const channelViewersBefore = await captureChannelViewersFromStore(transaction, workspaceId);
    const existing = await transaction.query.memberRoles.findFirst({
      where: and(eq(memberRoles.memberId, member.id), eq(memberRoles.roleId, roleId)),
    });
    let changed = false;
    if (action === 'assign' && !existing) {
      await transaction.insert(memberRoles).values({ memberId: member.id, roleId });
      changed = true;
    }
    if (action === 'unassign' && existing) {
      await transaction.delete(memberRoles).where(and(eq(memberRoles.memberId, member.id), eq(memberRoles.roleId, roleId)));
      changed = true;
    }
    const after = await evaluateMember(transaction, workspaceId, userId);
    if (!after) throw new Error('MEMBER_NOT_FOUND');
    const accessChanges = compareAccess([before], [after]);
    const channelViewersAfter = await captureChannelViewersFromStore(transaction, workspaceId);
    const roomEffects = await applyViewerEffectsAndRotation(transaction, channelViewersBefore, channelViewersAfter);
    return { role, before, after, changed, accessChanges, roomEffects };
  }, (committed) => ({
    actorId,
    action: `role.${action}`,
    targetType: 'role',
    targetId: roleId,
    details: {
      workspaceId,
      userId,
      changed: committed.changed,
      before: committed.before.effectivePermissions,
      after: committed.after.effectivePermissions,
    },
  }));
  return {
    workspaceId,
    userId,
    roleId,
    action,
    changed: result.changed,
    before: result.before,
    after: result.after,
    ...result.accessChanges,
    roomEffects: result.roomEffects,
    allChannelIds: [...new Set(result.roomEffects.map((effect) => effect.channelId))],
    keyedChannelIds: result.roomEffects.filter((effect) => effect.rotationRequired).map((effect) => effect.channelId),
  };
}

export async function previewRoleChange(workspaceId: string, actorId: string, input: RolePreviewInput) {
  return db.transaction(async (transaction) => {
    await lockWorkspaceForAuthorization(transaction, workspaceId, 'share');
    const authorizationRevision = await computeAuthorizationRevisionFromStore(transaction, workspaceId);
    const actor = await getRoleManager(transaction, workspaceId, actorId);
    const role = await findWorkspaceRole(transaction, workspaceId, input.roleId);
    if (!role) throw new Error('ROLE_NOT_FOUND');
    assertRoleCanBeManaged(actor, role);
    if (role.name === 'Owner') throw new Error('OWNER_ROLE_PROTECTED');

    if (input.operation === 'role.update' && input.permissions === undefined) throw new Error('INVALID_PREVIEW');
    if (input.permissions !== undefined) {
      assertValidPermissionMask(input.permissions);
      assertCanCreateOrAssign(actor, input.permissions, role.position);
    }
    if (input.operation === 'role.assign' || input.operation === 'role.unassign') {
      if (!input.userId) throw new Error('INVALID_PREVIEW');
      if (input.operation === 'role.assign') assertCanCreateOrAssign(actor, role.permissions, role.position);
      const before = await evaluateMember(transaction, workspaceId, input.userId);
      if (!before) throw new Error('MEMBER_NOT_FOUND');
      const after = await evaluateMember(transaction, workspaceId, input.userId, {
        roleId: role.id,
        included: input.operation === 'role.assign',
      });
      if (!after) throw new Error('MEMBER_NOT_FOUND');
      return { ...previewResponse(workspaceId, input.operation, [before], [after]), authorizationRevision };
    }

    if (input.operation === 'role.delete') {
      await assertRoleDeletable(transaction, workspaceId, role);
      return { ...previewResponse(workspaceId, input.operation, [], []), authorizationRevision };
    }

    const assignments = await transaction.query.memberRoles.findMany({
      where: eq(memberRoles.roleId, role.id),
      with: { member: true },
    });
    const before = [];
    const after = [];
    for (const assignment of assignments) {
      if (!assignment.member || assignment.member.workspaceId !== workspaceId) continue;
      const current = await evaluateMember(transaction, workspaceId, assignment.member.userId);
      const proposed = await evaluateMember(transaction, workspaceId, assignment.member.userId, {
        roleId: role.id,
        included: true,
        permissions: input.permissions,
      });
      if (current && proposed) {
        before.push(current);
        after.push(proposed);
      }
    }
    return { ...previewResponse(workspaceId, input.operation, before, after), authorizationRevision };
  });
}

async function getRoleManager(store: any, workspaceId: string, actorId: string) {
  const workspace = await store.query.workspaces.findFirst({
    columns: { ownerId: true },
    where: eq(workspaces.id, workspaceId),
  });
  if (!workspace) throw new Error('WORKSPACE_NOT_FOUND');
  const evaluated = await evaluateMember(store, workspaceId, actorId);
  if (!evaluated) throw new Error('NOT_AUTHORIZED');
  const owner = workspace.ownerId === actorId;
  if (!owner && (evaluated.permissionMask & Permissions.MANAGE_ROLES) !== Permissions.MANAGE_ROLES) {
    throw new Error('NOT_AUTHORIZED');
  }
  const highestPosition = owner
    ? 1_000_001
    : Math.max(-1, ...evaluated.roles.map((role: { position: number }) => role.position));
  return { owner, permissions: evaluated.permissionMask, highestPosition };
}

function assertCanCreateOrAssign(
  actor: { owner: boolean; permissions: number; highestPosition: number },
  permissions: number,
  position: number,
) {
  if (actor.owner) return;
  if (position >= actor.highestPosition) throw new Error('ROLE_HIERARCHY');
  if ((permissions & ~actor.permissions) !== 0) throw new Error('PERMISSION_ESCALATION');
}

function assertRoleCanBeManaged(actor: { owner: boolean; highestPosition: number }, role: { name: string; position: number }) {
  if (role.name === 'Owner') throw new Error('OWNER_ROLE_PROTECTED');
  if (!actor.owner && role.position >= actor.highestPosition) throw new Error('ROLE_HIERARCHY');
}

async function evaluateMember(store: any, workspaceId: string, userId: string, mutation?: RoleMutation) {
  const member = await store.query.workspaceMembers.findFirst({
    where: and(eq(workspaceMembers.workspaceId, workspaceId), eq(workspaceMembers.userId, userId)),
  });
  if (!member) return null;
  const assignments = await store.query.memberRoles.findMany({
    where: eq(memberRoles.memberId, member.id),
    with: { role: true },
  });
  let assignedRoles = assignments
    .map((assignment: any) => assignment.role)
    .filter((role: any) => role && role.workspaceId === workspaceId);
  if (mutation) {
    assignedRoles = assignedRoles.filter((role: any) => role.id !== mutation.roleId);
    if (mutation.included !== false) {
      const source = assignments.find((assignment: any) => assignment.role?.id === mutation.roleId)?.role
        || await findWorkspaceRole(store, workspaceId, mutation.roleId);
      if (source) assignedRoles.push({ ...source, permissions: mutation.permissions ?? source.permissions });
    }
  }
  assignedRoles.sort((left: any, right: any) => (
    right.position - left.position || right.id.localeCompare(left.id)
  ));
  const permissionMask = assignedRoles.reduce((mask: number, role: any) => mask | role.permissions, 0);
  const permissionDetails = Object.entries(Permissions).map(([permission, value]) => ({
    permission,
    value,
    allowed: (permissionMask & value) === value,
    reasons: assignedRoles
      .filter((role: any) => (role.permissions & value) === value)
      .map((role: any) => ({ source: 'role' as const, roleId: role.id, roleName: role.name })),
  }));
  return {
    workspaceId,
    userId,
    permissionMask,
    effectivePermissions: permissionMask.toString(),
    roles: assignedRoles.map(formatRole),
    permissionDetails,
  };
}

function pairEvaluations(before: any[], after: any[]) {
  const afterByUser = new Map(after.map((member) => [member.userId, member]));
  return before.map((previous) => {
    const next = afterByUser.get(previous.userId) || previous;
    return {
      userId: previous.userId,
      before: previous,
      after: next,
      gained: permissionNames(next.permissionMask & ~previous.permissionMask),
      lost: permissionNames(previous.permissionMask & ~next.permissionMask),
    };
  });
}

function previewResponse(workspaceId: string, operation: string, before: any[], after: any[]) {
  const affectedMembers = pairEvaluations(before, after);
  const accessChanges = compareAccess(before, after);
  return {
    workspaceId,
    operation,
    affectedMembers,
    affectedUserIds: affectedMembers.map((member) => member.userId),
    ...accessChanges,
    requiresKeyRotation: accessChanges.lostAccessUserIds.length > 0,
  };
}

function compareAccess(before: any[], after: any[]) {
  const afterByUser = new Map(after.map((member) => [member.userId, member.permissionMask]));
  const lostAccessUserIds: string[] = [];
  const gainedAccessUserIds: string[] = [];
  for (const previous of before) {
    const nextMask = afterByUser.get(previous.userId) ?? previous.permissionMask;
    const hadView = (previous.permissionMask & Permissions.VIEW_CHANNELS) === Permissions.VIEW_CHANNELS;
    const hasView = (nextMask & Permissions.VIEW_CHANNELS) === Permissions.VIEW_CHANNELS;
    if (hadView && !hasView) lostAccessUserIds.push(previous.userId);
    if (!hadView && hasView) gainedAccessUserIds.push(previous.userId);
  }
  return { lostAccessUserIds, gainedAccessUserIds };
}

async function markWorkspaceKeyRotation(store: any, workspaceId: string) {
  const workspaceChannels = await store.query.channels.findMany({
    columns: { id: true },
    where: eq(channels.workspaceId, workspaceId),
  });
  const allChannelIds: string[] = workspaceChannels.map((channel: { id: string }) => channel.id);
  if (allChannelIds.length === 0) return { allChannelIds, keyedChannelIds: [] as string[] };
  const keys = await store.query.channelKeys.findMany({
    columns: { channelId: true },
    where: inArray(channelKeys.channelId, allChannelIds),
  });
  const keyedChannelIds: string[] = [...new Set<string>(keys.map((key: { channelId: string }) => key.channelId))];
  if (keyedChannelIds.length > 0) {
    await store.update(channels).set({ keyRotationRequired: true }).where(inArray(channels.id, keyedChannelIds));
  }
  return { allChannelIds, keyedChannelIds };
}

async function lockWorkspace(store: any, workspaceId: string) {
  const locked = await store.execute(sql`select id from ${workspaces} where ${workspaces.id} = ${workspaceId} for update`);
  if (locked.rowCount === 0) throw new Error('WORKSPACE_NOT_FOUND');
}

async function findWorkspaceRole(store: any, workspaceId: string, roleId: string) {
  return store.query.roles.findFirst({ where: and(eq(roles.id, roleId), eq(roles.workspaceId, workspaceId)) });
}

async function assertNoCaseInsensitiveRoleName(store: any, workspaceId: string, name: string, excludingRoleId?: string) {
  const existing = await store.query.roles.findFirst({
    columns: { id: true },
    where: and(
      eq(roles.workspaceId, workspaceId),
      sql`lower(${roles.name}) = lower(${name})`,
      excludingRoleId ? ne(roles.id, excludingRoleId) : undefined,
    ),
  });
  if (existing) throw new Error('ROLE_NAME_EXISTS');
}

async function assertRoleDeletable(store: any, workspaceId: string, role: { id: string; name: string }) {
  if (isStandardRole(role.name)) {
    throw new Error(role.name === 'Owner' ? 'OWNER_ROLE_PROTECTED' : 'STANDARD_ROLE_PROTECTED');
  }
  const assignment = await store.query.memberRoles.findFirst({
    columns: { memberId: true },
    where: eq(memberRoles.roleId, role.id),
  });
  if (assignment) throw new Error('ROLE_IN_USE');
  const activeInvitation = await store.query.workspaceInvitations.findFirst({
    columns: { id: true },
    where: and(
      eq(workspaceInvitations.workspaceId, workspaceId),
      eq(workspaceInvitations.roleId, role.id),
      isNull(workspaceInvitations.usedAt),
      isNull(workspaceInvitations.revokedAt),
      gt(workspaceInvitations.expiresAt, new Date()),
    ),
  });
  if (activeInvitation) throw new Error('ROLE_IN_USE');
  const categoryOverride = await store.query.categoryRolePermissionOverrides.findFirst({
    columns: { roleId: true },
    where: and(
      eq(categoryRolePermissionOverrides.workspaceId, workspaceId),
      eq(categoryRolePermissionOverrides.roleId, role.id),
    ),
  });
  if (categoryOverride) throw new Error('ROLE_IN_USE');
  const channelOverride = await store.query.channelRolePermissionOverrides.findFirst({
    columns: { roleId: true },
    where: and(
      eq(channelRolePermissionOverrides.workspaceId, workspaceId),
      eq(channelRolePermissionOverrides.roleId, role.id),
    ),
  });
  if (channelOverride) throw new Error('ROLE_IN_USE');
}

async function assertAuthorizationRevision(store: any, workspaceId: string, expected: string) {
  if (!/^[a-f0-9]{64}$/.test(expected)) throw new Error('INVALID_AUTHORIZATION_REVISION');
  const current = await computeAuthorizationRevisionFromStore(store, workspaceId);
  if (current !== expected) throw new Error('STALE_PREVIEW');
}

function assertRoleNameAvailable(name: string) {
  if (standardRoleNames.has(name.toLowerCase())) throw new Error('STANDARD_ROLE_NAME_RESERVED');
}

function isStandardRole(name: string): boolean {
  return standardRoleNames.has(name.toLowerCase());
}

function permissionNames(mask: number): string[] {
  return Object.entries(Permissions)
    .filter(([, value]) => (mask & value) === value)
    .map(([name]) => name);
}

function formatRole(role: any) {
  return {
    id: role.id,
    workspaceId: role.workspaceId,
    name: role.name,
    permissions: role.permissions.toString(),
    permissionMask: role.permissions,
    position: role.position,
    standard: isStandardRole(role.name),
    createdAt: role.createdAt instanceof Date ? role.createdAt.toISOString() : role.createdAt,
  };
}
