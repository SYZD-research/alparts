import { createHash } from 'node:crypto';
import { and, asc, eq, inArray, sql } from 'drizzle-orm';
import { Permissions } from '@alparts/shared';
import { db } from '../db/index.js';
import {
  categoryRolePermissionOverrides,
  channelMembers,
  channelRolePermissionOverrides,
  channels,
  memberRoles,
  roles,
  workspaceMembers,
  workspaces,
} from '../db/schema.js';
import {
  requireChannelKeyRotation,
} from './key-epoch-state.js';
import {
  MAX_CATEGORIES_PER_WORKSPACE,
  MAX_ROLE_ASSIGNMENTS_PER_MEMBER,
  MAX_ROLES_PER_WORKSPACE,
  MAX_TOTAL_CHANNELS_PER_WORKSPACE,
  MAX_WORKSPACE_MEMBERS,
} from '../security/limits.js';

export const CHANNEL_SCOPED_PERMISSION_MASK =
  Permissions.VIEW_CHANNELS
  | Permissions.SEND_MESSAGES
  | Permissions.EDIT_MESSAGES
  | Permissions.DELETE_MESSAGES
  | Permissions.ADD_REACTIONS
  | Permissions.MENTION_EVERYONE
  | Permissions.PIN_MESSAGES
  | Permissions.ATTACH_FILES
  | Permissions.CONNECT_VOICE;

export interface RolePermissionOverrideValue {
  roleId: string;
  allowMask: number;
  denyMask: number;
}

export interface RoleMutation {
  roleId: string;
  included?: boolean;
  permissions?: number;
}

export interface OverrideMutation extends RolePermissionOverrideValue {
  deleted?: boolean;
}

export interface AuthorizationEvaluationOptions {
  roleMutation?: RoleMutation;
  roleMutationUserIds?: string[];
  categoryOverrideMutation?: OverrideMutation;
  channelOverrideMutation?: OverrideMutation;
}

export interface ChannelAuthorization {
  channelId: string;
  workspaceId: string;
  categoryId: string | null;
  permissions: number;
  workspacePermissions: number;
  isPrivate: boolean;
  isPrivateMember: boolean;
  isOwner: boolean;
  roles: Array<{ id: string; name: string; permissions: number; position: number }>;
  permissionDetails: Array<{
    permission: string;
    value: number;
    allowed: boolean;
    reasons: Array<Record<string, unknown>>;
  }>;
}

export interface ChannelViewerEffect {
  channelId: string;
  lostUserIds: string[];
  gainedUserIds: string[];
  rotationRequired: boolean;
}

interface SnapshotChannel {
  id: string;
  workspaceId: string;
  categoryId: string | null;
  isPrivate: boolean;
  [key: string]: unknown;
}

export interface WorkspaceAuthorizationSnapshot {
  workspaceId: string;
  ownerId: string;
  channels: SnapshotChannel[];
  channelsById: Map<string, SnapshotChannel>;
  membersByUserId: Map<string, { id: string; userId: string }>;
  rolesById: Map<string, any>;
  roleIdsByUserId: Map<string, string[]>;
  categoryOverridesById: Map<string, RolePermissionOverrideValue[]>;
  channelOverridesById: Map<string, RolePermissionOverrideValue[]>;
  privateMemberIdsByChannelId: Map<string, Set<string>>;
}

export function assertValidChannelOverrideMask(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || (value & ~CHANNEL_SCOPED_PERMISSION_MASK) !== 0) {
    throw new Error('INVALID_OVERRIDE_PERMISSIONS');
  }
}

/** Apply one override level. Denies win conflicts within the same level. */
export function applyPermissionOverrideLevel(
  permissionMask: number,
  values: RolePermissionOverrideValue[],
): { permissionMask: number; allowMask: number; denyMask: number } {
  const allowMask = values.reduce((mask, value) => mask | value.allowMask, 0);
  const denyMask = values.reduce((mask, value) => mask | value.denyMask, 0);
  return { permissionMask: (permissionMask | allowMask) & ~denyMask, allowMask, denyMask };
}

export async function getWorkspaceAuthorizationFromStore(store: any, workspaceId: string, userId: string) {
  const workspace = await store.query.workspaces.findFirst({
    columns: { ownerId: true },
    where: eq(workspaces.id, workspaceId),
  });
  if (!workspace) return null;
  const member = await store.query.workspaceMembers.findFirst({
    where: and(eq(workspaceMembers.workspaceId, workspaceId), eq(workspaceMembers.userId, userId)),
  });
  if (!member) return null;
  const assignments = await store.query.memberRoles.findMany({
    where: eq(memberRoles.memberId, member.id),
    with: { role: true },
    limit: MAX_ROLE_ASSIGNMENTS_PER_MEMBER + 1,
  });
  if (assignments.length > MAX_ROLE_ASSIGNMENTS_PER_MEMBER) {
    throw new Error('ROLE_ASSIGNMENT_INVARIANT_EXCEEDED');
  }
  const assignedRoles = assignments
    .map((assignment: any) => assignment.role)
    .filter((role: any) => role?.workspaceId === workspaceId)
    .sort((left: any, right: any) => right.position - left.position || left.id.localeCompare(right.id));
  const permissionMask = assignedRoles.reduce((mask: number, role: any) => mask | role.permissions, 0);
  return {
    workspaceId,
    userId,
    memberId: member.id,
    permissionMask,
    isOwner: workspace.ownerId === userId,
    roles: assignedRoles.map((role: any) => ({
      id: role.id,
      name: role.name,
      permissions: role.permissions,
      position: role.position,
    })),
  };
}

export async function getWorkspaceAuthorization(workspaceId: string, userId: string) {
  return getWorkspaceAuthorizationFromStore(db, workspaceId, userId);
}

/**
 * Load all bounded authorization inputs for one workspace in a fixed query
 * count. Callers that need a transaction-consistent view must hold the
 * workspace authorization lock while loading and evaluating this snapshot.
 */
export async function loadWorkspaceAuthorizationSnapshot(
  store: any,
  workspaceId: string,
  selectedChannelIds?: readonly string[],
): Promise<WorkspaceAuthorizationSnapshot | null> {
  if (selectedChannelIds && selectedChannelIds.length > MAX_TOTAL_CHANNELS_PER_WORKSPACE) {
    throw new Error('AUTHORIZATION_INPUT_LIMIT_EXCEEDED');
  }
  const workspace = await store.query.workspaces.findFirst({
    columns: { ownerId: true },
    where: eq(workspaces.id, workspaceId),
  });
  if (!workspace) return null;

  const channelRows = selectedChannelIds?.length === 0
    ? []
    : await store.query.channels.findMany({
      where: and(
        eq(channels.workspaceId, workspaceId),
        selectedChannelIds ? inArray(channels.id, [...selectedChannelIds]) : undefined,
      ),
      orderBy: [asc(channels.position), asc(channels.id)],
      limit: MAX_TOTAL_CHANNELS_PER_WORKSPACE + 1,
    }) as SnapshotChannel[];
  if (channelRows.length > MAX_TOTAL_CHANNELS_PER_WORKSPACE) throw new Error('CHANNEL_INVARIANT_EXCEEDED');

  const memberRows = await store.query.workspaceMembers.findMany({
    columns: { id: true, userId: true },
    where: eq(workspaceMembers.workspaceId, workspaceId),
    orderBy: [asc(workspaceMembers.userId)],
    limit: MAX_WORKSPACE_MEMBERS + 1,
  }) as Array<{ id: string; userId: string }>;
  if (memberRows.length > MAX_WORKSPACE_MEMBERS) throw new Error('WORKSPACE_MEMBER_INVARIANT_EXCEEDED');

  const roleRows = await store.query.roles.findMany({
    where: eq(roles.workspaceId, workspaceId),
    orderBy: [asc(roles.id)],
    limit: MAX_ROLES_PER_WORKSPACE + 1,
  });
  if (roleRows.length > MAX_ROLES_PER_WORKSPACE) throw new Error('ROLE_INVARIANT_EXCEEDED');

  const memberIds = memberRows.map((member) => member.id);
  const assignmentRows = memberIds.length === 0
    ? []
    : await store.query.memberRoles.findMany({
      columns: { memberId: true, roleId: true },
      where: inArray(memberRoles.memberId, memberIds),
      limit: MAX_WORKSPACE_MEMBERS * MAX_ROLE_ASSIGNMENTS_PER_MEMBER + 1,
    }) as Array<{ memberId: string; roleId: string }>;
  if (assignmentRows.length > MAX_WORKSPACE_MEMBERS * MAX_ROLE_ASSIGNMENTS_PER_MEMBER) {
    throw new Error('ROLE_ASSIGNMENT_INVARIANT_EXCEEDED');
  }

  const categoryIds = [...new Set(channelRows.flatMap((channel) => channel.categoryId ? [channel.categoryId] : []))];
  const categoryOverrideRows = categoryIds.length === 0
    ? []
    : await store.query.categoryRolePermissionOverrides.findMany({
      where: and(
        eq(categoryRolePermissionOverrides.workspaceId, workspaceId),
        inArray(categoryRolePermissionOverrides.categoryId, categoryIds),
      ),
      limit: MAX_CATEGORIES_PER_WORKSPACE * MAX_ROLES_PER_WORKSPACE + 1,
    });
  if (categoryOverrideRows.length > MAX_CATEGORIES_PER_WORKSPACE * MAX_ROLES_PER_WORKSPACE) {
    throw new Error('CATEGORY_OVERRIDE_INVARIANT_EXCEEDED');
  }

  const channelIds = channelRows.map((channel) => channel.id);
  const channelOverrideRows = channelIds.length === 0
    ? []
    : await store.query.channelRolePermissionOverrides.findMany({
      where: and(
        eq(channelRolePermissionOverrides.workspaceId, workspaceId),
        inArray(channelRolePermissionOverrides.channelId, channelIds),
      ),
      limit: MAX_TOTAL_CHANNELS_PER_WORKSPACE * MAX_ROLES_PER_WORKSPACE + 1,
    });
  if (channelOverrideRows.length > MAX_TOTAL_CHANNELS_PER_WORKSPACE * MAX_ROLES_PER_WORKSPACE) {
    throw new Error('CHANNEL_OVERRIDE_INVARIANT_EXCEEDED');
  }

  const privateChannelIds = channelRows.filter((channel) => channel.isPrivate).map((channel) => channel.id);
  const privateMembershipRows = privateChannelIds.length === 0
    ? []
    : await store.select({ channelId: channelMembers.channelId, userId: channelMembers.userId })
      .from(channelMembers)
      .where(inArray(channelMembers.channelId, privateChannelIds))
      .limit(MAX_TOTAL_CHANNELS_PER_WORKSPACE * MAX_WORKSPACE_MEMBERS + 1) as Array<{
        channelId: string;
        userId: string;
      }>;
  if (privateMembershipRows.length > MAX_TOTAL_CHANNELS_PER_WORKSPACE * MAX_WORKSPACE_MEMBERS) {
    throw new Error('PRIVATE_MEMBERSHIP_INVARIANT_EXCEEDED');
  }

  const memberIdToUserId = new Map(memberRows.map((member) => [member.id, member.userId]));
  const roleIdsByUserId = new Map(memberRows.map((member) => [member.userId, [] as string[]]));
  const workspaceRoleIds = new Set(roleRows.map((role: any) => role.id));
  for (const assignment of assignmentRows) {
    const userId = memberIdToUserId.get(assignment.memberId);
    if (!userId || !workspaceRoleIds.has(assignment.roleId)) throw new Error('ROLE_ASSIGNMENT_INVARIANT_EXCEEDED');
    roleIdsByUserId.get(userId)?.push(assignment.roleId);
  }

  return {
    workspaceId,
    ownerId: workspace.ownerId,
    channels: channelRows,
    channelsById: new Map(channelRows.map((channel) => [channel.id, channel])),
    membersByUserId: new Map(memberRows.map((member) => [member.userId, member])),
    rolesById: new Map(roleRows.map((role: any) => [role.id, role])),
    roleIdsByUserId,
    categoryOverridesById: groupOverrides(categoryOverrideRows, 'categoryId'),
    channelOverridesById: groupOverrides(channelOverrideRows, 'channelId'),
    privateMemberIdsByChannelId: groupPrivateMemberships(privateMembershipRows),
  };
}

export function getWorkspaceAuthorizationFromSnapshot(
  snapshot: WorkspaceAuthorizationSnapshot,
  userId: string,
) {
  const member = snapshot.membersByUserId.get(userId);
  if (!member) return null;
  const assignedRoles = (snapshot.roleIdsByUserId.get(userId) ?? [])
    .flatMap((roleId) => {
      const role = snapshot.rolesById.get(roleId);
      return role ? [role] : [];
    })
    .sort((left: any, right: any) => right.position - left.position || left.id.localeCompare(right.id));
  return {
    workspaceId: snapshot.workspaceId,
    userId,
    memberId: member.id,
    permissionMask: assignedRoles.reduce((mask: number, role: any) => mask | role.permissions, 0),
    isOwner: snapshot.ownerId === userId,
    roles: assignedRoles.map((role: any) => ({
      id: role.id,
      name: role.name,
      permissions: role.permissions,
      position: role.position,
    })),
  };
}

export function getChannelAuthorizationFromSnapshot(
  snapshot: WorkspaceAuthorizationSnapshot,
  userId: string,
  channelOrId: string | SnapshotChannel,
  options: AuthorizationEvaluationOptions = {},
  includePermissionDetails = true,
): ChannelAuthorization | null {
  const channel = typeof channelOrId === 'string' ? snapshot.channelsById.get(channelOrId) : channelOrId;
  if (!channel || channel.workspaceId !== snapshot.workspaceId || !snapshot.membersByUserId.has(userId)) return null;

  let assignedRoles = (snapshot.roleIdsByUserId.get(userId) ?? [])
    .flatMap((roleId) => {
      const role = snapshot.rolesById.get(roleId);
      return role ? [role] : [];
    });
  if (options.roleMutation && (!options.roleMutationUserIds || options.roleMutationUserIds.includes(userId))) {
    const mutation = options.roleMutation;
    assignedRoles = assignedRoles.filter((role: any) => role.id !== mutation.roleId);
    if (mutation.included !== false) {
      const source = snapshot.rolesById.get(mutation.roleId);
      if (source) assignedRoles.push({ ...source, permissions: mutation.permissions ?? source.permissions });
    }
  }
  assignedRoles.sort((left: any, right: any) => right.position - left.position || left.id.localeCompare(right.id));
  const roleIds = assignedRoles.map((role: any) => role.id);
  const roleIdSet = new Set(roleIds);
  const workspacePermissions = assignedRoles.reduce((mask: number, role: any) => mask | role.permissions, 0);
  const categoryValues = applyOverrideMutation(
    (channel.categoryId ? snapshot.categoryOverridesById.get(channel.categoryId) : undefined)
      ?.filter((value) => roleIdSet.has(value.roleId)) ?? [],
    options.categoryOverrideMutation,
    roleIdSet,
  );
  const channelValues = applyOverrideMutation(
    (snapshot.channelOverridesById.get(channel.id) ?? []).filter((value) => roleIdSet.has(value.roleId)),
    options.channelOverrideMutation,
    roleIdSet,
  );
  const categoryLevel = applyPermissionOverrideLevel(workspacePermissions, categoryValues);
  const channelLevel = applyPermissionOverrideLevel(categoryLevel.permissionMask, channelValues);
  const isOwner = snapshot.ownerId === userId;
  const permissionMask = isOwner
    ? channelLevel.permissionMask | CHANNEL_SCOPED_PERMISSION_MASK
    : channelLevel.permissionMask;
  const isPrivateMember = !channel.isPrivate
    || Boolean(snapshot.privateMemberIdsByChannelId.get(channel.id)?.has(userId));

  return {
    channelId: channel.id,
    workspaceId: channel.workspaceId,
    categoryId: channel.categoryId,
    permissions: permissionMask,
    workspacePermissions,
    isPrivate: channel.isPrivate,
    isPrivateMember,
    isOwner,
    roles: assignedRoles.map((role: any) => ({
      id: role.id,
      name: role.name,
      permissions: role.permissions,
      position: role.position,
    })),
    permissionDetails: includePermissionDetails
      ? buildPermissionDetails(assignedRoles, categoryValues, channelValues, permissionMask, isOwner)
      : [],
  };
}

export async function getChannelAuthorizationFromStore(
  store: any,
  userId: string,
  channelOrId: string | { id: string; workspaceId: string; categoryId: string | null; isPrivate: boolean },
  options: AuthorizationEvaluationOptions = {},
): Promise<ChannelAuthorization | null> {
  const channel = typeof channelOrId === 'string'
    ? await store.query.channels.findFirst({ where: eq(channels.id, channelOrId) })
    : channelOrId;
  if (!channel) return null;

  const workspace = await store.query.workspaces.findFirst({
    columns: { ownerId: true },
    where: eq(workspaces.id, channel.workspaceId),
  });
  if (!workspace) return null;
  const member = await store.query.workspaceMembers.findFirst({
    where: and(eq(workspaceMembers.workspaceId, channel.workspaceId), eq(workspaceMembers.userId, userId)),
  });
  if (!member) return null;
  const assignments = await store.query.memberRoles.findMany({
    where: eq(memberRoles.memberId, member.id),
    with: { role: true },
    limit: MAX_ROLE_ASSIGNMENTS_PER_MEMBER + 1,
  });
  if (assignments.length > MAX_ROLE_ASSIGNMENTS_PER_MEMBER) {
    throw new Error('ROLE_ASSIGNMENT_INVARIANT_EXCEEDED');
  }
  let assignedRoles = assignments
    .map((assignment: any) => assignment.role)
    .filter((role: any) => role?.workspaceId === channel.workspaceId);
  if (options.roleMutation && (!options.roleMutationUserIds || options.roleMutationUserIds.includes(userId))) {
    const mutation = options.roleMutation;
    assignedRoles = assignedRoles.filter((role: any) => role.id !== mutation.roleId);
    if (mutation.included !== false) {
      const source = assignments.find((assignment: any) => assignment.role?.id === mutation.roleId)?.role
        ?? await store.query.roles.findFirst({
          where: and(eq(roles.workspaceId, channel.workspaceId), eq(roles.id, mutation.roleId)),
        });
      if (source) assignedRoles.push({ ...source, permissions: mutation.permissions ?? source.permissions });
    }
  }
  assignedRoles.sort((left: any, right: any) => right.position - left.position || left.id.localeCompare(right.id));
  const roleIds = assignedRoles.map((role: any) => role.id);
  const workspacePermissions = assignedRoles.reduce((mask: number, role: any) => mask | role.permissions, 0);

  let categoryValues: RolePermissionOverrideValue[] = [];
  if (channel.categoryId && roleIds.length > 0) {
    categoryValues = await store.query.categoryRolePermissionOverrides.findMany({
      where: and(
        eq(categoryRolePermissionOverrides.workspaceId, channel.workspaceId),
        eq(categoryRolePermissionOverrides.categoryId, channel.categoryId),
        inArray(categoryRolePermissionOverrides.roleId, roleIds),
      ),
      limit: MAX_ROLE_ASSIGNMENTS_PER_MEMBER + 1,
    });
    if (categoryValues.length > MAX_ROLE_ASSIGNMENTS_PER_MEMBER) {
      throw new Error('CATEGORY_OVERRIDE_INVARIANT_EXCEEDED');
    }
  }
  categoryValues = applyOverrideMutation(categoryValues, options.categoryOverrideMutation, new Set(roleIds));

  let channelValues: RolePermissionOverrideValue[] = [];
  if (roleIds.length > 0) {
    channelValues = await store.query.channelRolePermissionOverrides.findMany({
      where: and(
        eq(channelRolePermissionOverrides.workspaceId, channel.workspaceId),
        eq(channelRolePermissionOverrides.channelId, channel.id),
        inArray(channelRolePermissionOverrides.roleId, roleIds),
      ),
      limit: MAX_ROLE_ASSIGNMENTS_PER_MEMBER + 1,
    });
    if (channelValues.length > MAX_ROLE_ASSIGNMENTS_PER_MEMBER) {
      throw new Error('CHANNEL_OVERRIDE_INVARIANT_EXCEEDED');
    }
  }
  channelValues = applyOverrideMutation(channelValues, options.channelOverrideMutation, new Set(roleIds));

  const categoryLevel = applyPermissionOverrideLevel(workspacePermissions, categoryValues);
  const channelLevel = applyPermissionOverrideLevel(categoryLevel.permissionMask, channelValues);
  const isOwner = workspace.ownerId === userId;
  const permissionMask = isOwner
    ? channelLevel.permissionMask | CHANNEL_SCOPED_PERMISSION_MASK
    : channelLevel.permissionMask;
  const privateMembership = channel.isPrivate
    ? await store.query.channelMembers.findFirst({
      columns: { userId: true },
      where: and(eq(channelMembers.channelId, channel.id), eq(channelMembers.userId, userId)),
    })
    : null;
  const isPrivateMember = !channel.isPrivate || Boolean(privateMembership);

  return {
    channelId: channel.id,
    workspaceId: channel.workspaceId,
    categoryId: channel.categoryId,
    permissions: permissionMask,
    workspacePermissions,
    isPrivate: channel.isPrivate,
    isPrivateMember,
    isOwner,
    roles: assignedRoles.map((role: any) => ({
      id: role.id,
      name: role.name,
      permissions: role.permissions,
      position: role.position,
    })),
    permissionDetails: buildPermissionDetails(
      assignedRoles,
      categoryValues,
      channelValues,
      permissionMask,
      isOwner,
    ),
  };
}

export async function getChannelAuthorization(userId: string, channelId: string) {
  const authorization = await getChannelAuthorizationFromStore(db, userId, channelId);
  return isVisibleChannelAuthorization(authorization) ? authorization : null;
}

export function isVisibleChannelAuthorization(
  authorization: ChannelAuthorization | null,
): authorization is ChannelAuthorization {
  return Boolean(
    authorization
    && authorization.isPrivateMember
    && (authorization.permissions & Permissions.VIEW_CHANNELS) === Permissions.VIEW_CHANNELS,
  );
}

export async function getChannelViewerIdsFromStore(
  store: any,
  channel: { id: string; workspaceId: string; categoryId: string | null; isPrivate: boolean },
  options: AuthorizationEvaluationOptions = {},
): Promise<string[]> {
  const snapshot = await loadWorkspaceAuthorizationSnapshot(store, channel.workspaceId, [channel.id]);
  if (!snapshot) return [];
  return captureChannelViewersFromSnapshot(snapshot, options).get(channel.id) ?? [];
}

export async function captureChannelViewersFromStore(
  store: any,
  workspaceId: string,
  channelIds?: string[],
  options: AuthorizationEvaluationOptions = {},
): Promise<Map<string, string[]>> {
  if (channelIds && channelIds.length === 0) return new Map();
  const snapshot = await loadWorkspaceAuthorizationSnapshot(store, workspaceId, channelIds);
  if (!snapshot) return new Map();
  return captureChannelViewersFromSnapshot(snapshot, options);
}

export function captureChannelViewersFromSnapshot(
  snapshot: WorkspaceAuthorizationSnapshot,
  options: AuthorizationEvaluationOptions = {},
): Map<string, string[]> {
  const result = new Map<string, string[]>();
  const userIds = [...snapshot.membersByUserId.keys()].sort();
  for (const channel of snapshot.channels) {
    const viewers = userIds.filter((userId) => {
      const authorization = getChannelAuthorizationFromSnapshot(snapshot, userId, channel, options, false);
      return isVisibleChannelAuthorization(authorization)
        && (channel.type !== 'voice' || (authorization.permissions & Permissions.CONNECT_VOICE) !== 0);
    });
    result.set(channel.id, viewers);
  }
  return result;
}

export async function applyViewerEffectsAndRotation(
  store: any,
  before: Map<string, string[]>,
  after: Map<string, string[]>,
): Promise<ChannelViewerEffect[]> {
  const effects: ChannelViewerEffect[] = [];
  const allChannelIds = [...new Set([...before.keys(), ...after.keys()])].sort();
  for (const channelId of allChannelIds) {
    const previous = new Set(before.get(channelId) ?? []);
    const next = new Set(after.get(channelId) ?? []);
    const lostUserIds = [...previous].filter((userId) => !next.has(userId)).sort();
    const gainedUserIds = [...next].filter((userId) => !previous.has(userId)).sort();
    let rotationRequired = false;
    if (lostUserIds.length > 0 || gainedUserIds.length > 0) {
      const result = await requireChannelKeyRotation(store, [channelId]);
      rotationRequired = result.keyedChannelIds.includes(channelId);
    }
    if (lostUserIds.length > 0 || gainedUserIds.length > 0 || rotationRequired) {
      effects.push({ channelId, lostUserIds, gainedUserIds, rotationRequired });
    }
  }
  return effects;
}

export async function lockWorkspaceForAuthorization(store: any, workspaceId: string, mode: 'share' | 'update') {
  const lock = mode === 'update' ? sql.raw('update') : sql.raw('share');
  const result = await store.execute(sql`
    select id from ${workspaces} where ${workspaces.id} = ${workspaceId} for ${lock}
  `);
  if (result.rowCount === 0) throw new Error('WORKSPACE_NOT_FOUND');
}

export async function lockChannelAuthorization(store: any, channelId: string): Promise<void> {
  await store.execute(sql`select pg_advisory_xact_lock(hashtext(${channelId})::bigint)`);
}

export async function computeAuthorizationRevisionFromStore(store: any, workspaceId: string): Promise<string> {
  const workspace = await store.query.workspaces.findFirst({
    columns: { ownerId: true },
    where: eq(workspaces.id, workspaceId),
  });
  if (!workspace) throw new Error('WORKSPACE_NOT_FOUND');
  const roleRows = await store.query.roles.findMany({
    columns: { id: true, name: true, permissions: true, position: true },
    where: eq(roles.workspaceId, workspaceId),
    orderBy: [asc(roles.id)],
    limit: MAX_ROLES_PER_WORKSPACE + 1,
  });
  const membershipRows = await store.select({
    memberId: workspaceMembers.id,
    userId: workspaceMembers.userId,
    roleId: memberRoles.roleId,
  }).from(workspaceMembers)
    .leftJoin(memberRoles, eq(memberRoles.memberId, workspaceMembers.id))
    .where(eq(workspaceMembers.workspaceId, workspaceId))
    .orderBy(asc(workspaceMembers.userId), asc(memberRoles.roleId))
    .limit(MAX_WORKSPACE_MEMBERS * MAX_ROLE_ASSIGNMENTS_PER_MEMBER + 1);
  const categoryOverrideRows = await store.query.categoryRolePermissionOverrides.findMany({
    columns: {
      categoryId: true,
      roleId: true,
      allowMask: true,
      denyMask: true,
      revision: true,
    },
    where: eq(categoryRolePermissionOverrides.workspaceId, workspaceId),
    orderBy: [asc(categoryRolePermissionOverrides.categoryId), asc(categoryRolePermissionOverrides.roleId)],
    limit: MAX_CATEGORIES_PER_WORKSPACE * MAX_ROLES_PER_WORKSPACE + 1,
  });
  const channelOverrideRows = await store.query.channelRolePermissionOverrides.findMany({
    columns: {
      channelId: true,
      roleId: true,
      allowMask: true,
      denyMask: true,
      revision: true,
    },
    where: eq(channelRolePermissionOverrides.workspaceId, workspaceId),
    orderBy: [asc(channelRolePermissionOverrides.channelId), asc(channelRolePermissionOverrides.roleId)],
    limit: MAX_TOTAL_CHANNELS_PER_WORKSPACE * MAX_ROLES_PER_WORKSPACE + 1,
  });
  const channelRows = await store.query.channels.findMany({
    columns: { id: true, categoryId: true, isPrivate: true },
    where: eq(channels.workspaceId, workspaceId),
    orderBy: [asc(channels.id)],
    limit: MAX_TOTAL_CHANNELS_PER_WORKSPACE + 1,
  });
  if (roleRows.length > MAX_ROLES_PER_WORKSPACE) throw new Error('ROLE_INVARIANT_EXCEEDED');
  if (membershipRows.length > MAX_WORKSPACE_MEMBERS * MAX_ROLE_ASSIGNMENTS_PER_MEMBER) {
    throw new Error('ROLE_ASSIGNMENT_INVARIANT_EXCEEDED');
  }
  const revisionMemberAssignments = new Map<string, number>();
  for (const row of membershipRows) {
    const count = revisionMemberAssignments.get(row.memberId) ?? 0;
    const next = row.roleId === null ? count : count + 1;
    revisionMemberAssignments.set(row.memberId, next);
    if (next > MAX_ROLE_ASSIGNMENTS_PER_MEMBER) throw new Error('ROLE_ASSIGNMENT_INVARIANT_EXCEEDED');
  }
  if (revisionMemberAssignments.size > MAX_WORKSPACE_MEMBERS) {
    throw new Error('WORKSPACE_MEMBER_INVARIANT_EXCEEDED');
  }
  if (categoryOverrideRows.length > MAX_CATEGORIES_PER_WORKSPACE * MAX_ROLES_PER_WORKSPACE) {
    throw new Error('CATEGORY_OVERRIDE_INVARIANT_EXCEEDED');
  }
  if (channelOverrideRows.length > MAX_TOTAL_CHANNELS_PER_WORKSPACE * MAX_ROLES_PER_WORKSPACE) {
    throw new Error('CHANNEL_OVERRIDE_INVARIANT_EXCEEDED');
  }
  if (channelRows.length > MAX_TOTAL_CHANNELS_PER_WORKSPACE) throw new Error('CHANNEL_INVARIANT_EXCEEDED');
  const channelIds = channelRows.map((channel: { id: string }) => channel.id);
  const privateMembershipRows = channelIds.length === 0
    ? []
    : await store.select({ channelId: channelMembers.channelId, userId: channelMembers.userId })
      .from(channelMembers)
      .where(inArray(channelMembers.channelId, channelIds))
      .orderBy(asc(channelMembers.channelId), asc(channelMembers.userId))
      .limit(MAX_TOTAL_CHANNELS_PER_WORKSPACE * MAX_WORKSPACE_MEMBERS + 1);
  if (privateMembershipRows.length > MAX_TOTAL_CHANNELS_PER_WORKSPACE * MAX_WORKSPACE_MEMBERS) {
    throw new Error('PRIVATE_MEMBERSHIP_INVARIANT_EXCEEDED');
  }
  const canonical = JSON.stringify({
    policyVersion: 2,
    ownerId: workspace.ownerId,
    roles: roleRows.map((role: any) => [role.id, role.name, role.permissions, role.position]),
    assignments: membershipRows.map((assignment: any) => [assignment.memberId, assignment.userId, assignment.roleId]),
    categoryOverrides: categoryOverrideRows.map((row: any) => (
      [row.categoryId, row.roleId, row.allowMask, row.denyMask, row.revision]
    )),
    channelOverrides: channelOverrideRows.map((row: any) => (
      [row.channelId, row.roleId, row.allowMask, row.denyMask, row.revision]
    )),
    channels: channelRows.map((channel: any) => [channel.id, channel.categoryId, channel.isPrivate]),
    privateMemberships: privateMembershipRows.map((row: any) => [row.channelId, row.userId]),
  });
  return createHash('sha256').update(canonical).digest('hex');
}

function applyOverrideMutation(
  rows: RolePermissionOverrideValue[],
  mutation: OverrideMutation | undefined,
  assignedRoleIds?: ReadonlySet<string>,
): RolePermissionOverrideValue[] {
  if (!mutation || (assignedRoleIds && !assignedRoleIds.has(mutation.roleId))) return rows;
  const withoutTarget = rows.filter((row) => row.roleId !== mutation.roleId);
  if (!mutation.deleted) withoutTarget.push(mutation);
  return withoutTarget;
}

function groupOverrides(
  rows: any[],
  targetField: 'categoryId' | 'channelId',
): Map<string, RolePermissionOverrideValue[]> {
  const grouped = new Map<string, RolePermissionOverrideValue[]>();
  for (const row of rows) {
    const targetId = row[targetField] as string;
    const values = grouped.get(targetId) ?? [];
    values.push({ roleId: row.roleId, allowMask: row.allowMask, denyMask: row.denyMask });
    grouped.set(targetId, values);
  }
  return grouped;
}

function groupPrivateMemberships(
  rows: Array<{ channelId: string; userId: string }>,
): Map<string, Set<string>> {
  const grouped = new Map<string, Set<string>>();
  for (const row of rows) {
    const users = grouped.get(row.channelId) ?? new Set<string>();
    users.add(row.userId);
    grouped.set(row.channelId, users);
  }
  return grouped;
}

function buildPermissionDetails(
  assignedRoles: any[],
  categoryValues: RolePermissionOverrideValue[],
  channelValues: RolePermissionOverrideValue[],
  permissionMask: number,
  isOwner: boolean,
) {
  return Object.entries(Permissions).map(([permission, value]) => {
    const reasons: Array<Record<string, unknown>> = [];
    for (const role of assignedRoles) {
      if ((role.permissions & value) === value) {
        reasons.push({ source: 'role', effect: 'allow', roleId: role.id, roleName: role.name });
      }
    }
    for (const override of categoryValues) {
      if ((override.denyMask & value) === value) reasons.push({ source: 'category', effect: 'deny', roleId: override.roleId });
      if ((override.allowMask & value) === value) reasons.push({ source: 'category', effect: 'allow', roleId: override.roleId });
    }
    for (const override of channelValues) {
      if ((override.denyMask & value) === value) reasons.push({ source: 'channel', effect: 'deny', roleId: override.roleId });
      if ((override.allowMask & value) === value) reasons.push({ source: 'channel', effect: 'allow', roleId: override.roleId });
    }
    if (isOwner && (CHANNEL_SCOPED_PERMISSION_MASK & value) === value) {
      reasons.push({ source: 'workspace-owner', effect: 'allow' });
    }
    return { permission, value, allowed: (permissionMask & value) === value, reasons };
  });
}
