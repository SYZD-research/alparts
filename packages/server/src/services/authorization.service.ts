import { createHash } from 'node:crypto';
import { and, asc, eq, inArray, sql } from 'drizzle-orm';
import { Permissions } from '@alparts/shared';
import { db } from '../db/index.js';
import {
  categories,
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
  abortPendingChannelKeyEpochs,
  requireChannelKeyRotation,
} from './key-epoch-state.js';

export const CHANNEL_SCOPED_PERMISSION_MASK =
  Permissions.VIEW_CHANNELS
  | Permissions.SEND_MESSAGES
  | Permissions.EDIT_MESSAGES
  | Permissions.DELETE_MESSAGES
  | Permissions.ADD_REACTIONS
  | Permissions.MENTION_EVERYONE
  | Permissions.PIN_MESSAGES
  | Permissions.ATTACH_FILES;

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

export function assertValidChannelOverrideMask(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || (value & ~CHANNEL_SCOPED_PERMISSION_MASK) !== 0) {
    throw new Error('INVALID_OVERRIDE_PERMISSIONS');
  }
}

/** Apply one override level. Denies are evaluated first and allows win conflicts. */
export function applyPermissionOverrideLevel(
  permissionMask: number,
  values: RolePermissionOverrideValue[],
): { permissionMask: number; allowMask: number; denyMask: number } {
  const allowMask = values.reduce((mask, value) => mask | value.allowMask, 0);
  const denyMask = values.reduce((mask, value) => mask | value.denyMask, 0);
  return { permissionMask: (permissionMask & ~denyMask) | allowMask, allowMask, denyMask };
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
  });
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
  });
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
    });
  }
  categoryValues = applyOverrideMutation(categoryValues, options.categoryOverrideMutation);

  let channelValues: RolePermissionOverrideValue[] = [];
  if (roleIds.length > 0) {
    channelValues = await store.query.channelRolePermissionOverrides.findMany({
      where: and(
        eq(channelRolePermissionOverrides.workspaceId, channel.workspaceId),
        eq(channelRolePermissionOverrides.channelId, channel.id),
        inArray(channelRolePermissionOverrides.roleId, roleIds),
      ),
    });
  }
  channelValues = applyOverrideMutation(channelValues, options.channelOverrideMutation);

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
  const members = await store.query.workspaceMembers.findMany({
    columns: { userId: true },
    where: eq(workspaceMembers.workspaceId, channel.workspaceId),
    orderBy: [asc(workspaceMembers.userId)],
  });
  const viewerIds: string[] = [];
  for (const member of members) {
    const authorization = await getChannelAuthorizationFromStore(store, member.userId, channel, options);
    if (isVisibleChannelAuthorization(authorization)) viewerIds.push(member.userId);
  }
  return viewerIds;
}

export async function captureChannelViewersFromStore(
  store: any,
  workspaceId: string,
  channelIds?: string[],
  options: AuthorizationEvaluationOptions = {},
): Promise<Map<string, string[]>> {
  if (channelIds && channelIds.length === 0) return new Map();
  const workspaceChannels = await store.query.channels.findMany({
    where: and(
      eq(channels.workspaceId, workspaceId),
      channelIds && channelIds.length > 0 ? inArray(channels.id, channelIds) : undefined,
    ),
    orderBy: [asc(channels.id)],
  });
  const result = new Map<string, string[]>();
  for (const channel of workspaceChannels) {
    result.set(channel.id, await getChannelViewerIdsFromStore(store, channel, options));
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
    if (lostUserIds.length > 0) {
      const result = await requireChannelKeyRotation(store, [channelId]);
      rotationRequired = result.keyedChannelIds.includes(channelId);
    } else if (gainedUserIds.length > 0) {
      // A provisional epoch's all-recipient acknowledgement is meaningful
      // only for its frozen viewer/device snapshot. Viewer gain aborts that
      // proposal but does not force an already-active epoch to rotate.
      await abortPendingChannelKeyEpochs(store, [channelId]);
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
  });
  const membershipRows = await store.select({
    memberId: workspaceMembers.id,
    userId: workspaceMembers.userId,
    roleId: memberRoles.roleId,
  }).from(workspaceMembers)
    .leftJoin(memberRoles, eq(memberRoles.memberId, workspaceMembers.id))
    .where(eq(workspaceMembers.workspaceId, workspaceId))
    .orderBy(asc(workspaceMembers.userId), asc(memberRoles.roleId));
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
  });
  const channelRows = await store.query.channels.findMany({
    columns: { id: true, categoryId: true, isPrivate: true },
    where: eq(channels.workspaceId, workspaceId),
    orderBy: [asc(channels.id)],
  });
  const channelIds = channelRows.map((channel: { id: string }) => channel.id);
  const privateMembershipRows = channelIds.length === 0
    ? []
    : await store.select({ channelId: channelMembers.channelId, userId: channelMembers.userId })
      .from(channelMembers)
      .where(inArray(channelMembers.channelId, channelIds))
      .orderBy(asc(channelMembers.channelId), asc(channelMembers.userId));
  const canonical = JSON.stringify({
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
): RolePermissionOverrideValue[] {
  if (!mutation) return rows;
  const withoutTarget = rows.filter((row) => row.roleId !== mutation.roleId);
  if (!mutation.deleted) withoutTarget.push(mutation);
  return withoutTarget;
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
