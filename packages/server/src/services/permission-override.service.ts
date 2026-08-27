import { and, asc, eq } from 'drizzle-orm';
import { Permissions } from '@alparts/shared';
import { db } from '../db/index.js';
import {
  categories,
  categoryRolePermissionOverrides,
  channelRolePermissionOverrides,
  channels,
  roles,
} from '../db/schema.js';
import { auditedTransaction } from '../middleware/audit.js';
import {
  applyViewerEffectsAndRotation,
  assertValidChannelOverrideMask,
  captureChannelViewersFromStore,
  computeAuthorizationRevisionFromStore,
  getChannelAuthorizationFromStore,
  getWorkspaceAuthorizationFromStore,
  isVisibleChannelAuthorization,
  lockChannelAuthorization,
  lockWorkspaceForAuthorization,
  type ChannelViewerEffect,
  type OverrideMutation,
} from './authorization.service.js';

export type OverrideTarget = 'category' | 'channel';

interface OverrideWriteInput {
  allowMask: number;
  denyMask: number;
  expectedRevision: number;
  expectedAuthorizationRevision: string;
}

interface OverridePreviewInput {
  operation: 'upsert' | 'delete';
  roleId: string;
  allowMask?: number;
  denyMask?: number;
}

export async function listPermissionOverrides(
  target: OverrideTarget,
  workspaceId: string,
  targetId: string,
  actorId: string,
) {
  await assertManagementAuthorization(db, target, workspaceId, targetId, actorId);
  const rows = target === 'category'
    ? await db.query.categoryRolePermissionOverrides.findMany({
      where: and(
        eq(categoryRolePermissionOverrides.workspaceId, workspaceId),
        eq(categoryRolePermissionOverrides.categoryId, targetId),
      ),
      orderBy: [asc(categoryRolePermissionOverrides.roleId)],
    })
    : await db.query.channelRolePermissionOverrides.findMany({
      where: and(
        eq(channelRolePermissionOverrides.workspaceId, workspaceId),
        eq(channelRolePermissionOverrides.channelId, targetId),
      ),
      orderBy: [asc(channelRolePermissionOverrides.roleId)],
    });
  return rows.map(formatOverride);
}

export async function getEffectiveChannelPermissions(
  workspaceId: string,
  channelId: string,
  userId: string,
  actorId: string,
) {
  await assertManagementAuthorization(db, 'channel', workspaceId, channelId, actorId);
  const authorization = await getChannelAuthorizationFromStore(db, userId, channelId);
  if (!authorization || authorization.workspaceId !== workspaceId) throw new Error('MEMBER_NOT_FOUND');
  return {
    workspaceId,
    channelId,
    userId,
    effectivePermissions: authorization.permissions.toString(),
    permissionMask: authorization.permissions,
    workspacePermissionMask: authorization.workspacePermissions,
    visible: isVisibleChannelAuthorization(authorization),
    privateMembershipRequired: authorization.isPrivate,
    privateMember: authorization.isPrivateMember,
    ownerProtected: authorization.isOwner,
    roles: authorization.roles,
    permissionDetails: authorization.permissionDetails,
  };
}

export async function previewPermissionOverride(
  target: OverrideTarget,
  workspaceId: string,
  targetId: string,
  actorId: string,
  input: OverridePreviewInput,
) {
  const normalized = normalizePreview(input);
  return db.transaction(async (transaction) => {
    await lockWorkspaceForAuthorization(transaction, workspaceId, 'share');
    await assertManagementAuthorization(transaction, target, workspaceId, targetId, actorId);
    await assertWorkspaceRole(transaction, workspaceId, input.roleId);
    const current = await findOverride(transaction, target, workspaceId, targetId, input.roleId);
    if (input.operation === 'delete' && !current) throw new Error('OVERRIDE_NOT_FOUND');
    const affectedChannelIds = await getAffectedChannelIds(transaction, target, workspaceId, targetId);
    const before = await captureChannelViewersFromStore(transaction, workspaceId, affectedChannelIds);
    const mutation: OverrideMutation = {
      roleId: input.roleId,
      allowMask: normalized.allowMask,
      denyMask: normalized.denyMask,
      deleted: input.operation === 'delete',
    };
    const after = await captureChannelViewersFromStore(transaction, workspaceId, affectedChannelIds, target === 'category'
      ? { categoryOverrideMutation: mutation }
      : { channelOverrideMutation: mutation });
    return {
      target,
      workspaceId,
      targetId,
      roleId: input.roleId,
      operation: input.operation,
      currentRevision: current?.revision ?? 0,
      authorizationRevision: await computeAuthorizationRevisionFromStore(transaction, workspaceId),
      before: current ? formatOverride(current) : null,
      after: input.operation === 'delete' ? null : {
        workspaceId,
        targetId,
        roleId: input.roleId,
        allowMask: normalized.allowMask,
        denyMask: normalized.denyMask,
        revision: (current?.revision ?? 0) + 1,
      },
      roomEffects: compareViewerMaps(before, after),
    };
  });
}

export async function upsertPermissionOverride(
  target: OverrideTarget,
  workspaceId: string,
  targetId: string,
  roleId: string,
  actorId: string,
  input: OverrideWriteInput,
) {
  assertValidChannelOverrideMask(input.allowMask);
  assertValidChannelOverrideMask(input.denyMask);
  assertExpectedRevision(input.expectedRevision);
  const result = await auditedTransaction(async (transaction) => {
    await lockWorkspaceForAuthorization(transaction, workspaceId, 'update');
    await assertAuthorizationRevision(transaction, workspaceId, input.expectedAuthorizationRevision);
    const affectedChannelIds = await getAffectedChannelIds(transaction, target, workspaceId, targetId);
    for (const channelId of [...affectedChannelIds].sort()) await lockChannelAuthorization(transaction, channelId);
    await assertManagementAuthorization(transaction, target, workspaceId, targetId, actorId);
    await assertWorkspaceRole(transaction, workspaceId, roleId);
    const current = await findOverride(transaction, target, workspaceId, targetId, roleId);
    if ((current?.revision ?? 0) !== input.expectedRevision) throw new Error('STALE_OVERRIDE');
    const before = await captureChannelViewersFromStore(transaction, workspaceId, affectedChannelIds);
    const nextRevision = input.expectedRevision + 1;
    const now = new Date();
    let row;
    if (target === 'category') {
      [row] = current
        ? await transaction.update(categoryRolePermissionOverrides).set({
          allowMask: input.allowMask,
          denyMask: input.denyMask,
          revision: nextRevision,
          updatedAt: now,
        }).where(and(
          eq(categoryRolePermissionOverrides.workspaceId, workspaceId),
          eq(categoryRolePermissionOverrides.categoryId, targetId),
          eq(categoryRolePermissionOverrides.roleId, roleId),
        )).returning()
        : await transaction.insert(categoryRolePermissionOverrides).values({
          workspaceId,
          categoryId: targetId,
          roleId,
          allowMask: input.allowMask,
          denyMask: input.denyMask,
          revision: nextRevision,
          updatedAt: now,
        }).returning();
    } else {
      [row] = current
        ? await transaction.update(channelRolePermissionOverrides).set({
          allowMask: input.allowMask,
          denyMask: input.denyMask,
          revision: nextRevision,
          updatedAt: now,
        }).where(and(
          eq(channelRolePermissionOverrides.workspaceId, workspaceId),
          eq(channelRolePermissionOverrides.channelId, targetId),
          eq(channelRolePermissionOverrides.roleId, roleId),
        )).returning()
        : await transaction.insert(channelRolePermissionOverrides).values({
          workspaceId,
          channelId: targetId,
          roleId,
          allowMask: input.allowMask,
          denyMask: input.denyMask,
          revision: nextRevision,
          updatedAt: now,
        }).returning();
    }
    const after = await captureChannelViewersFromStore(transaction, workspaceId, affectedChannelIds);
    const roomEffects = await applyViewerEffectsAndRotation(transaction, before, after);
    return {
      row,
      current,
      roomEffects,
      authorizationRevision: await computeAuthorizationRevisionFromStore(transaction, workspaceId),
    };
  }, (committed) => ({
    actorId,
    action: `${target}.permission-override.upsert`,
    targetType: target,
    targetId,
    details: {
      workspaceId,
      roleId,
      before: committed.current ? {
        allowMask: committed.current.allowMask,
        denyMask: committed.current.denyMask,
        revision: committed.current.revision,
      } : null,
      after: { allowMask: input.allowMask, denyMask: input.denyMask, revision: committed.row.revision },
      affectedChannelIds: committed.roomEffects.map((effect) => effect.channelId),
    },
  }));
  return {
    override: formatOverride(result.row),
    authorizationRevision: result.authorizationRevision,
    roomEffects: result.roomEffects,
  };
}

export async function deletePermissionOverride(
  target: OverrideTarget,
  workspaceId: string,
  targetId: string,
  roleId: string,
  actorId: string,
  expectedRevision: number,
  expectedAuthorizationRevision: string,
) {
  assertExpectedRevision(expectedRevision);
  const result = await auditedTransaction(async (transaction) => {
    await lockWorkspaceForAuthorization(transaction, workspaceId, 'update');
    await assertAuthorizationRevision(transaction, workspaceId, expectedAuthorizationRevision);
    const affectedChannelIds = await getAffectedChannelIds(transaction, target, workspaceId, targetId);
    for (const channelId of [...affectedChannelIds].sort()) await lockChannelAuthorization(transaction, channelId);
    await assertManagementAuthorization(transaction, target, workspaceId, targetId, actorId);
    await assertWorkspaceRole(transaction, workspaceId, roleId);
    const current = await findOverride(transaction, target, workspaceId, targetId, roleId);
    if (!current) throw new Error('OVERRIDE_NOT_FOUND');
    if (current.revision !== expectedRevision) throw new Error('STALE_OVERRIDE');
    const before = await captureChannelViewersFromStore(transaction, workspaceId, affectedChannelIds);
    if (target === 'category') {
      await transaction.delete(categoryRolePermissionOverrides).where(and(
        eq(categoryRolePermissionOverrides.workspaceId, workspaceId),
        eq(categoryRolePermissionOverrides.categoryId, targetId),
        eq(categoryRolePermissionOverrides.roleId, roleId),
      ));
    } else {
      await transaction.delete(channelRolePermissionOverrides).where(and(
        eq(channelRolePermissionOverrides.workspaceId, workspaceId),
        eq(channelRolePermissionOverrides.channelId, targetId),
        eq(channelRolePermissionOverrides.roleId, roleId),
      ));
    }
    const after = await captureChannelViewersFromStore(transaction, workspaceId, affectedChannelIds);
    const roomEffects = await applyViewerEffectsAndRotation(transaction, before, after);
    return {
      current,
      roomEffects,
      authorizationRevision: await computeAuthorizationRevisionFromStore(transaction, workspaceId),
    };
  }, (committed) => ({
    actorId,
    action: `${target}.permission-override.delete`,
    targetType: target,
    targetId,
    details: {
      workspaceId,
      roleId,
      before: {
        allowMask: committed.current.allowMask,
        denyMask: committed.current.denyMask,
        revision: committed.current.revision,
      },
      affectedChannelIds: committed.roomEffects.map((effect) => effect.channelId),
    },
  }));
  return {
    workspaceId,
    target,
    targetId,
    roleId,
    deleted: true,
    authorizationRevision: result.authorizationRevision,
    roomEffects: result.roomEffects,
  };
}

async function assertManagementAuthorization(
  store: any,
  target: OverrideTarget,
  workspaceId: string,
  targetId: string,
  actorId: string,
) {
  if (target === 'category') {
    const category = await store.query.categories.findFirst({
      columns: { id: true },
      where: and(eq(categories.id, targetId), eq(categories.workspaceId, workspaceId)),
    });
    if (!category) throw new Error('TARGET_NOT_FOUND');
    const authorization = await getWorkspaceAuthorizationFromStore(store, workspaceId, actorId);
    if (!authorization) throw new Error('TARGET_NOT_FOUND');
    if (
      (authorization.permissionMask & Permissions.VIEW_CHANNELS) !== Permissions.VIEW_CHANNELS
      || (authorization.permissionMask & Permissions.MANAGE_CHANNELS) !== Permissions.MANAGE_CHANNELS
    ) throw new Error('NOT_AUTHORIZED');
    return;
  }
  const channel = await store.query.channels.findFirst({
    where: and(eq(channels.id, targetId), eq(channels.workspaceId, workspaceId)),
  });
  if (!channel || channel.type === 'dm') throw new Error('TARGET_NOT_FOUND');
  const authorization = await getChannelAuthorizationFromStore(store, actorId, channel);
  if (!isVisibleChannelAuthorization(authorization)) throw new Error('TARGET_NOT_FOUND');
  if ((authorization.permissions & Permissions.MANAGE_CHANNELS) !== Permissions.MANAGE_CHANNELS) {
    throw new Error('NOT_AUTHORIZED');
  }
}

async function assertWorkspaceRole(store: any, workspaceId: string, roleId: string) {
  const role = await store.query.roles.findFirst({
    columns: { id: true },
    where: and(eq(roles.id, roleId), eq(roles.workspaceId, workspaceId)),
  });
  if (!role) throw new Error('ROLE_NOT_FOUND');
}

async function getAffectedChannelIds(store: any, target: OverrideTarget, workspaceId: string, targetId: string) {
  if (target === 'channel') {
    const channel = await store.query.channels.findFirst({
      columns: { id: true },
      where: and(eq(channels.id, targetId), eq(channels.workspaceId, workspaceId)),
    });
    if (!channel) throw new Error('TARGET_NOT_FOUND');
    return [channel.id];
  }
  const category = await store.query.categories.findFirst({
    columns: { id: true },
    where: and(eq(categories.id, targetId), eq(categories.workspaceId, workspaceId)),
  });
  if (!category) throw new Error('TARGET_NOT_FOUND');
  const rows = await store.query.channels.findMany({
    columns: { id: true },
    where: and(eq(channels.workspaceId, workspaceId), eq(channels.categoryId, targetId)),
    orderBy: [asc(channels.id)],
  });
  return rows.map((channel: { id: string }) => channel.id);
}

async function findOverride(store: any, target: OverrideTarget, workspaceId: string, targetId: string, roleId: string) {
  return target === 'category'
    ? store.query.categoryRolePermissionOverrides.findFirst({
      where: and(
        eq(categoryRolePermissionOverrides.workspaceId, workspaceId),
        eq(categoryRolePermissionOverrides.categoryId, targetId),
        eq(categoryRolePermissionOverrides.roleId, roleId),
      ),
    })
    : store.query.channelRolePermissionOverrides.findFirst({
      where: and(
        eq(channelRolePermissionOverrides.workspaceId, workspaceId),
        eq(channelRolePermissionOverrides.channelId, targetId),
        eq(channelRolePermissionOverrides.roleId, roleId),
      ),
    });
}

function normalizePreview(input: OverridePreviewInput) {
  if (input.operation === 'delete') return { allowMask: 0, denyMask: 0 };
  if (input.allowMask === undefined || input.denyMask === undefined) throw new Error('INVALID_OVERRIDE');
  assertValidChannelOverrideMask(input.allowMask);
  assertValidChannelOverrideMask(input.denyMask);
  return { allowMask: input.allowMask, denyMask: input.denyMask };
}

function assertExpectedRevision(value: number) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('INVALID_OVERRIDE');
}

async function assertAuthorizationRevision(store: any, workspaceId: string, expected: string) {
  if (!/^[a-f0-9]{64}$/.test(expected)) throw new Error('INVALID_OVERRIDE');
  if (await computeAuthorizationRevisionFromStore(store, workspaceId) !== expected) {
    throw new Error('STALE_PREVIEW');
  }
}

function formatOverride(row: any) {
  return {
    workspaceId: row.workspaceId,
    targetId: row.categoryId ?? row.channelId,
    roleId: row.roleId,
    allowMask: row.allowMask,
    denyMask: row.denyMask,
    revision: row.revision,
    updatedAt: row.updatedAt instanceof Date ? row.updatedAt.toISOString() : row.updatedAt,
  };
}

function compareViewerMaps(before: Map<string, string[]>, after: Map<string, string[]>): ChannelViewerEffect[] {
  const effects: ChannelViewerEffect[] = [];
  for (const channelId of [...new Set([...before.keys(), ...after.keys()])].sort()) {
    const previous = new Set(before.get(channelId) ?? []);
    const next = new Set(after.get(channelId) ?? []);
    const lostUserIds = [...previous].filter((userId) => !next.has(userId)).sort();
    const gainedUserIds = [...next].filter((userId) => !previous.has(userId)).sort();
    if (lostUserIds.length > 0 || gainedUserIds.length > 0) {
      effects.push({ channelId, lostUserIds, gainedUserIds, rotationRequired: lostUserIds.length > 0 });
    }
  }
  return effects;
}
