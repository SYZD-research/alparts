import { db } from '../db/index.js';
import {
  channels,
  channelMembers,
  channelPreferences,
  categories,
  workspaceMembers,
  workspaces,
  users,
} from '../db/schema.js';
import { eq, and, asc, inArray, ne, sql } from 'drizzle-orm';
import { Permissions } from '@alparts/shared';
import { auditedTransaction } from '../middleware/audit.js';
import {
  MAX_CATEGORIES_PER_WORKSPACE,
  MAX_CHANNELS_PER_WORKSPACE,
  MAX_TOTAL_CHANNELS_PER_WORKSPACE,
  MAX_WORKSPACE_MEMBERS,
} from '../security/limits.js';
import {
  applyViewerEffectsAndRotation,
  assertNoSuperiorAccessLoss,
  captureChannelViewersFromSnapshot,
  captureChannelViewersFromStore,
  getChannelAuthorizationFromSnapshot,
  getChannelAuthorizationFromStore,
  getChannelViewerIdsFromStore,
  getWorkspaceAuthorizationFromSnapshot,
  getWorkspaceAuthorizationFromStore,
  isVisibleChannelAuthorization,
  loadWorkspaceAuthorizationSnapshot,
  lockWorkspaceForAuthorization,
} from './authorization.service.js';

export async function getWorkspaceChannels(workspaceId: string, userId: string) {
  return db.transaction(async (transaction) => {
    await lockWorkspaceForAuthorization(transaction, workspaceId, 'share');
    const snapshot = await loadWorkspaceAuthorizationSnapshot(transaction, workspaceId);
    if (!snapshot) return [];
    return snapshot.channels.flatMap((channel) => (
      isVisibleChannelAuthorization(getChannelAuthorizationFromSnapshot(snapshot, userId, channel, {}, false))
        ? [formatChannel(channel as any)]
        : []
    ));
  });
}

export async function getWorkspaceCategories(workspaceId: string, userId: string) {
  return db.transaction(async (transaction) => {
    await lockWorkspaceForAuthorization(transaction, workspaceId, 'share');
    const snapshot = await loadWorkspaceAuthorizationSnapshot(transaction, workspaceId);
    if (!snapshot) return [];
    const workspaceAuthorization = getWorkspaceAuthorizationFromSnapshot(snapshot, userId);
    if (!workspaceAuthorization) return [];
    const canManageEmptyCategories = workspaceAuthorization.isOwner
      || (workspaceAuthorization.permissionMask & Permissions.MANAGE_CHANNELS) === Permissions.MANAGE_CHANNELS;
    const cats = await transaction.query.categories.findMany({
      where: eq(categories.workspaceId, workspaceId),
      orderBy: [asc(categories.position), asc(categories.id)],
      limit: MAX_CATEGORIES_PER_WORKSPACE + 1,
    });
    if (cats.length > MAX_CATEGORIES_PER_WORKSPACE) throw new Error('CATEGORY_INVARIANT_EXCEEDED');

    return cats.flatMap((category: any) => {
      const visibleChannels = snapshot.channels.flatMap((channel) => (
        channel.categoryId === category.id
        && isVisibleChannelAuthorization(getChannelAuthorizationFromSnapshot(snapshot, userId, channel, {}, false))
          ? [formatChannel(channel as any)]
          : []
      ));
      if (visibleChannels.length === 0 && !canManageEmptyCategories) return [];
      return [{
        id: category.id,
        workspaceId: category.workspaceId,
        name: category.name,
        position: category.position,
        channels: visibleChannels,
      }];
    });
  });
}

export async function createChannel(
  workspaceId: string,
  name: string,
  type: string = 'text',
  options?: { categoryId?: string; isPrivate?: boolean; topic?: string; position?: number },
  actorId?: string,
) {
  if (!actorId) throw new Error('CHANNEL_ACTOR_REQUIRED');
  if (!['text', 'announcement', 'voice'].includes(type)) throw new Error('INVALID_CHANNEL_TYPE');
  const channel = await auditedTransaction(async (transaction) => {
    await lockWorkspaceForMutation(transaction, workspaceId);
    await assertWorkspaceChannelManager(transaction, workspaceId, actorId);
    const existingChannels = await transaction.query.channels.findMany({
      columns: { id: true },
      where: and(eq(channels.workspaceId, workspaceId), ne(channels.type, 'dm')),
      limit: MAX_CHANNELS_PER_WORKSPACE + 1,
    });
    if (existingChannels.length >= MAX_CHANNELS_PER_WORKSPACE) throw new Error('CHANNEL_LIMIT_REACHED');
    if (options?.categoryId) await assertCategoryWorkspace(transaction, options.categoryId, workspaceId);
    const [created] = await transaction.insert(channels).values({
      workspaceId,
      name,
      type,
      categoryId: options?.categoryId || null,
      isPrivate: options?.isPrivate ?? false,
      topic: options?.topic || null,
      position: options?.position ?? 0,
    }).returning();
    if (created.isPrivate) {
      await transaction.insert(channelMembers).values({ channelId: created.id, userId: actorId });
    }
    return created;
  }, (created) => ({
    actorId,
    action: 'channel.create',
    targetType: 'channel',
    targetId: created.id,
    details: { workspaceId, name, type },
  }));

  return formatChannel(channel);
}

export async function getChannelById(channelId: string) {
  const channel = await db.query.channels.findFirst({
    where: eq(channels.id, channelId),
  });
  if (!channel) return null;
  return formatChannel(channel);
}

export async function updateChannel(channelId: string, updates: { name?: string; topic?: string; categoryId?: string | null; position?: number; isPrivate?: boolean }, actorId: string) {
  const location = await db.query.channels.findFirst({
    columns: { workspaceId: true },
    where: eq(channels.id, channelId),
  });
  if (!location) return null;
  const result = await auditedTransaction(async (transaction) => {
    const existing = await lockChannelForMutation(transaction, channelId, location.workspaceId);
    if (!existing) throw new Error('CHANNEL_NOT_FOUND');
    assertGenericChannel(existing);
    await assertChannelManager(transaction, existing, actorId);
    if (updates.categoryId) await assertCategoryWorkspace(transaction, updates.categoryId, existing.workspaceId);
    const snapshotBefore = await loadWorkspaceAuthorizationSnapshot(transaction, existing.workspaceId, [channelId]);
    if (!snapshotBefore) throw new Error('CHANNEL_NOT_FOUND');
    const before = captureChannelViewersFromSnapshot(snapshotBefore);
    const privacyChanged = updates.isPrivate !== undefined && updates.isPrivate !== existing.isPrivate;
    if (privacyChanged) {
      await transaction.delete(channelMembers).where(eq(channelMembers.channelId, channelId));
      if (updates.isPrivate === true) {
        await transaction.insert(channelMembers).values({ channelId, userId: actorId });
      }
    }

    const [updated] = await transaction.update(channels).set({
      ...updates,
    }).where(and(eq(channels.id, channelId), eq(channels.workspaceId, existing.workspaceId))).returning();
    if (!updated) throw new Error('CHANNEL_NOT_FOUND');
    const snapshotAfter = await loadWorkspaceAuthorizationSnapshot(transaction, existing.workspaceId, [channelId]);
    if (!snapshotAfter) throw new Error('CHANNEL_NOT_FOUND');
    assertNoSuperiorAccessLoss(snapshotBefore, snapshotAfter, actorId);
    const after = captureChannelViewersFromSnapshot(snapshotAfter);
    const roomEffects = await applyViewerEffectsAndRotation(transaction, before, after);
    const effect = roomEffects[0];
    return {
      existing,
      updated: effect?.rotationRequired ? { ...updated, keyRotationRequired: true } : updated,
      removedUserIds: effect?.lostUserIds ?? [],
      gainedUserIds: effect?.gainedUserIds ?? [],
      rotationRequired: effect?.rotationRequired ?? false,
      roomEffects,
    };
  }, (committed) => ({
    actorId,
    action: 'channel.update',
    targetType: 'channel',
    targetId: channelId,
    details: {
      workspaceId: committed.updated.workspaceId,
      fields: Object.keys(updates),
      privacyChanged: committed.existing.isPrivate !== committed.updated.isPrivate,
      privacyBefore: committed.existing.isPrivate,
      privacyAfter: committed.updated.isPrivate,
      removedUserIds: committed.removedUserIds,
      gainedUserIds: committed.gainedUserIds,
      rotationRequired: committed.rotationRequired,
    },
  }));
  return {
    channel: formatChannel(result.updated),
    workspaceId: result.updated.workspaceId,
    removedUserIds: result.removedUserIds,
    gainedUserIds: result.gainedUserIds,
    rotationRequired: result.rotationRequired,
    roomEffects: result.roomEffects,
  };
}

export async function deleteChannel(channelId: string, actorId: string) {
  const location = await db.query.channels.findFirst({
    columns: { workspaceId: true },
    where: eq(channels.id, channelId),
  });
  if (!location) return null;
  let deleted;
  try {
    deleted = await auditedTransaction(async (transaction) => {
      const existing = await lockChannelForMutation(transaction, channelId, location.workspaceId);
      if (!existing) throw new Error('CHANNEL_NOT_FOUND');
      assertGenericChannel(existing);
      await assertChannelManager(transaction, existing, actorId);
      const snapshotBefore = await loadWorkspaceAuthorizationSnapshot(transaction, existing.workspaceId, [channelId]);
      if (!snapshotBefore) throw new Error('CHANNEL_NOT_FOUND');
      // Evaluate removal before touching dependants, so hierarchy rejection is
      // independent of whether foreign keys would also prevent deletion.
      assertNoSuperiorAccessLoss(snapshotBefore, {
        ...snapshotBefore, channels: [], channelsById: new Map(),
      }, actorId);
      const viewerUserIds = await getChannelViewerIdsFromStore(transaction, existing);
      // Explicit private-channel grants are part of the channel itself. Other
      // durable dependants (messages, keys, uploads, DM records) deliberately
      // make deletion fail with CHANNEL_IN_USE instead of being cascaded.
      await transaction.delete(channelMembers).where(eq(channelMembers.channelId, channelId));
      await transaction.delete(channelPreferences).where(eq(channelPreferences.channelId, channelId));
      const [removed] = await transaction.delete(channels)
        .where(and(eq(channels.id, channelId), eq(channels.workspaceId, existing.workspaceId)))
        .returning({ id: channels.id, workspaceId: channels.workspaceId });
      if (!removed) throw new Error('CHANNEL_NOT_FOUND');
      return { ...removed, viewerUserIds };
    }, (removed) => ({
      actorId,
      action: 'channel.delete',
      targetType: 'channel',
      targetId: channelId,
      details: { workspaceId: removed.workspaceId },
    }));
  } catch (error: any) {
    if (error?.code === '23503' || error?.cause?.code === '23503') throw new Error('CHANNEL_IN_USE');
    throw error;
  }
  return {
    channelId: deleted.id,
    workspaceId: deleted.workspaceId,
    viewerUserIds: deleted.viewerUserIds,
  };
}

export async function createCategory(workspaceId: string, name: string, position: number | undefined, actorId: string) {
  if (position !== undefined) assertValidCategoryPosition(position);
  const category = await auditedTransaction(async (transaction) => {
    await lockWorkspaceForMutation(transaction, workspaceId);
    await assertWorkspaceChannelManager(transaction, workspaceId, actorId);
    const existingCategories = await transaction.query.categories.findMany({
      columns: { id: true },
      where: eq(categories.workspaceId, workspaceId),
      limit: MAX_CATEGORIES_PER_WORKSPACE + 1,
    });
    if (existingCategories.length >= MAX_CATEGORIES_PER_WORKSPACE) throw new Error('CATEGORY_LIMIT_REACHED');
    const [created] = await transaction.insert(categories).values({
      workspaceId,
      name,
      position: position ?? 0,
    }).returning();
    return created;
  }, (created) => ({
    actorId,
    action: 'category.create',
    targetType: 'category',
    targetId: created.id,
    details: { workspaceId, name },
  }));

  return category;
}

export async function updateCategory(
  workspaceId: string,
  categoryId: string,
  updates: { name?: string; position?: number },
  actorId: string,
) {
  if (updates.position !== undefined) assertValidCategoryPosition(updates.position);
  const result = await auditedTransaction(async (transaction) => {
    await lockWorkspaceForMutation(transaction, workspaceId);
    await assertWorkspaceChannelManager(transaction, workspaceId, actorId);
    await transaction.execute(sql`
      select 1 from ${categories}
      where ${categories.id} = ${categoryId} and ${categories.workspaceId} = ${workspaceId}
      for update
    `);
    const existing = await transaction.query.categories.findFirst({
      where: and(eq(categories.id, categoryId), eq(categories.workspaceId, workspaceId)),
    });
    if (!existing) throw new Error('CATEGORY_NOT_FOUND');
    const [updated] = await transaction.update(categories)
      .set(updates)
      .where(and(eq(categories.id, categoryId), eq(categories.workspaceId, workspaceId)))
      .returning();
    if (!updated) throw new Error('CATEGORY_NOT_FOUND');
    return { existing, updated };
  }, (committed) => ({
    actorId,
    action: 'category.update',
    targetType: 'category',
    targetId: categoryId,
    details: {
      workspaceId,
      before: { name: committed.existing.name, position: committed.existing.position },
      after: { name: committed.updated.name, position: committed.updated.position },
    },
  }));
  return result.updated;
}

export async function deleteCategory(workspaceId: string, categoryId: string, actorId: string) {
  const result = await auditedTransaction(async (transaction) => {
    await lockWorkspaceForMutation(transaction, workspaceId);
    await assertWorkspaceChannelManager(transaction, workspaceId, actorId);
    await transaction.execute(sql`
      select 1 from ${categories}
      where ${categories.id} = ${categoryId} and ${categories.workspaceId} = ${workspaceId}
      for update
    `);
    const existing = await transaction.query.categories.findFirst({
      where: and(eq(categories.id, categoryId), eq(categories.workspaceId, workspaceId)),
    });
    if (!existing) throw new Error('CATEGORY_NOT_FOUND');
    const affectedChannels = await transaction.query.channels.findMany({
      columns: { id: true },
      where: and(eq(channels.workspaceId, workspaceId), eq(channels.categoryId, categoryId)),
      orderBy: [asc(channels.id)],
      limit: MAX_TOTAL_CHANNELS_PER_WORKSPACE + 1,
    });
    if (affectedChannels.length > MAX_TOTAL_CHANNELS_PER_WORKSPACE) throw new Error('CHANNEL_INVARIANT_EXCEEDED');
    for (const channel of affectedChannels) {
      await transaction.execute(sql`select pg_advisory_xact_lock(hashtext(${channel.id})::bigint)`);
    }
    const affectedChannelIds = affectedChannels.map((channel: { id: string }) => channel.id);
    const snapshotBefore = await loadWorkspaceAuthorizationSnapshot(transaction, workspaceId, affectedChannelIds);
    if (!snapshotBefore) throw new Error('CATEGORY_NOT_FOUND');
    const before = captureChannelViewersFromSnapshot(snapshotBefore);
    await transaction.update(channels)
      .set({ categoryId: null })
      .where(and(eq(channels.workspaceId, workspaceId), eq(channels.categoryId, categoryId)));
    await transaction.delete(categories)
      .where(and(eq(categories.id, categoryId), eq(categories.workspaceId, workspaceId)));
    const snapshotAfter = await loadWorkspaceAuthorizationSnapshot(transaction, workspaceId, affectedChannelIds);
    if (!snapshotAfter) throw new Error('CATEGORY_NOT_FOUND');
    assertNoSuperiorAccessLoss(snapshotBefore, snapshotAfter, actorId);
    const after = captureChannelViewersFromSnapshot(snapshotAfter);
    const roomEffects = await applyViewerEffectsAndRotation(transaction, before, after);
    return { existing, movedChannelIds: affectedChannelIds, roomEffects };
  }, (committed) => ({
    actorId,
    action: 'category.delete',
    targetType: 'category',
    targetId: categoryId,
    details: {
      workspaceId,
      name: committed.existing.name,
      movedChannelCount: committed.movedChannelIds.length,
      movedChannelIds: committed.movedChannelIds,
    },
  }));
  return { categoryId, workspaceId, movedChannelIds: result.movedChannelIds, roomEffects: result.roomEffects };
}

export async function isChannelMember(channelId: string, userId: string): Promise<boolean> {
  const channel = await db.query.channels.findFirst({
    where: eq(channels.id, channelId),
  });
  if (!channel) return false;

  return isVisibleChannelAuthorization(await getChannelAuthorizationFromStore(db, userId, channel));
}

export async function getChannelMembers(channelId: string) {
  const ch = await db.query.channels.findFirst({
    where: eq(channels.id, channelId),
  });
  if (!ch) return [];

  const viewerIds = await getChannelViewerIdsFromStore(db, ch);
  if (viewerIds.length === 0) return [];
  const result = await db.query.users.findMany({
    where: inArray(users.id, viewerIds),
    orderBy: [asc(users.id)],
    limit: MAX_WORKSPACE_MEMBERS + 1,
  });
  if (result.length > MAX_WORKSPACE_MEMBERS) throw new Error('WORKSPACE_MEMBER_INVARIANT_EXCEEDED');
  return result.map((user) => ({
    id: user.id,
    displayName: user.displayName,
    avatarUrl: user.avatarUrl,
    status: user.status,
  }));
}

export async function addChannelMember(channelId: string, userId: string, actorId: string) {
  const location = await db.query.channels.findFirst({
    columns: { workspaceId: true },
    where: eq(channels.id, channelId),
  });
  if (!location) throw new Error('PRIVATE_CHANNEL_NOT_FOUND');
  const result = await auditedTransaction(async (transaction) => {
    const channel = await lockChannelForMutation(transaction, channelId, location.workspaceId);
    if (!channel || !channel.isPrivate || channel.type === 'dm') throw new Error('PRIVATE_CHANNEL_NOT_FOUND');
    await assertChannelManager(transaction, channel, actorId);
    const before = await captureChannelViewersFromStore(transaction, channel.workspaceId, [channelId]);
    const workspaceMember = await transaction.query.workspaceMembers.findFirst({
      where: and(eq(workspaceMembers.workspaceId, channel.workspaceId), eq(workspaceMembers.userId, userId)),
    });
    if (!workspaceMember) throw new Error('WORKSPACE_MEMBER_REQUIRED');
    const inserted = await transaction.insert(channelMembers)
      .values({ channelId, userId })
      .onConflictDoNothing()
      .returning({ userId: channelMembers.userId });
    const after = await captureChannelViewersFromStore(transaction, channel.workspaceId, [channelId]);
    const roomEffects = await applyViewerEffectsAndRotation(transaction, before, after);
    return { workspaceId: channel.workspaceId, changed: inserted.length === 1, roomEffects };
  }, (committed) => ({
    actorId,
    action: 'channel.member.add',
    targetType: 'channel',
    targetId: channelId,
    details: { workspaceId: committed.workspaceId, addedUserId: userId, changed: committed.changed },
  }));
  return { channelId, userId, ...result };
}

export async function removeChannelMember(channelId: string, userId: string, actorId: string) {
  const location = await db.query.channels.findFirst({
    columns: { workspaceId: true },
    where: eq(channels.id, channelId),
  });
  if (!location) throw new Error('PRIVATE_CHANNEL_NOT_FOUND');
  const result = await auditedTransaction(async (transaction) => {
    const channel = await lockChannelForMutation(transaction, channelId, location.workspaceId);
    if (!channel || !channel.isPrivate || channel.type === 'dm') throw new Error('PRIVATE_CHANNEL_NOT_FOUND');
    await assertChannelManager(transaction, channel, actorId);
    const member = await transaction.query.channelMembers.findFirst({
      where: and(eq(channelMembers.channelId, channelId), eq(channelMembers.userId, userId)),
    });
    if (!member) throw new Error('CHANNEL_MEMBER_NOT_FOUND');
    const explicitMembers = await transaction.query.channelMembers.findMany({
      columns: { userId: true },
      where: eq(channelMembers.channelId, channelId),
      limit: MAX_WORKSPACE_MEMBERS + 1,
    });
    if (explicitMembers.length > MAX_WORKSPACE_MEMBERS) throw new Error('PRIVATE_MEMBERSHIP_INVARIANT_EXCEEDED');
    if (explicitMembers.length <= 1) throw new Error('LAST_PRIVATE_MEMBER');
    const snapshotBefore = await loadWorkspaceAuthorizationSnapshot(transaction, channel.workspaceId, [channelId]);
    if (!snapshotBefore) throw new Error('PRIVATE_CHANNEL_NOT_FOUND');
    const before = captureChannelViewersFromSnapshot(snapshotBefore);
    await transaction.delete(channelMembers).where(and(
      eq(channelMembers.channelId, channelId),
      eq(channelMembers.userId, userId),
    ));
    const snapshotAfter = await loadWorkspaceAuthorizationSnapshot(transaction, channel.workspaceId, [channelId]);
    if (!snapshotAfter) throw new Error('PRIVATE_CHANNEL_NOT_FOUND');
    // Same boundary as role and override changes: only a higher-ranked member
    // (or the owner, or the member themself) may remove someone.
    assertNoSuperiorAccessLoss(snapshotBefore, snapshotAfter, actorId);
    const after = captureChannelViewersFromSnapshot(snapshotAfter);
    const roomEffects = await applyViewerEffectsAndRotation(transaction, before, after);
    return {
      workspaceId: channel.workspaceId,
      rotationRequired: roomEffects.some((effect) => effect.rotationRequired),
      roomEffects,
    };
  }, (committed) => ({
    actorId,
    action: 'channel.member.remove',
    targetType: 'channel',
    targetId: channelId,
    details: { workspaceId: committed.workspaceId, removedUserId: userId, rotationRequired: committed.rotationRequired },
  }));
  return { channelId, userId, ...result };
}

async function assertCategoryWorkspace(store: any, categoryId: string, workspaceId: string): Promise<void> {
  const category = await store.query.categories.findFirst({ where: eq(categories.id, categoryId) });
  if (!category || category.workspaceId !== workspaceId) throw new Error('INVALID_CATEGORY');
}

async function lockChannelForMutation(store: any, channelId: string, workspaceId: string) {
  const locked = await store.execute(sql`select id from ${workspaces} where ${workspaces.id} = ${workspaceId} for update`);
  if (locked.rowCount === 0) return null;
  await store.execute(sql`select pg_advisory_xact_lock(hashtext(${channelId})::bigint)`);
  return store.query.channels.findFirst({
    where: and(eq(channels.id, channelId), eq(channels.workspaceId, workspaceId)),
  });
}

async function lockWorkspaceForMutation(store: any, workspaceId: string) {
  const locked = await store.execute(sql`select id from ${workspaces} where ${workspaces.id} = ${workspaceId} for update`);
  if (locked.rowCount === 0) throw new Error('WORKSPACE_NOT_FOUND');
}

async function assertWorkspaceChannelManager(
  store: any,
  workspaceId: string,
  actorId: string,
  failure = 'NOT_AUTHORIZED',
) {
  const member = await store.query.workspaceMembers.findFirst({
    where: and(eq(workspaceMembers.workspaceId, workspaceId), eq(workspaceMembers.userId, actorId)),
  });
  if (!member) throw new Error(failure);
  const authorization = await getWorkspaceAuthorizationFromStore(store, workspaceId, actorId);
  const permissions = authorization?.permissionMask ?? 0;
  if (
    (permissions & Permissions.VIEW_CHANNELS) !== Permissions.VIEW_CHANNELS
    || (permissions & Permissions.MANAGE_CHANNELS) !== Permissions.MANAGE_CHANNELS
  ) throw new Error(failure);
}

async function assertChannelManager(
  store: any,
  channel: { id: string; workspaceId: string; isPrivate: boolean },
  actorId: string,
) {
  const authorization = await getChannelAuthorizationFromStore(store, actorId, channel as any);
  if (!isVisibleChannelAuthorization(authorization)) throw new Error('CHANNEL_NOT_FOUND');
  if ((authorization.permissions & Permissions.MANAGE_CHANNELS) !== Permissions.MANAGE_CHANNELS) {
    throw new Error('CHANNEL_NOT_FOUND');
  }
}

function assertGenericChannel(channel: { type: string }): void {
  if (channel.type === 'dm') throw new Error('CHANNEL_NOT_FOUND');
}

export function assertValidCategoryPosition(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > 1_000_000) {
    throw new Error('INVALID_POSITION');
  }
}

function formatChannel(ch: any) {
  return {
    id: ch.id,
    workspaceId: ch.workspaceId,
    categoryId: ch.categoryId,
    name: ch.name,
    type: ch.type,
    isPrivate: ch.isPrivate,
    keyRotationRequired: ch.keyRotationRequired,
    topic: ch.topic,
    position: ch.position,
    createdAt: ch.createdAt.toISOString(),
  };
}
