import { and, desc, eq, gt, inArray, or, sql } from 'drizzle-orm';
import { alias } from 'drizzle-orm/pg-core';
import type { NotificationLevel } from '@alparts/shared';
import { db } from '../db/index.js';
import {
  channelPreferences,
  channels,
  messageBookmarks,
  messages,
  readPositions,
} from '../db/schema.js';
import { auditedTransaction } from '../middleware/audit.js';
import { MAX_BOOKMARKS_PER_USER } from '../security/limits.js';
import { getWorkspaceChannels } from './channel.service.js';
import {
  getChannelAuthorizationFromStore,
  getChannelAuthorizationFromSnapshot,
  isVisibleChannelAuthorization,
  loadWorkspaceAuthorizationSnapshot,
  lockWorkspaceForAuthorization,
} from './authorization.service.js';

interface PreferenceUpdate {
  favorite?: boolean;
  muted?: boolean;
  hidden?: boolean;
  notificationLevel?: NotificationLevel;
}

export async function getWorkspaceChannelState(workspaceId: string, userId: string) {
  const visibleChannels = await getWorkspaceChannels(workspaceId, userId);
  const channelIds = visibleChannels.map((channel) => channel.id);
  if (channelIds.length === 0) return [];
  const lastReadMessages = alias(messages, 'last_read_messages');

  const [preferences, positions, latestRows, unreadRows] = await Promise.all([
    db.query.channelPreferences.findMany({
      where: and(
        eq(channelPreferences.userId, userId),
        inArray(channelPreferences.channelId, channelIds),
      ),
    }),
    db.select({
      channelId: readPositions.channelId,
      lastReadMessageId: lastReadMessages.id,
    }).from(readPositions)
      .leftJoin(lastReadMessages, and(
        eq(lastReadMessages.id, readPositions.lastReadMessageId),
        eq(lastReadMessages.channelId, readPositions.channelId),
        eq(lastReadMessages.type, 'message'),
      ))
      .where(and(eq(readPositions.userId, userId), inArray(readPositions.channelId, channelIds))),
    db.selectDistinctOn([messages.channelId], {
      channelId: messages.channelId,
      id: messages.id,
    }).from(messages)
      .where(and(
        inArray(messages.channelId, channelIds),
        eq(messages.type, 'message'),
        isUndeletedBaseMessage(),
      ))
      .orderBy(messages.channelId, desc(messages.createdAt), desc(messages.id)),
    db.select({
      channelId: messages.channelId,
      count: sql<number>`count(*)::int`,
    }).from(messages)
      .leftJoin(readPositions, and(
        eq(readPositions.userId, userId),
        eq(readPositions.channelId, messages.channelId),
      ))
      .leftJoin(lastReadMessages, and(
        eq(lastReadMessages.id, readPositions.lastReadMessageId),
        eq(lastReadMessages.channelId, messages.channelId),
        eq(lastReadMessages.type, 'message'),
      ))
      .where(and(
        inArray(messages.channelId, channelIds),
        eq(messages.type, 'message'),
        isUndeletedBaseMessage(),
        or(
          sql`${lastReadMessages.id} is null`,
          gt(messages.createdAt, lastReadMessages.createdAt),
          and(eq(messages.createdAt, lastReadMessages.createdAt), gt(messages.id, lastReadMessages.id)),
        ),
      ))
      .groupBy(messages.channelId),
  ]);
  const preferenceByChannel = new Map(preferences.map((preference) => [preference.channelId, preference]));
  const positionByChannel = new Map(positions.map((position) => [position.channelId, position]));
  const latestByChannel = new Map(latestRows.map((message) => [message.channelId, message.id]));
  const unreadByChannel = new Map(unreadRows.map((row) => [row.channelId, Number(row.count)]));

  return channelIds.map((channelId) => {
    const preference = preferenceByChannel.get(channelId);
    const position = positionByChannel.get(channelId);
    return {
      channelId,
      favorite: preference?.favorite ?? false,
      muted: preference?.muted ?? false,
      hidden: preference?.hidden ?? false,
      notificationLevel: normalizeNotificationLevel(preference?.notificationLevel),
      updatedAt: preference?.updatedAt.toISOString() ?? null,
      lastReadMessageId: position?.lastReadMessageId ?? null,
      latestMessageId: latestByChannel.get(channelId) ?? null,
      unreadCount: unreadByChannel.get(channelId) ?? 0,
    };
  });
}

/** Keep unread/latest state aligned with the append-only message projection. */
function isUndeletedBaseMessage() {
  return sql<boolean>`not exists (
    select 1
    from "messages" as "message_deletions"
    where "message_deletions"."ref_message_id" = ${messages.id}
      and "message_deletions"."type" = 'delete'
  )`;
}

export async function updateChannelPreference(
  channelId: string,
  userId: string,
  updates: PreferenceUpdate,
) {
  const location = await db.query.channels.findFirst({ columns: { workspaceId: true }, where: eq(channels.id, channelId) });
  if (!location) throw new Error('CHANNEL_NOT_FOUND');
  return auditedTransaction(async (transaction) => {
    await lockWorkspaceForAuthorization(transaction, location.workspaceId, 'share');
    const channel = await transaction.query.channels.findFirst({ where: eq(channels.id, channelId) });
    if (!channel || channel.workspaceId !== location.workspaceId) throw new Error('CHANNEL_NOT_FOUND');
    if (!isVisibleChannelAuthorization(await getChannelAuthorizationFromStore(transaction, userId, channel))) {
      throw new Error('CHANNEL_NOT_FOUND');
    }
    const updatedAt = new Date();
    const [preference] = await transaction.insert(channelPreferences).values({
      userId,
      channelId,
      favorite: updates.favorite ?? false,
      muted: updates.muted ?? false,
      hidden: updates.hidden ?? false,
      notificationLevel: updates.notificationLevel ?? 'all',
      updatedAt,
    }).onConflictDoUpdate({
      target: [channelPreferences.userId, channelPreferences.channelId],
      set: { ...updates, updatedAt },
    }).returning();
    return formatPreference(preference);
  }, (result) => ({
    actorId: userId,
    action: 'channel.preference.update',
    targetType: 'channel',
    targetId: channelId,
    details: {
      workspaceId: location.workspaceId,
      favorite: result.favorite,
      muted: result.muted,
      hidden: result.hidden,
      notificationLevel: result.notificationLevel,
    },
  }));
}

export async function toggleMessageBookmark(messageId: string, userId: string) {
  const message = await db.query.messages.findFirst({
    columns: { channelId: true, type: true },
    where: eq(messages.id, messageId),
  });
  if (!message || message.type !== 'message') throw new Error('MESSAGE_NOT_FOUND');
  const location = await db.query.channels.findFirst({ columns: { workspaceId: true }, where: eq(channels.id, message.channelId) });
  if (!location) throw new Error('MESSAGE_NOT_FOUND');
  return auditedTransaction(async (transaction) => {
    await lockWorkspaceForAuthorization(transaction, location.workspaceId, 'share');
    await transaction.execute(sql`select pg_advisory_xact_lock(hashtext(${`bookmark:${userId}:${messageId}`})::bigint)`);
    const [lockedMessage] = await transaction.select().from(messages)
      .where(and(eq(messages.id, messageId), eq(messages.type, 'message')))
      .for('share');
    if (!lockedMessage || lockedMessage.channelId !== message.channelId) throw new Error('MESSAGE_NOT_FOUND');
    const deleted = await transaction.query.messages.findFirst({
      columns: { id: true },
      where: and(eq(messages.refMessageId, messageId), eq(messages.type, 'delete')),
    });
    if (deleted) throw new Error('MESSAGE_NOT_FOUND');
    const channel = await transaction.query.channels.findFirst({ where: eq(channels.id, message.channelId) });
    if (!channel || !isVisibleChannelAuthorization(await getChannelAuthorizationFromStore(transaction, userId, channel))) {
      throw new Error('MESSAGE_NOT_FOUND');
    }
    const existing = await transaction.query.messageBookmarks.findFirst({
      where: and(eq(messageBookmarks.userId, userId), eq(messageBookmarks.messageId, messageId)),
    });
    if (existing) {
      await transaction.delete(messageBookmarks).where(and(
        eq(messageBookmarks.userId, userId),
        eq(messageBookmarks.messageId, messageId),
      ));
      return { messageId, channelId: message.channelId, bookmarked: false, createdAt: null };
    }
    await transaction.execute(sql`select pg_advisory_xact_lock(hashtext(${`bookmark-user:${userId}`})::bigint)`);
    const retained = await transaction.query.messageBookmarks.findMany({
      columns: { messageId: true },
      where: eq(messageBookmarks.userId, userId),
      limit: MAX_BOOKMARKS_PER_USER + 1,
    });
    if (retained.length >= MAX_BOOKMARKS_PER_USER) throw new Error('BOOKMARK_LIMIT_REACHED');
    const [created] = await transaction.insert(messageBookmarks)
      .values({ userId, messageId })
      .returning();
    return {
      messageId,
      channelId: message.channelId,
      bookmarked: true,
      createdAt: created.createdAt.toISOString(),
    };
  }, (result) => ({
    actorId: userId,
    action: result.bookmarked ? 'message.bookmark.add' : 'message.bookmark.remove',
    targetType: 'message',
    targetId: messageId,
    details: {
      workspaceId: location.workspaceId,
      channelId: result.channelId,
    },
  }));
}

export async function listMessageBookmarks(userId: string, limit = 100) {
  const requested = Math.min(Math.max(limit, 1), 500);
  const rows = await db.select({
    messageId: messageBookmarks.messageId,
    channelId: messages.channelId,
    workspaceId: channels.workspaceId,
    createdAt: messageBookmarks.createdAt,
  }).from(messageBookmarks)
    .innerJoin(messages, and(eq(messages.id, messageBookmarks.messageId), eq(messages.type, 'message')))
    .innerJoin(channels, eq(channels.id, messages.channelId))
    .where(eq(messageBookmarks.userId, userId))
    .orderBy(desc(messageBookmarks.createdAt), desc(messageBookmarks.messageId))
    .limit(MAX_BOOKMARKS_PER_USER + 1);
  if (rows.length > MAX_BOOKMARKS_PER_USER) throw new Error('BOOKMARK_INVARIANT_EXCEEDED');

  const allowedChannels = new Set<string>();
  const channelIdsByWorkspace = new Map<string, string[]>();
  for (const row of rows) {
    const ids = channelIdsByWorkspace.get(row.workspaceId) ?? [];
    if (!ids.includes(row.channelId)) ids.push(row.channelId);
    channelIdsByWorkspace.set(row.workspaceId, ids);
  }
  for (const [workspaceId, channelIds] of channelIdsByWorkspace) {
    await db.transaction(async (transaction) => {
      await lockWorkspaceForAuthorization(transaction, workspaceId, 'share');
      const snapshot = await loadWorkspaceAuthorizationSnapshot(transaction, workspaceId, channelIds);
      if (!snapshot) return;
      for (const channelId of channelIds) {
        if (isVisibleChannelAuthorization(
          getChannelAuthorizationFromSnapshot(snapshot, userId, channelId, {}, false),
        )) allowedChannels.add(channelId);
      }
    });
  }
  return rows
    .filter((row) => allowedChannels.has(row.channelId))
    .slice(0, requested)
    .map((row) => ({
      messageId: row.messageId,
      channelId: row.channelId,
      createdAt: row.createdAt.toISOString(),
    }));
}

function formatPreference(preference: typeof channelPreferences.$inferSelect) {
  return {
    channelId: preference.channelId,
    favorite: preference.favorite,
    muted: preference.muted,
    hidden: preference.hidden,
    notificationLevel: normalizeNotificationLevel(preference.notificationLevel),
    updatedAt: preference.updatedAt.toISOString(),
  };
}

function normalizeNotificationLevel(value: string | null | undefined): NotificationLevel {
  return value === 'mentions' || value === 'none' ? value : 'all';
}
