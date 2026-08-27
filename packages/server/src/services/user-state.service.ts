import { and, desc, eq, gt, inArray, lt, or, sql } from 'drizzle-orm';
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
import { getWorkspaceChannels } from './channel.service.js';
import {
  getChannelAuthorizationFromStore,
  isVisibleChannelAuthorization,
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
  return db.transaction(async (transaction) => {
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
  });
}

export async function toggleMessageBookmark(messageId: string, userId: string) {
  const message = await db.query.messages.findFirst({
    columns: { channelId: true, type: true },
    where: eq(messages.id, messageId),
  });
  if (!message || message.type !== 'message') throw new Error('MESSAGE_NOT_FOUND');
  const location = await db.query.channels.findFirst({ columns: { workspaceId: true }, where: eq(channels.id, message.channelId) });
  if (!location) throw new Error('MESSAGE_NOT_FOUND');
  return db.transaction(async (transaction) => {
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
    const [created] = await transaction.insert(messageBookmarks)
      .values({ userId, messageId })
      .returning();
    return {
      messageId,
      channelId: message.channelId,
      bookmarked: true,
      createdAt: created.createdAt.toISOString(),
    };
  });
}

export async function listMessageBookmarks(userId: string, limit = 100) {
  const requested = Math.min(Math.max(limit, 1), 500);
  const authorized: Array<{ messageId: string; channelId: string; createdAt: string }> = [];
  const authorizationCache = new Map<string, boolean>();
  let cursor: { createdAt: Date; messageId: string } | null = null;
  let examined = 0;
  const maxExamined = 10_000;
  while (authorized.length < requested && examined < maxExamined) {
    const rows: Array<{ messageId: string; channelId: string; createdAt: Date }> = await db.select({
      messageId: messageBookmarks.messageId,
      channelId: messages.channelId,
      createdAt: messageBookmarks.createdAt,
    }).from(messageBookmarks)
      .innerJoin(messages, and(eq(messages.id, messageBookmarks.messageId), eq(messages.type, 'message')))
      .where(and(
        eq(messageBookmarks.userId, userId),
        cursor ? or(
          lt(messageBookmarks.createdAt, cursor.createdAt),
          and(eq(messageBookmarks.createdAt, cursor.createdAt), lt(messageBookmarks.messageId, cursor.messageId)),
        ) : undefined,
      ))
      .orderBy(desc(messageBookmarks.createdAt), desc(messageBookmarks.messageId))
      .limit(Math.min(500, maxExamined - examined));
    if (rows.length === 0) break;
    examined += rows.length;
    for (const row of rows) {
      let allowed = authorizationCache.get(row.channelId);
      if (allowed === undefined) {
        const authorization = await getChannelAuthorizationFromStore(db, userId, row.channelId);
        allowed = isVisibleChannelAuthorization(authorization);
        authorizationCache.set(row.channelId, allowed);
      }
      if (allowed) {
        authorized.push({
          messageId: row.messageId,
          channelId: row.channelId,
          createdAt: row.createdAt.toISOString(),
        });
        if (authorized.length >= requested) break;
      }
    }
    const last: { messageId: string; channelId: string; createdAt: Date } = rows[rows.length - 1];
    cursor = { createdAt: last.createdAt, messageId: last.messageId };
    if (rows.length < Math.min(500, maxExamined - examined + rows.length)) break;
  }
  return authorized;
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
