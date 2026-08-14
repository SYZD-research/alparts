import { db } from '../db/index.js';
import { messages, messagePins, readPositions, users } from '../db/schema.js';
import { eq, and, desc, lt, sql } from 'drizzle-orm';
import { MESSAGES_PER_PAGE } from '@alparts/shared';
import { audit } from '../middleware/audit.js';

export async function getChannelMessages(
  channelId: string,
  options?: { cursor?: string; limit?: number },
) {
  const limit = options?.limit || MESSAGES_PER_PAGE;

  let query = db.query.messages.findMany({
    where: eq(messages.channelId, channelId),
    orderBy: [desc(messages.createdAt)],
    limit: limit + 1,
    with: {
      author: true,
    },
  });

  const results = await query;
  const hasMore = results.length > limit;
  const data = results.slice(0, limit);

  return {
    data: data.map(m => formatMessage(m)),
    hasMore,
    cursor: hasMore ? data[data.length - 1]?.id : null,
  };
}

export async function createMessage(
  channelId: string,
  authorId: string,
  deviceId: string,
  content: string,
  contentNonce: string,
  idempotencyKey: string,
  refMessageId?: string,
  type: string = 'message',
) {
  // Check for duplicate (idempotency)
  if (idempotencyKey) {
    const existing = await db.query.messages.findFirst({
      where: and(
        eq(messages.channelId, channelId),
        eq(messages.idempotencyKey, idempotencyKey),
      ),
    });
    if (existing) {
      return formatMessage({ ...existing, author: await getUserForMessage(existing.authorId) });
    }
  }

  const [message] = await db.insert(messages).values({
    channelId,
    authorId,
    deviceId,
    content,
    contentNonce,
    type,
    refMessageId: refMessageId || null,
    idempotencyKey,
  }).returning();

  const author = await getUserForMessage(authorId);

  return formatMessage({ ...message, author });
}

export async function editMessage(
  messageId: string,
  authorId: string,
  content: string,
  contentNonce: string,
) {
  // Append as a new edit event (MSG-16: non-destructive)
  const original = await db.query.messages.findFirst({
    where: eq(messages.id, messageId),
  });
  if (!original) throw new Error('MESSAGE_NOT_FOUND');
  if (original.authorId !== authorId) throw new Error('NOT_AUTHORIZED');

  const [editEvent] = await db.insert(messages).values({
    channelId: original.channelId,
    authorId,
    deviceId: original.deviceId,
    content,
    contentNonce,
    type: 'edit',
    refMessageId: messageId,
    idempotencyKey: `edit-${messageId}-${Date.now()}`,
  }).returning();

  const author = await getUserForMessage(authorId);
  return formatMessage({ ...editEvent, author });
}

export async function deleteMessage(messageId: string, userId: string) {
  const original = await db.query.messages.findFirst({
    where: eq(messages.id, messageId),
  });
  if (!original) throw new Error('MESSAGE_NOT_FOUND');

  // Append delete event
  const [deleteEvent] = await db.insert(messages).values({
    channelId: original.channelId,
    authorId: userId,
    deviceId: original.deviceId,
    content: '',
    contentNonce: '',
    type: 'delete',
    refMessageId: messageId,
    idempotencyKey: `delete-${messageId}-${Date.now()}`,
  }).returning();

  return { messageId, channelId: original.channelId };
}

export async function toggleReaction(messageId: string, userId: string, emoji: string) {
  // For simplicity, reactions are stored as system messages referencing the original
  const original = await db.query.messages.findFirst({
    where: eq(messages.id, messageId),
  });
  if (!original) throw new Error('MESSAGE_NOT_FOUND');

  // Check if reaction already exists
  const existingReaction = await db.query.messages.findFirst({
    where: and(
      eq(messages.refMessageId, messageId),
      eq(messages.authorId, userId),
      eq(messages.type, 'reaction'),
      sql`${messages.content} = ${emoji}`,
    ),
  });

  if (existingReaction) {
    // Remove reaction
    await db.delete(messages).where(eq(messages.id, existingReaction.id));
    return { action: 'removed', emoji };
  }

  // Add reaction
  await db.insert(messages).values({
    channelId: original.channelId,
    authorId: userId,
    deviceId: 'system',
    content: emoji,
    contentNonce: '',
    type: 'reaction',
    refMessageId: messageId,
    idempotencyKey: `reaction-${messageId}-${userId}-${emoji}`,
  });

  return { action: 'added', emoji };
}

export async function getReactions(messageId: string) {
  const reactions = await db.query.messages.findMany({
    where: and(
      eq(messages.refMessageId, messageId),
      eq(messages.type, 'reaction'),
    ),
  });

  const grouped = new Map<string, string[]>();
  for (const r of reactions) {
    const existing = grouped.get(r.content) || [];
    existing.push(r.authorId);
    grouped.set(r.content, existing);
  }

  return Array.from(grouped.entries()).map(([emoji, userIds]) => ({
    emoji,
    count: userIds.length,
    userIds,
  }));
}

export async function pinMessage(messageId: string, channelId: string, userId: string) {
  const existing = await db.query.messagePins.findFirst({
    where: and(
      eq(messagePins.messageId, messageId),
      eq(messagePins.channelId, channelId),
    ),
  });

  if (existing) {
    // Unpin
    await db.delete(messagePins).where(
      and(
        eq(messagePins.messageId, messageId),
        eq(messagePins.channelId, channelId),
      ),
    );
    return { pinned: false };
  }

  await db.insert(messagePins).values({
    channelId,
    messageId,
    pinnedBy: userId,
  });

  return { pinned: true };
}

export async function getPinnedMessages(channelId: string) {
  const pins = await db.query.messagePins.findMany({
    where: eq(messagePins.channelId, channelId),
    with: {
      // message: true,
    },
  });
  return pins;
}

export async function updateReadPosition(userId: string, channelId: string, messageId: string) {
  await db.insert(readPositions)
    .values({ userId, channelId, lastReadMessageId: messageId })
    .onConflictDoUpdate({
      target: [readPositions.userId, readPositions.channelId],
      set: { lastReadMessageId: messageId, updatedAt: new Date() },
    });
}

export async function getReadPositions(userId: string, channelId: string) {
  return db.query.readPositions.findFirst({
    where: and(
      eq(readPositions.userId, userId),
      eq(readPositions.channelId, channelId),
    ),
  });
}

async function getUserForMessage(userId: string) {
  const user = await db.query.users.findFirst({
    where: eq(users.id, userId),
  });
  if (!user) return { id: userId, displayName: 'Unknown', avatarUrl: null, status: 'offline', email: '', createdAt: new Date().toISOString() };
  return {
    id: user.id,
    displayName: user.displayName,
    avatarUrl: user.avatarUrl,
    status: user.status,
    email: user.email,
    createdAt: user.createdAt.toISOString(),
  };
}

function formatMessage(m: any) {
  return {
    id: m.id,
    channelId: m.channelId,
    authorId: m.authorId,
    author: m.author,
    deviceId: m.deviceId,
    content: m.content,
    encryptedContent: m.content,
    contentNonce: m.contentNonce,
    type: m.type,
    refMessageId: m.refMessageId,
    reactions: [],
    isPinned: false,
    idempotencyKey: m.idempotencyKey,
    createdAt: m.createdAt.toISOString(),
  };
}
