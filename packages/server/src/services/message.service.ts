import { and, desc, eq, inArray, isNotNull, isNull, lt, or, sql } from 'drizzle-orm';
import {
  MAX_DIRECT_MENTION_RECIPIENTS_PER_MESSAGE,
  Permissions,
  MESSAGES_PER_PAGE,
  type AttentionNotificationKind,
  type SignedMessageEnvelope,
} from '@alparts/shared';
import { db } from '../db/index.js';
import {
  channels,
  devices,
  forumPostReads,
  forumPosts,
  messagePins,
  messageReactions,
  messages,
  readPositions,
  users,
} from '../db/schema.js';
import { auditedTransaction, auditGuardedTransaction } from '../middleware/audit.js';
import { verifyMessageEnvelopeSignature } from '../security/message.js';
import { getAttachmentsForMessages } from './file.service.js';
import { scopedIdempotencyKey, signedIdempotencyKey } from './message-idempotency.js';
import {
  getChannelAuthorizationFromStore,
  getChannelViewerIdsFromStore,
  isVisibleChannelAuthorization,
  lockWorkspaceForAuthorization,
} from './authorization.service.js';
import {
  MAX_PINS_PER_CHANNEL,
  MAX_REACTION_EMOJIS_PER_MESSAGE,
  MAX_REACTIONS_PER_MESSAGE,
  MAX_REACTIONS_PER_USER_PER_MESSAGE,
} from '../security/limits.js';
import { authorizeGroupWrite } from './mls-group-gate.js';
import {
  addForumPostTags,
  loadForumPostStates,
  lockForumPost,
  type ForumPostBroadcastState,
} from './forum-state.js';

interface CryptoEventInput {
  deviceId: string;
  encryptedContent: string;
  contentNonce: string;
  keyVersion: number;
  idempotencyKey: string;
  signature: string;
  broadcastMention: boolean;
  /**
   * Forum channels only (required there, rejected elsewhere). Null starts a
   * new post; otherwise the post this event belongs to.
   */
  postId?: string | null;
}

interface ReactionRow {
  messageId: string;
  emoji: string;
  userId: string;
}

type CryptoEventType = 'message' | 'edit' | 'delete';
export async function getChannelMessages(
  channelId: string,
  userId: string,
  options?: { cursor?: string; limit?: number },
) {
  return db.transaction(async (tx) => {
    const channel = await tx.query.channels.findFirst({ where: eq(channels.id, channelId) });
    if (!channel) throw new Error('CHANNEL_NOT_FOUND');
    await lockWorkspaceForAuthorization(tx, channel.workspaceId, 'share');
    if (
      !isVisibleChannelAuthorization(await getChannelAuthorizationFromStore(tx, userId, channelId))
    ) {
      throw new Error('CHANNEL_NOT_FOUND');
    }
    const limit = Math.min(Math.max(options?.limit ?? MESSAGES_PER_PAGE, 1), 100);
    let cursorCondition;
    if (options?.cursor) {
      const cursor = await tx.query.messages.findFirst({
        columns: { id: true, channelId: true, createdAt: true },
        where: and(eq(messages.id, options.cursor), eq(messages.channelId, channelId)),
      });
      if (!cursor) throw new Error('INVALID_CURSOR');
      cursorCondition = or(
        lt(messages.createdAt, cursor.createdAt),
        and(eq(messages.createdAt, cursor.createdAt), lt(messages.id, cursor.id)),
      );
    }

    const results = await tx.query.messages.findMany({
      where: cursorCondition
        ? and(eq(messages.channelId, channelId), cursorCondition)
        : eq(messages.channelId, channelId),
      orderBy: [desc(messages.createdAt), desc(messages.id)],
      limit: limit + 1,
      with: { author: { columns: messageAuthorColumns } },
    });
    const hasMore = results.length > limit;
    const data = results.slice(0, limit);
    return {
      data: await hydrateMessageEvents(tx, data),
      hasMore,
      cursor: hasMore ? data[data.length - 1]?.id : null,
    };
  });
}

export const messageAuthorColumns = {
  id: true,
  displayName: true,
  avatarUrl: true,
  status: true,
  createdAt: true,
} as const;

/** Attach pins, reactions and attachments to stored events (with author) for the wire. */
export async function hydrateMessageEvents(tx: any, data: any[]) {
  const baseMessageIds = data
    .filter((message) => message.type === 'message')
    .map((message) => message.id);
  const [pins, reactionRows] =
    baseMessageIds.length > 0
      ? await Promise.all([
          tx.query.messagePins.findMany({
            columns: { messageId: true },
            where: inArray(messagePins.messageId, baseMessageIds),
          }),
          tx.query.messageReactions.findMany({
            columns: {
              messageId: true,
              emoji: true,
              userId: true,
            },
            where: inArray(messageReactions.messageId, baseMessageIds),
            limit: baseMessageIds.length * MAX_REACTIONS_PER_MESSAGE + 1,
          }),
        ])
      : [[], []];
  if (reactionRows.length > baseMessageIds.length * MAX_REACTIONS_PER_MESSAGE) {
    throw new Error('REACTION_INVARIANT_EXCEEDED');
  }
  const pinnedMessageIds = new Set(pins.map((pin: { messageId: string }) => pin.messageId));
  const attachmentsByMessage = await getAttachmentsForMessages(
    baseMessageIds,
    tx as unknown as typeof db,
  );
  const reactionsByMessage = new Map<string, ReactionRow[]>();
  for (const reaction of reactionRows as ReactionRow[]) {
    const grouped = reactionsByMessage.get(reaction.messageId) || [];
    grouped.push(reaction);
    reactionsByMessage.set(reaction.messageId, grouped);
  }
  return data.map((message) => ({
    ...formatMessage(
      message,
      message.type === 'message'
        ? {
            isPinned: pinnedMessageIds.has(message.id),
            reactions: summarizeReactions(reactionsByMessage.get(message.id) || []),
          }
        : undefined,
    ),
    attachments: message.type === 'message' ? attachmentsByMessage.get(message.id) || [] : [],
  }));
}

export async function createMessage(
  channelId: string,
  authorId: string,
  input: CryptoEventInput,
  refMessageId?: string,
  mentionedUserIds: string[] = [],
  options: { tagIds?: string[] } = {},
) {
  const creatingPost = input.postId === null;
  return auditedTransaction(async (transaction) => {
    const authorization = await lockAndAuthorizeCryptoWrite(
      transaction,
      channelId,
      authorId,
      input,
      creatingPost ? Permissions.CREATE_POSTS : Permissions.SEND_MESSAGES,
      'message',
      refMessageId,
    );
    const isForum = authorization.channelType === 'forum';
    if (!isForum && options.tagIds?.length) throw new Error('INVALID_REFERENCE');
    if (creatingPost && refMessageId) throw new Error('INVALID_REFERENCE');
    const post = isForum && !creatingPost
      ? await lockOpenForumPost(transaction, input.postId!, channelId, authorization.permissions)
      : null;
    const reference = refMessageId
      ? await assertReferenceInChannel(transaction, refMessageId, channelId)
      : null;
    // A reply may quote the post itself or any reply inside the same post.
    if (post && reference && reference.id !== post.messageId && reference.postId !== post.messageId) {
      throw new Error('INVALID_REFERENCE');
    }
    const stored = await insertCryptoEvent(transaction, channelId, authorId, input, 'message', refMessageId);
    const forumPostId: string | null = isForum ? (creatingPost ? stored.event.id : post!.messageId) : null;
    if (forumPostId) {
      if (stored.isNewEvent) {
        const at = new Date(stored.event.createdAt);
        if (creatingPost) {
          await transaction.insert(forumPosts).values({
            messageId: forumPostId,
            channelId,
            authorId,
            createdAt: at,
            lastActivityAt: at,
          });
          await addForumPostTags(transaction, channelId, forumPostId, options.tagIds ?? []);
        } else {
          await transaction.update(forumPosts).set({
            lastActivityAt: sql`greatest(${forumPosts.lastActivityAt}, ${at})`,
            replyCount: sql`${forumPosts.replyCount} + 1`,
          }).where(eq(forumPosts.messageId, forumPostId));
        }
        // Writing to a post means its author has seen it up to this point.
        await transaction.insert(forumPostReads)
          .values({ userId: authorId, postId: forumPostId, lastReadActivityAt: at })
          .onConflictDoUpdate({
            target: [forumPostReads.userId, forumPostReads.postId],
            set: { lastReadActivityAt: sql`greatest(${forumPostReads.lastReadActivityAt}, ${at})` },
          });
      }
    }
    const attentionRecipients = stored.isNewEvent
      ? await resolveAttentionRecipients(
        transaction,
        channelId,
        authorization.workspaceId,
        authorId,
        input.broadcastMention,
        mentionedUserIds,
        // In a forum, a reply without a quote is a reply to the post.
        reference?.authorId ?? post?.authorId,
      )
      : [];
    const forumPost = forumPostId
      ? (await loadForumPostStates(transaction, [forumPostId]))[0] ?? null
      : null;
    return {
      ...stored,
      workspaceId: authorization.workspaceId,
      attentionRecipients,
      forumPost,
    };
  }, (result) => ({
    actorId: authorId,
    action: result.isNewEvent
      ? (creatingPost ? 'forum.post.create' : 'message.create')
      : (creatingPost ? 'forum.post.create.replay' : 'message.create.replay'),
    targetType: 'message',
    targetId: result.event.id,
    details: {
      workspaceId: result.workspaceId,
      channelId,
      reply: Boolean(refMessageId),
      ...(result.forumPost ? { postId: result.forumPost.postId } : {}),
    },
  }));
}

export async function editMessage(messageId: string, authorId: string, input: CryptoEventInput) {
  const location = await getOriginalMessage(messageId);
  return auditedTransaction(async (transaction) => {
    const authorization = await lockAndAuthorizeCryptoWrite(
      transaction,
      location.channelId,
      authorId,
      input,
      Permissions.EDIT_MESSAGES,
      'edit',
      messageId,
    );
    // Forum writes lock the post row before any message row (see deleteMessage).
    const post = authorization.channelType === 'forum'
      ? await lockForumPost(transaction, location.postId ?? location.id, location.channelId, 'share')
      : null;
    const original = await lockActiveBaseMessage(transaction, messageId, 'share');
    if (original.channelId !== location.channelId || original.authorId !== authorId || original.type !== 'message') {
      throw new Error('NOT_AUTHORIZED');
    }
    if (authorization.channelType === 'forum') {
      if (!post || input.postId !== (original.postId ?? original.id) || post.messageId !== input.postId) throw new Error('INVALID_REFERENCE');
      if (post.deletedAt) throw new Error('MESSAGE_NOT_FOUND');
    }
    const stored = await insertCryptoEvent(transaction, original.channelId, authorId, input, 'edit', messageId);
    return { ...stored, workspaceId: authorization.workspaceId };
  }, (result) => ({
    actorId: authorId,
    action: result.isNewEvent ? 'message.edit' : 'message.edit.replay',
    targetType: 'message',
    targetId: messageId,
    details: {
      workspaceId: result.workspaceId,
      channelId: location.channelId,
      eventId: result.event.id,
    },
  }));
}

export async function deleteMessage(messageId: string, userId: string, input: CryptoEventInput) {
  const deleteInput = { ...input, encryptedContent: '', contentNonce: '' };
  const location = await getOriginalMessage(messageId);
  return auditedTransaction(async (transaction) => {
    const authorization = await lockAndAuthorizeCryptoWrite(
      transaction,
      location.channelId,
      userId,
      deleteInput,
      Permissions.DELETE_MESSAGES,
      'delete',
      messageId,
    );
    // Take the post row before the message row, the same order a reply uses
    // (post, then the quoted message), so the two can never deadlock.
    const lockedPost = authorization.channelType === 'forum'
      ? await lockForumPost(transaction, location.postId ?? location.id, location.channelId, 'update')
      : null;
    const original = await lockBaseMessage(transaction, messageId, 'update');
    if (original.channelId !== location.channelId || original.type !== 'message') throw new Error('MESSAGE_NOT_FOUND');
    if (original.authorId !== userId && (authorization.permissions & Permissions.MANAGE_CHANNELS) !== Permissions.MANAGE_CHANNELS) {
      throw new Error('NOT_AUTHORIZED');
    }
    const forumPostId = authorization.channelType === 'forum' ? original.postId ?? original.id : null;
    if (forumPostId && (deleteInput.postId !== forumPostId || lockedPost?.messageId !== forumPostId)) {
      throw new Error('INVALID_REFERENCE');
    }
    const priorDelete = await findDeleteEvent(transaction, messageId);
    if (priorDelete) {
      const expectedKey = scopedIdempotencyKey(userId, deleteInput.idempotencyKey);
      if (priorDelete.idempotencyKey !== expectedKey) throw new Error('MESSAGE_NOT_FOUND');
    }
    const storedEvent = await insertCryptoEvent(transaction, original.channelId, userId, deleteInput, 'delete', messageId);
    let forumPost: ForumPostBroadcastState | null = null;
    let forumPostRemoved = false;
    if (forumPostId) {
      if (storedEvent.isNewEvent) {
        if (original.id === forumPostId) {
          await transaction.update(forumPosts).set({ deletedAt: new Date(storedEvent.event.createdAt) })
            .where(and(eq(forumPosts.messageId, forumPostId), isNull(forumPosts.deletedAt)));
        } else {
          await transaction.update(forumPosts).set({ replyCount: sql`greatest(${forumPosts.replyCount} - 1, 0)` })
            .where(eq(forumPosts.messageId, forumPostId));
        }
      }
      forumPostRemoved = original.id === forumPostId;
      // A reply deleted inside a deleted post changes nothing anyone lists:
      // its state would put the deleted post back into clients' lists.
      if (!forumPostRemoved && !lockedPost?.deletedAt) {
        forumPost = (await loadForumPostStates(transaction, [forumPostId]))[0] ?? null;
      }
    }
    return {
      messageId,
      channelId: original.channelId,
      workspaceId: authorization.workspaceId,
      event: storedEvent.event,
      isNewEvent: storedEvent.isNewEvent,
      forumPostId,
      forumPost,
      forumPostRemoved,
    };
  }, (result) => ({
    actorId: userId,
    action: result.isNewEvent ? 'message.delete' : 'message.delete.replay',
    targetType: 'message',
    targetId: messageId,
    details: {
      workspaceId: result.workspaceId,
      channelId: result.channelId,
      eventId: result.event.id,
    },
  }));
}

export async function toggleReaction(messageId: string, userId: string, emoji: string) {
  const committed = await auditedTransaction(async (transaction) => {
    const { original, workspaceId } = await lockAndAuthorizeMessageMutation(
      transaction,
      messageId,
      userId,
      Permissions.ADD_REACTIONS,
    );
    const existingReaction = await transaction.query.messageReactions.findFirst({
      where: and(
        eq(messageReactions.messageId, messageId),
        eq(messageReactions.userId, userId),
        eq(messageReactions.emoji, emoji),
      ),
    });
    const currentlyAdded = Boolean(existingReaction);
    const reactionAction = currentlyAdded ? 'remove' as const : 'add' as const;
    const action = currentlyAdded ? 'removed' as const : 'added' as const;
    if (currentlyAdded) {
      await transaction.delete(messageReactions).where(and(
        eq(messageReactions.messageId, messageId),
        eq(messageReactions.userId, userId),
        eq(messageReactions.emoji, emoji),
      ));
    } else {
      const [counts] = await transaction.select({
        totalReactionCount: sql<number>`count(*)::int`,
        distinctEmojiCount: sql<number>`count(distinct ${messageReactions.emoji})::int`,
        userReactionCount: sql<number>`count(*) filter (where ${messageReactions.userId} = ${userId})::int`,
        emojiExists: sql<boolean>`coalesce(bool_or(${messageReactions.emoji} = ${emoji}), false)`,
      }).from(messageReactions).where(eq(messageReactions.messageId, messageId));
      if (
        Number(counts?.totalReactionCount ?? 0) >= MAX_REACTIONS_PER_MESSAGE
        || Number(counts?.userReactionCount ?? 0) >= MAX_REACTIONS_PER_USER_PER_MESSAGE
        || (!counts?.emojiExists && Number(counts?.distinctEmojiCount ?? 0) >= MAX_REACTION_EMOJIS_PER_MESSAGE)
      ) throw new Error('REACTION_LIMIT_REACHED');
      await transaction.insert(messageReactions).values({ messageId, userId, emoji });
    }
    const currentReactions = await transaction.query.messageReactions.findMany({
      columns: {
        messageId: true,
        emoji: true,
        userId: true,
      },
      where: eq(messageReactions.messageId, messageId),
      limit: MAX_REACTIONS_PER_MESSAGE + 1,
    });
    if (currentReactions.length > MAX_REACTIONS_PER_MESSAGE) throw new Error('REACTION_INVARIANT_EXCEEDED');
    return {
      workspaceId,
      response: {
        messageId,
        channelId: original.channelId,
        userId,
        action,
        reactionAction,
        emoji,
        reactions: summarizeReactions(currentReactions),
      },
    };
  }, (result) => ({
    actorId: userId,
    action: `message.reaction.${result.response.reactionAction}`,
    targetType: 'message',
    targetId: messageId,
    details: {
      workspaceId: result.workspaceId,
      channelId: result.response.channelId,
    },
  }));
  return committed.response;
}

/**
 * Without `pinned` the pin is toggled. With it the pin is set to that value,
 * so repeating a request whose response was lost changes nothing.
 */
export async function pinMessage(messageId: string, userId: string, pinned?: boolean) {
  const committed = await auditedTransaction(async (transaction) => {
    const { original, workspaceId, channelType } = await lockAndAuthorizeMessageMutation(
      transaction,
      messageId,
      userId,
      Permissions.PIN_MESSAGES,
    );
    // In a forum, pinning keeps a whole post at the top of the list.
    if (channelType === 'forum' && original.postId !== null) throw new Error('NOT_AUTHORIZED');
    await transaction.execute(
      sql`select pg_advisory_xact_lock(hashtext(${`pins:${original.channelId}`})::bigint)`,
    );
    const existing = await transaction.query.messagePins.findFirst({
      where: and(eq(messagePins.messageId, messageId), eq(messagePins.channelId, original.channelId)),
    });
    const next = pinned ?? !existing;
    const changed = Boolean(existing) !== next;
    if (changed && existing) {
      await transaction.delete(messagePins).where(and(
        eq(messagePins.messageId, messageId),
        eq(messagePins.channelId, original.channelId),
      ));
    } else if (changed) {
      const currentPins = await transaction.query.messagePins.findMany({
        columns: { messageId: true },
        where: eq(messagePins.channelId, original.channelId),
        limit: MAX_PINS_PER_CHANNEL + 1,
      });
      if (currentPins.length >= MAX_PINS_PER_CHANNEL) throw new Error('PIN_LIMIT_REACHED');
      await transaction.insert(messagePins)
        .values({ channelId: original.channelId, messageId, pinnedBy: userId });
    }
    // A pinned forum post moves in every viewer's list. Its new state is read
    // in the same transaction, so a committed pin always comes with it.
    const forumPost: ForumPostBroadcastState | null = channelType === 'forum'
      ? (await loadForumPostStates(transaction, [messageId]))[0] ?? null
      : null;
    return {
      workspaceId,
      changed,
      forumPost,
      response: { messageId, channelId: original.channelId, userId, pinned: next },
    };
  }, (result) => ({
    actorId: userId,
    action: result.response.pinned ? 'message.pin.add' : 'message.pin.remove',
    targetType: 'message',
    targetId: messageId,
    details: {
      workspaceId: result.workspaceId,
      channelId: result.response.channelId,
      ...(result.changed ? {} : { changed: false }),
    },
  }));
  return { ...committed.response, forumPost: committed.forumPost };
}

export async function getPinnedMessages(channelId: string) {
  const rows = await db.query.messagePins.findMany({
    where: eq(messagePins.channelId, channelId),
    limit: MAX_PINS_PER_CHANNEL + 1,
  });
  if (rows.length > MAX_PINS_PER_CHANNEL) throw new Error('PIN_INVARIANT_EXCEEDED');
  return rows;
}

export async function updateReadPosition(userId: string, channelId: string, messageId: string) {
  return auditGuardedTransaction(async (transaction) => {
    const channel = await transaction.query.channels.findFirst({ where: eq(channels.id, channelId) });
    if (!channel) throw new Error('MESSAGE_NOT_FOUND');
    await lockWorkspaceForAuthorization(transaction, channel.workspaceId, 'share');
    const authorization = await getChannelAuthorizationFromStore(transaction, userId, channel);
    if (!isVisibleChannelAuthorization(authorization)) throw new Error('MESSAGE_NOT_FOUND');
    await transaction.execute(
      sql`select pg_advisory_xact_lock(hashtext(${`read:${userId}:${channelId}`})::bigint)`,
    );
    const message = await lockActiveBaseMessage(transaction, messageId, 'share');
    if (message.channelId !== channelId) throw new Error('MESSAGE_NOT_FOUND');
    const existing = await transaction.query.readPositions.findFirst({
      where: and(eq(readPositions.userId, userId), eq(readPositions.channelId, channelId)),
    });
    if (existing?.lastReadMessageId) {
      const previous = await transaction.query.messages.findFirst({
        columns: { id: true, createdAt: true },
        where: and(eq(messages.id, existing.lastReadMessageId), eq(messages.channelId, channelId)),
      });
      if (previous && (
        previous.createdAt > message.createdAt
        || (previous.createdAt.getTime() === message.createdAt.getTime() && previous.id >= message.id)
      )) {
        return formatReadPosition(existing);
      }
    }
    const updatedAt = new Date();
    const [position] = await transaction.insert(readPositions)
      .values({ userId, channelId, lastReadMessageId: messageId, updatedAt })
      .onConflictDoUpdate({
        target: [readPositions.userId, readPositions.channelId],
        set: { lastReadMessageId: messageId, updatedAt },
      })
      .returning();
    return formatReadPosition(position);
  });
}

function formatReadPosition(position: typeof readPositions.$inferSelect) {
  return {
    userId: position.userId,
    channelId: position.channelId,
    lastReadMessageId: position.lastReadMessageId,
    updatedAt: position.updatedAt.toISOString(),
  };
}

async function insertCryptoEvent(
  store: any,
  channelId: string,
  authorId: string,
  input: CryptoEventInput,
  type: CryptoEventType,
  refMessageId?: string,
) {
  const storedIdempotencyKey = scopedIdempotencyKey(authorId, input.idempotencyKey);
  // PostgreSQL timestamps may contain microseconds while JavaScript Date and
  // the wire format expose milliseconds. Persist millisecond precision so the
  // client and cursor can use the same deterministic (createdAt, id) order.
  const createdAt = new Date();
  const inserted = await store.insert(messages).values({
    channelId,
    authorId,
    deviceId: input.deviceId,
    content: input.encryptedContent,
    contentNonce: input.contentNonce,
    keyVersion: input.keyVersion,
    signature: input.signature,
    broadcastMention: input.broadcastMention,
    type,
    refMessageId: refMessageId || null,
    postId: input.postId ?? null,
    idempotencyKey: storedIdempotencyKey,
    createdAt,
  }).onConflictDoNothing().returning();

  const event = inserted[0] || await store.query.messages.findFirst({
    where: and(eq(messages.channelId, channelId), eq(messages.idempotencyKey, storedIdempotencyKey)),
  });
  if (!event || event.authorId !== authorId || !sameCryptoEvent(event, input, type, refMessageId)) {
    throw new Error('IDEMPOTENCY_CONFLICT');
  }
  return {
    event: formatMessage({ ...event, author: await getUserForMessage(event.authorId, store) }),
    isNewEvent: inserted.length > 0,
  };
}

function sameCryptoEvent(
  event: typeof messages.$inferSelect,
  input: CryptoEventInput,
  type: CryptoEventType,
  refMessageId?: string,
): boolean {
  return event.deviceId === input.deviceId
    && event.content === input.encryptedContent
    && event.contentNonce === input.contentNonce
    && event.keyVersion === input.keyVersion
    && event.signature === input.signature
    && event.broadcastMention === input.broadcastMention
    && event.type === type
    && event.refMessageId === (refMessageId || null)
    && event.postId === (input.postId ?? null);
}

async function lockAndAuthorizeCryptoWrite(
  store: any,
  channelId: string,
  userId: string,
  input: CryptoEventInput,
  permission: number,
  type: CryptoEventType,
  refMessageId?: string,
) {
  const channelLocation = await store.query.channels.findFirst({
    columns: { workspaceId: true },
    where: eq(channels.id, channelId),
  });
  if (!channelLocation) throw new Error('CHANNEL_NOT_FOUND');

  // Membership, role and group-commit changes take UPDATE on this workspace row.
  // Holding SHARE until the ciphertext event commits prevents authorization
  // from changing between validation and durable acknowledgement.
  await lockWorkspaceForAuthorization(store, channelLocation.workspaceId, 'share');

  // Revocation takes UPDATE on this row. PostgreSQL rechecks revoked_at after
  // a conflicting lock wait, so a revoked sender cannot pass a stale check.
  const [device] = await store.select()
    .from(devices)
    .where(and(eq(devices.id, input.deviceId), eq(devices.userId, userId), isNull(devices.revokedAt), isNotNull(devices.approvedAt)))
    .for('share');
  if (!device) throw new Error('INVALID_DEVICE');

  const channel = await store.query.channels.findFirst({
    where: eq(channels.id, channelId),
  });
  if (!channel || channel.workspaceId !== channelLocation.workspaceId) throw new Error('CHANNEL_NOT_FOUND');
  if (channel.type === 'voice') throw new Error('CHANNEL_NOT_FOUND');
  // Forum events must name their post (v4); no other channel may carry one.
  const isForum = channel.type === 'forum';
  if (isForum !== (input.postId !== undefined)) throw new Error('INVALID_REFERENCE');
  if (input.postId === null && type !== 'message') throw new Error('INVALID_REFERENCE');
  const authorization = await getChannelAuthorizationFromStore(store, userId, channel);
  if (!isVisibleChannelAuthorization(authorization)) throw new Error('CHANNEL_NOT_FOUND');
  if ((authorization.permissions & permission) !== permission) throw new Error('NOT_AUTHORIZED');
  if (
    input.broadcastMention
    && (authorization.permissions & Permissions.MENTION_EVERYONE) !== Permissions.MENTION_EVERYONE
  ) throw new Error('BROADCAST_MENTION_FORBIDDEN');
  await authorizeGroupWrite(store, {
    channel,
    userId,
    deviceId: input.deviceId,
    keyVersion: input.keyVersion,
  });
  const envelope: SignedMessageEnvelope = {
    channelId,
    authorId: userId,
    deviceId: input.deviceId,
    encryptedContent: input.encryptedContent,
    contentNonce: input.contentNonce,
    keyVersion: input.keyVersion,
    idempotencyKey: input.idempotencyKey,
    refMessageId: refMessageId || null,
    broadcastMention: input.broadcastMention,
    ...(isForum ? { postId: input.postId } : {}),
    type,
  };
  if (!verifyMessageEnvelopeSignature(device.identityKey, envelope, input.signature)) {
    throw new Error('INVALID_SIGNATURE');
  }
  return { ...authorization, channelType: channel.type as string };
}

/**
 * Lock a post for a new reply. Locked posts accept replies only from members
 * who can manage the channel, so moderators can still explain the lock.
 */
async function lockOpenForumPost(store: any, postId: string, channelId: string, permissions: number) {
  const post = await lockForumPost(store, postId, channelId, 'update');
  if (!post || post.deletedAt) throw new Error('INVALID_REFERENCE');
  if (post.lockedAt && (permissions & Permissions.MANAGE_CHANNELS) !== Permissions.MANAGE_CHANNELS) {
    throw new Error('FORUM_POST_LOCKED');
  }
  return post;
}

async function assertReferenceInChannel(store: any, messageId: string, channelId: string) {
  try {
    const reference = await lockActiveBaseMessage(store, messageId, 'share');
    if (reference.channelId !== channelId) throw new Error('INVALID_REFERENCE');
    return reference;
  } catch (error: any) {
    if (error?.message === 'MESSAGE_NOT_FOUND') throw new Error('INVALID_REFERENCE');
    throw error;
  }
}

async function resolveAttentionRecipients(
  store: any,
  channelId: string,
  workspaceId: string,
  authorId: string,
  broadcastMention: boolean,
  mentionedUserIds: string[],
  replyAuthorId?: string,
): Promise<Array<{ userId: string; workspaceId: string; kind: AttentionNotificationKind }>> {
  if (!broadcastMention && mentionedUserIds.length === 0 && !replyAuthorId) return [];
  const channel = await store.query.channels.findFirst({ where: eq(channels.id, channelId) });
  if (!channel || channel.workspaceId !== workspaceId) return [];
  return buildAttentionRecipients(
    await getChannelViewerIdsFromStore(store, channel),
    workspaceId,
    authorId,
    broadcastMention,
    mentionedUserIds,
    replyAuthorId,
  );
}

export function buildAttentionRecipients(
  viewerIds: string[],
  workspaceId: string,
  authorId: string,
  broadcastMention: boolean,
  mentionedUserIds: string[],
  replyAuthorId?: string,
): Array<{ userId: string; workspaceId: string; kind: AttentionNotificationKind }> {
  const viewers = new Set(viewerIds);
  const byUser = new Map<string, Set<AttentionNotificationKind>>();
  const add = (userId: string | undefined, kind: AttentionNotificationKind) => {
    if (!userId || userId === authorId || !viewers.has(userId)) return;
    const kinds = byUser.get(userId) || new Set<AttentionNotificationKind>();
    kinds.add(kind);
    byUser.set(userId, kinds);
  };
  if (broadcastMention) {
    for (const userId of viewers) add(userId, 'mention');
  }
  for (const userId of mentionedUserIds.slice(0, MAX_DIRECT_MENTION_RECIPIENTS_PER_MESSAGE)) {
    add(userId, 'mention');
  }
  add(replyAuthorId, 'reply');
  return [...byUser.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .flatMap(([userId, kinds]) => [...kinds].sort().map((kind) => ({ userId, workspaceId, kind })));
}

async function getOriginalMessage(messageId: string, store: any = db) {
  const original = await store.query.messages.findFirst({ where: eq(messages.id, messageId) });
  if (!original) throw new Error('MESSAGE_NOT_FOUND');
  return original;
}

/**
 * Serialize a stateful message mutation with membership and role changes.
 * Workspace management takes UPDATE on the workspace row, so a SHARE lock
 * keeps the authorization decision valid until this transaction commits.
 */
async function lockAndAuthorizeMessageMutation(
  store: any,
  messageId: string,
  userId: string,
  permission: number,
) {
  const location = await store.query.messages.findFirst({
    columns: { channelId: true },
    where: eq(messages.id, messageId),
  });
  if (!location) throw new Error('MESSAGE_NOT_FOUND');
  const channelLocation = await store.query.channels.findFirst({
    columns: { workspaceId: true },
    where: eq(channels.id, location.channelId),
  });
  if (!channelLocation) throw new Error('MESSAGE_NOT_FOUND');
  await lockWorkspaceForAuthorization(store, channelLocation.workspaceId, 'share');
  const original = await lockActiveBaseMessage(store, messageId, 'update');
  if (original.channelId !== location.channelId) throw new Error('MESSAGE_NOT_FOUND');
  const channel = await store.query.channels.findFirst({ where: eq(channels.id, original.channelId) });
  if (!channel || channel.workspaceId !== channelLocation.workspaceId) throw new Error('MESSAGE_NOT_FOUND');
  const authorization = await getChannelAuthorizationFromStore(store, userId, channel);
  if (!isVisibleChannelAuthorization(authorization)) throw new Error('MESSAGE_NOT_FOUND');
  if ((authorization.permissions & permission) !== permission) throw new Error('NOT_AUTHORIZED');
  return { original, workspaceId: channelLocation.workspaceId, channelType: channel.type as string };
}

async function getUserForMessage(userId: string, store: any = db) {
  const user = await store.query.users.findFirst({
    columns: {
      id: true,
      displayName: true,
      avatarUrl: true,
      status: true,
      createdAt: true,
    },
    where: eq(users.id, userId),
  });
  if (!user) return { id: userId, displayName: 'Unknown', avatarUrl: null, status: 'offline', createdAt: new Date(0).toISOString() };
  return {
    id: user.id,
    displayName: user.displayName,
    avatarUrl: user.avatarUrl,
    status: user.status,
    createdAt: user.createdAt.toISOString(),
  };
}

function formatMessage(message: any, state?: { reactions: ReturnType<typeof summarizeReactions>; isPinned: boolean }) {
  const idempotencyKey = signedIdempotencyKey(message);
  return {
    id: message.id,
    channelId: message.channelId,
    authorId: message.authorId,
    author: message.author ? formatMessageAuthor(message.author) : undefined,
    deviceId: message.deviceId,
    content: '',
    encryptedContent: message.content,
    contentNonce: message.contentNonce,
    keyVersion: message.keyVersion,
    signature: message.signature,
    broadcastMention: message.broadcastMention ?? null,
    type: message.type,
    reactionAction: message.reactionAction ?? null,
    refMessageId: message.refMessageId,
    postId: message.postId ?? null,
    reactions: state?.reactions || [],
    isPinned: state?.isPinned || false,
    idempotencyKey,
    createdAt: message.createdAt.toISOString(),
  };
}

function summarizeReactions(reactions: ReactionRow[]) {
  const grouped = new Map<string, Set<string>>();
  for (const reaction of reactions) {
    const userIds = grouped.get(reaction.emoji) || new Set<string>();
    userIds.add(reaction.userId);
    grouped.set(reaction.emoji, userIds);
  }
  return [...grouped.entries()]
    .map(([emoji, userIds]) => {
      const sortedUserIds = [...userIds].sort();
      return { emoji, count: sortedUserIds.length, userIds: sortedUserIds };
    })
    .sort((left, right) => left.emoji < right.emoji ? -1 : left.emoji > right.emoji ? 1 : 0);
}

export async function lockActiveBaseMessage(
  store: any,
  messageId: string,
  lock: 'share' | 'update' = 'share',
) {
  const [original] = await store.select()
    .from(messages)
    .where(eq(messages.id, messageId))
    .for(lock);
  if (!original || original.type !== 'message') throw new Error('MESSAGE_NOT_FOUND');
  if (await findDeleteEvent(store, messageId)) throw new Error('MESSAGE_NOT_FOUND');
  return original;
}

async function lockBaseMessage(store: any, messageId: string, lock: 'share' | 'update') {
  const [original] = await store.select().from(messages).where(eq(messages.id, messageId)).for(lock);
  if (!original || original.type !== 'message') throw new Error('MESSAGE_NOT_FOUND');
  return original;
}

async function findDeleteEvent(store: any, messageId: string) {
  return store.query.messages.findFirst({
    where: and(eq(messages.refMessageId, messageId), eq(messages.type, 'delete')),
    orderBy: [desc(messages.createdAt), desc(messages.id)],
  });
}

function formatMessageAuthor(author: {
  id: string;
  displayName: string;
  avatarUrl: string | null;
  status: string;
  createdAt: Date | string;
}) {
  return {
    id: author.id,
    displayName: author.displayName,
    avatarUrl: author.avatarUrl,
    status: author.status,
    createdAt: author.createdAt instanceof Date ? author.createdAt.toISOString() : author.createdAt,
  };
}
