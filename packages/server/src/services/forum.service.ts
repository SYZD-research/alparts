import { and, asc, desc, eq, inArray, isNull, lt, ne, or, sql } from 'drizzle-orm';
import {
  FORUM_POSTS_PER_PAGE,
  MAX_FORUM_TAGS_PER_CHANNEL,
  MESSAGES_PER_PAGE,
  Permissions,
  type ForumPostSummary,
  type ForumTag,
  type ForumViewerCapabilities,
} from '@alparts/shared';
import { db } from '../db/index.js';
import {
  channels,
  forumPostReads,
  forumPostTags,
  forumPosts,
  forumTags,
  messagePins,
  messages,
} from '../db/schema.js';
import { auditedTransaction, auditGuardedTransaction } from '../middleware/audit.js';
import {
  getChannelAuthorizationFromStore,
  isVisibleChannelAuthorization,
  lockWorkspaceForAuthorization,
  type ChannelAuthorization,
} from './authorization.service.js';
import { hydrateMessageEvents, messageAuthorColumns } from './message.service.js';
import {
  assertForumTagIds,
  formatForumPostStates,
  lockForumPost,
  type ForumPostBroadcastState,
} from './forum-state.js';

type ForumPostRow = typeof forumPosts.$inferSelect;
type ForumChannel = typeof channels.$inferSelect;

export interface ForumPostListOptions {
  sort?: 'activity' | 'created';
  tagId?: string;
  cursor?: string;
  limit?: number;
}

// === Reading ===

export async function listForumPosts(channelId: string, userId: string, options: ForumPostListOptions = {}) {
  return db.transaction(async (tx) => {
    const { authorization } = await authorizeForumChannel(tx, channelId, userId);
    const limit = Math.min(Math.max(options.limit ?? FORUM_POSTS_PER_PAGE, 1), 50);
    const sortColumn = options.sort === 'created' ? forumPosts.createdAt : forumPosts.lastActivityAt;
    const pinned = sql<number>`(case when ${messagePins.messageId} is null then 0 else 1 end)`;
    const pinJoin = and(eq(messagePins.messageId, forumPosts.messageId), eq(messagePins.channelId, forumPosts.channelId));

    // Pinned posts first, then newest first; (pinned, time, id) is a strict
    // total order, so the cursor post fixes an exact position.
    let cursorCondition;
    if (options.cursor) {
      const [cursor] = await tx.select({ pinned, sortAt: sortColumn })
        .from(forumPosts)
        .leftJoin(messagePins, pinJoin)
        .where(and(eq(forumPosts.messageId, options.cursor), eq(forumPosts.channelId, channelId)));
      if (!cursor) throw new Error('INVALID_CURSOR');
      cursorCondition = sql`(${pinned}, ${sortColumn}, ${forumPosts.messageId}) < (${Number(cursor.pinned)}::int, ${cursor.sortAt}::timestamptz, ${options.cursor}::uuid)`;
    }
    const tagCondition = options.tagId
      ? sql`exists (select 1 from ${forumPostTags} where ${forumPostTags.postId} = ${forumPosts.messageId} and ${forumPostTags.channelId} = ${forumPosts.channelId} and ${forumPostTags.tagId} = ${options.tagId}::uuid)`
      : undefined;
    const rows = await tx.select({ post: forumPosts, lastReadActivityAt: forumPostReads.lastReadActivityAt })
      .from(forumPosts)
      .leftJoin(messagePins, pinJoin)
      .leftJoin(forumPostReads, and(eq(forumPostReads.postId, forumPosts.messageId), eq(forumPostReads.userId, userId)))
      .where(and(eq(forumPosts.channelId, channelId), isNull(forumPosts.deletedAt), tagCondition, cursorCondition))
      .orderBy(desc(pinned), desc(sortColumn), desc(forumPosts.messageId))
      .limit(limit + 1);
    const hasMore = rows.length > limit;
    const page = rows.slice(0, limit);
    return {
      data: await buildPostSummaries(tx, page, userId),
      hasMore,
      cursor: hasMore ? page[page.length - 1]!.post.messageId : null,
      viewer: viewerCapabilities(authorization),
    };
  });
}

export async function getForumPost(postId: string, userId: string): Promise<ForumPostSummary> {
  return db.transaction(async (tx) => {
    await authorizeForumPost(tx, postId, userId);
    const [row] = await tx.select({ post: forumPosts, lastReadActivityAt: forumPostReads.lastReadActivityAt })
      .from(forumPosts)
      .leftJoin(forumPostReads, and(eq(forumPostReads.postId, forumPosts.messageId), eq(forumPostReads.userId, userId)))
      .where(and(eq(forumPosts.messageId, postId), isNull(forumPosts.deletedAt)));
    if (!row) throw new Error('FORUM_POST_NOT_FOUND');
    const [summary] = await buildPostSummaries(tx, [row], userId);
    if (!summary) throw new Error('FORUM_POST_NOT_FOUND');
    return summary;
  });
}

/** Events inside one post (replies and every edit/delete, including the post's own), newest first. */
export async function getForumPostMessages(
  postId: string,
  userId: string,
  options: { cursor?: string; limit?: number } = {},
) {
  return db.transaction(async (tx) => {
    const { post } = await authorizeForumPost(tx, postId, userId);
    if (post.deletedAt) throw new Error('FORUM_POST_NOT_FOUND');
    const limit = Math.min(Math.max(options.limit ?? MESSAGES_PER_PAGE, 1), 100);
    let cursorCondition;
    if (options.cursor) {
      const cursor = await tx.query.messages.findFirst({
        columns: { id: true, createdAt: true },
        where: and(eq(messages.id, options.cursor), eq(messages.postId, postId)),
      });
      if (!cursor) throw new Error('INVALID_CURSOR');
      cursorCondition = or(
        lt(messages.createdAt, cursor.createdAt),
        and(eq(messages.createdAt, cursor.createdAt), lt(messages.id, cursor.id)),
      );
    }
    const results = await tx.query.messages.findMany({
      where: and(eq(messages.postId, postId), eq(messages.channelId, post.channelId), cursorCondition),
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

export async function markForumPostRead(postId: string, userId: string) {
  return auditGuardedTransaction(async (tx) => {
    const { post } = await authorizeForumPost(tx, postId, userId);
    if (post.deletedAt) throw new Error('FORUM_POST_NOT_FOUND');
    // The server's own activity time is recorded, never a client clock.
    const [read] = await tx.insert(forumPostReads)
      .values({ userId, postId, lastReadActivityAt: post.lastActivityAt })
      .onConflictDoUpdate({
        target: [forumPostReads.userId, forumPostReads.postId],
        set: { lastReadActivityAt: sql`greatest(${forumPostReads.lastReadActivityAt}, excluded.last_read_activity_at)` },
      })
      .returning();
    return {
      channelId: post.channelId,
      postId,
      lastReadActivityAt: read!.lastReadActivityAt.toISOString(),
    };
  });
}

// === Post moderation ===

export async function setForumPostLocked(postId: string, actorId: string, locked: boolean) {
  return auditedTransaction(async (tx) => {
    const { channel, authorization } = await authorizeForumPost(tx, postId, actorId, 'update');
    if (!canManage(authorization)) throw new Error('NOT_AUTHORIZED');
    const post = await lockLivePost(tx, postId, channel.id);
    const changed = (post.lockedAt !== null) !== locked;
    if (changed) {
      await tx.update(forumPosts)
        .set(locked ? { lockedAt: new Date(), lockedBy: actorId } : { lockedAt: null, lockedBy: null })
        .where(eq(forumPosts.messageId, postId));
    }
    return { workspaceId: channel.workspaceId, channelId: channel.id, changed, state: await postState(tx, postId) };
  }, (result) => ({
    actorId,
    action: locked ? 'forum.post.lock' : 'forum.post.unlock',
    targetType: 'message',
    targetId: postId,
    details: { workspaceId: result.workspaceId, channelId: result.channelId, changed: result.changed },
  }));
}

export async function setForumPostResolved(postId: string, actorId: string, resolved: boolean) {
  return auditedTransaction(async (tx) => {
    const { channel, authorization } = await authorizeForumPost(tx, postId, actorId, 'update');
    const post = await lockLivePost(tx, postId, channel.id);
    if (post.authorId !== actorId && !canManage(authorization)) throw new Error('NOT_AUTHORIZED');
    const changed = (post.resolvedAt !== null) !== resolved;
    if (changed) {
      await tx.update(forumPosts)
        .set(resolved ? { resolvedAt: new Date(), resolvedBy: actorId } : { resolvedAt: null, resolvedBy: null })
        .where(eq(forumPosts.messageId, postId));
    }
    return { workspaceId: channel.workspaceId, channelId: channel.id, changed, state: await postState(tx, postId) };
  }, (result) => ({
    actorId,
    action: resolved ? 'forum.post.resolve' : 'forum.post.unresolve',
    targetType: 'message',
    targetId: postId,
    details: { workspaceId: result.workspaceId, channelId: result.channelId, changed: result.changed },
  }));
}

export async function setForumPostTags(postId: string, actorId: string, tagIds: string[]) {
  return auditedTransaction(async (tx) => {
    const { channel, authorization } = await authorizeForumPost(tx, postId, actorId, 'update');
    const post = await lockLivePost(tx, postId, channel.id);
    if (post.authorId !== actorId && !canManage(authorization)) throw new Error('NOT_AUTHORIZED');
    await assertForumTagIds(tx, channel.id, tagIds);
    await tx.delete(forumPostTags).where(eq(forumPostTags.postId, postId));
    if (tagIds.length > 0) {
      await tx.insert(forumPostTags).values(tagIds.map((tagId) => ({ postId, channelId: channel.id, tagId })));
    }
    return { workspaceId: channel.workspaceId, channelId: channel.id, state: await postState(tx, postId) };
  }, (result) => ({
    actorId,
    action: 'forum.post.tags',
    targetType: 'message',
    targetId: postId,
    details: { workspaceId: result.workspaceId, channelId: result.channelId, tagIds: result.state.tagIds },
  }));
}

// === Tags ===

export async function listForumTags(channelId: string, userId: string): Promise<ForumTag[]> {
  return db.transaction(async (tx) => {
    await authorizeForumChannel(tx, channelId, userId);
    return loadTags(tx, channelId);
  });
}

export async function createForumTag(channelId: string, actorId: string, name: string, position?: number) {
  return auditedTransaction(async (tx) => {
    const { channel } = await authorizeForumManager(tx, channelId, actorId);
    await lockTags(tx, channelId);
    const existing = await tx.select({ id: forumTags.id, name: forumTags.name })
      .from(forumTags)
      .where(eq(forumTags.channelId, channelId))
      .limit(MAX_FORUM_TAGS_PER_CHANNEL + 1);
    if (existing.length >= MAX_FORUM_TAGS_PER_CHANNEL) throw new Error('FORUM_TAG_LIMIT_REACHED');
    if (existing.some((tag: { name: string }) => tag.name === name)) throw new Error('FORUM_TAG_EXISTS');
    const [created] = await tx.insert(forumTags)
      .values({ channelId, name, position: position ?? existing.length })
      .returning();
    return { workspaceId: channel.workspaceId, tag: formatTag(created!), tags: await loadTags(tx, channelId) };
  }, (result) => ({
    actorId,
    action: 'forum.tag.create',
    targetType: 'channel',
    targetId: channelId,
    details: { workspaceId: result.workspaceId, tagId: result.tag.id, name: result.tag.name },
  }));
}

export async function updateForumTag(tagId: string, actorId: string, updates: { name?: string; position?: number }) {
  const location = await db.query.forumTags.findFirst({ columns: { channelId: true }, where: eq(forumTags.id, tagId) });
  if (!location) throw new Error('FORUM_TAG_NOT_FOUND');
  return auditedTransaction(async (tx) => {
    const { channel } = await authorizeForumManager(tx, location.channelId, actorId, 'FORUM_TAG_NOT_FOUND');
    await lockTags(tx, channel.id);
    const tag = await tx.query.forumTags.findFirst({
      where: and(eq(forumTags.id, tagId), eq(forumTags.channelId, channel.id)),
    });
    if (!tag) throw new Error('FORUM_TAG_NOT_FOUND');
    if (updates.name !== undefined && updates.name !== tag.name) {
      const clash = await tx.query.forumTags.findFirst({
        columns: { id: true },
        where: and(eq(forumTags.channelId, channel.id), eq(forumTags.name, updates.name), ne(forumTags.id, tagId)),
      });
      if (clash) throw new Error('FORUM_TAG_EXISTS');
    }
    const [updated] = await tx.update(forumTags).set(updates).where(eq(forumTags.id, tagId)).returning();
    return {
      workspaceId: channel.workspaceId,
      channelId: channel.id,
      before: formatTag(tag),
      tag: formatTag(updated!),
      tags: await loadTags(tx, channel.id),
    };
  }, (result) => ({
    actorId,
    action: 'forum.tag.update',
    targetType: 'channel',
    targetId: result.channelId,
    details: {
      workspaceId: result.workspaceId,
      tagId,
      before: { name: result.before.name, position: result.before.position },
      after: { name: result.tag.name, position: result.tag.position },
    },
  }));
}

export async function deleteForumTag(tagId: string, actorId: string) {
  const location = await db.query.forumTags.findFirst({ columns: { channelId: true }, where: eq(forumTags.id, tagId) });
  if (!location) throw new Error('FORUM_TAG_NOT_FOUND');
  return auditedTransaction(async (tx) => {
    const { channel } = await authorizeForumManager(tx, location.channelId, actorId, 'FORUM_TAG_NOT_FOUND');
    await lockTags(tx, channel.id);
    // Post-tag links go with the tag (ON DELETE CASCADE); report which posts changed.
    const affected = await tx.select({ postId: forumPostTags.postId })
      .from(forumPostTags)
      .where(and(eq(forumPostTags.channelId, channel.id), eq(forumPostTags.tagId, tagId)));
    const [removed] = await tx.delete(forumTags)
      .where(and(eq(forumTags.id, tagId), eq(forumTags.channelId, channel.id)))
      .returning();
    if (!removed) throw new Error('FORUM_TAG_NOT_FOUND');
    return {
      workspaceId: channel.workspaceId,
      channelId: channel.id,
      name: removed.name,
      affectedPostCount: affected.length,
      tags: await loadTags(tx, channel.id),
    };
  }, (result) => ({
    actorId,
    action: 'forum.tag.delete',
    targetType: 'channel',
    targetId: result.channelId,
    details: {
      workspaceId: result.workspaceId,
      tagId,
      name: result.name,
      affectedPostCount: result.affectedPostCount,
    },
  }));
}

// === Helpers ===

async function authorizeForumChannel(
  store: any,
  channelId: string,
  userId: string,
): Promise<{ channel: ForumChannel; authorization: ChannelAuthorization }> {
  const location = await store.query.channels.findFirst({
    columns: { workspaceId: true },
    where: eq(channels.id, channelId),
  });
  if (!location) throw new Error('CHANNEL_NOT_FOUND');
  // Membership, role, override and channel changes (privacy, category) take
  // UPDATE on the workspace row. Read the channel only after SHARE is held, so
  // the decision uses the committed row it stays valid against until commit.
  await lockWorkspaceForAuthorization(store, location.workspaceId, 'share');
  const channel = await store.query.channels.findFirst({ where: eq(channels.id, channelId) });
  if (!channel || channel.workspaceId !== location.workspaceId) throw new Error('CHANNEL_NOT_FOUND');
  const authorization = await getChannelAuthorizationFromStore(store, userId, channel);
  if (!isVisibleChannelAuthorization(authorization) || channel.type !== 'forum') throw new Error('CHANNEL_NOT_FOUND');
  return { channel, authorization };
}

async function authorizeForumManager(store: any, channelId: string, actorId: string, notFound = 'CHANNEL_NOT_FOUND') {
  let context;
  try {
    context = await authorizeForumChannel(store, channelId, actorId);
  } catch (error: any) {
    if (error?.message === 'CHANNEL_NOT_FOUND') throw new Error(notFound);
    throw error;
  }
  if (!canManage(context.authorization)) throw new Error('NOT_AUTHORIZED');
  return context;
}

/** Posts are reachable only through a channel the viewer can see; otherwise they do not exist. */
async function authorizeForumPost(store: any, postId: string, userId: string, lock: 'share' | 'update' = 'share') {
  const location = await store.query.forumPosts.findFirst({
    columns: { channelId: true },
    where: eq(forumPosts.messageId, postId),
  });
  if (!location) throw new Error('FORUM_POST_NOT_FOUND');
  let context;
  try {
    context = await authorizeForumChannel(store, location.channelId, userId);
  } catch (error: any) {
    if (error?.message === 'CHANNEL_NOT_FOUND') throw new Error('FORUM_POST_NOT_FOUND');
    throw error;
  }
  const post = await lockForumPost(store, postId, context.channel.id, lock);
  if (!post) throw new Error('FORUM_POST_NOT_FOUND');
  return { ...context, post };
}

async function lockLivePost(store: any, postId: string, channelId: string): Promise<ForumPostRow> {
  const post = await lockForumPost(store, postId, channelId, 'update');
  if (!post || post.deletedAt) throw new Error('FORUM_POST_NOT_FOUND');
  return post;
}

function viewerCapabilities(authorization: ChannelAuthorization): ForumViewerCapabilities {
  const has = (permission: number) => (authorization.permissions & permission) === permission;
  return {
    canCreatePosts: has(Permissions.CREATE_POSTS),
    canReply: has(Permissions.SEND_MESSAGES),
    canManage: has(Permissions.MANAGE_CHANNELS),
    canPin: has(Permissions.PIN_MESSAGES),
    canAttach: has(Permissions.ATTACH_FILES),
  };
}

function canManage(authorization: ChannelAuthorization): boolean {
  return (authorization.permissions & Permissions.MANAGE_CHANNELS) === Permissions.MANAGE_CHANNELS;
}

async function postState(store: any, postId: string): Promise<ForumPostBroadcastState> {
  const [row] = await store.select().from(forumPosts).where(eq(forumPosts.messageId, postId));
  const [state] = await formatForumPostStates(store, row ? [row] : []);
  if (!state) throw new Error('FORUM_POST_NOT_FOUND');
  return state;
}

async function buildPostSummaries(
  store: any,
  rows: Array<{ post: ForumPostRow; lastReadActivityAt: Date | null }>,
  userId: string,
): Promise<ForumPostSummary[]> {
  if (rows.length === 0) return [];
  const postIds = rows.map((row) => row.post.messageId);
  const states = await formatForumPostStates(store, rows.map((row) => row.post));
  const rootRows = await store.query.messages.findMany({
    where: inArray(messages.id, postIds),
    with: { author: { columns: messageAuthorColumns } },
  });
  // The current title is in the post's most recent edit, if any. Clients
  // verify that the edit is signed by the post author before applying it.
  const latestEditIds = await store.selectDistinctOn([messages.refMessageId], { id: messages.id })
    .from(messages)
    .where(and(inArray(messages.refMessageId, postIds), eq(messages.type, 'edit'), inArray(messages.postId, postIds)))
    .orderBy(messages.refMessageId, desc(messages.createdAt), desc(messages.id));
  const editRows = latestEditIds.length === 0 ? [] : await store.query.messages.findMany({
    where: inArray(messages.id, latestEditIds.map((row: { id: string }) => row.id)),
    with: { author: { columns: messageAuthorColumns } },
  });
  const [roots, edits] = await Promise.all([
    hydrateMessageEvents(store, rootRows),
    hydrateMessageEvents(store, editRows),
  ]);
  const rootById = new Map(roots.map((root) => [root.id, root]));
  const editByPost = new Map(edits.map((edit) => [edit.refMessageId, edit]));
  const lastReadByPost = new Map(rows.map((row) => [row.post.messageId, row.lastReadActivityAt]));
  return states.flatMap((state) => {
    const root = rootById.get(state.postId);
    if (!root) return [];
    const lastRead = lastReadByPost.get(state.postId) ?? null;
    return [{
      root,
      latestEdit: editByPost.get(state.postId) ?? null,
      state: {
        ...state,
        unread: lastRead ? new Date(state.lastActivityAt) > lastRead : state.authorId !== userId,
      },
    } as ForumPostSummary];
  });
}

async function lockTags(store: any, channelId: string): Promise<void> {
  await store.execute(sql`select pg_advisory_xact_lock(hashtext(${`forum-tags:${channelId}`})::bigint)`);
}

async function loadTags(store: any, channelId: string): Promise<ForumTag[]> {
  const rows = await store.select().from(forumTags)
    .where(eq(forumTags.channelId, channelId))
    .orderBy(asc(forumTags.position), asc(forumTags.id))
    .limit(MAX_FORUM_TAGS_PER_CHANNEL + 1);
  if (rows.length > MAX_FORUM_TAGS_PER_CHANNEL) throw new Error('FORUM_TAG_INVARIANT_EXCEEDED');
  return rows.map(formatTag);
}

function formatTag(tag: typeof forumTags.$inferSelect): ForumTag {
  return { id: tag.id, channelId: tag.channelId, name: tag.name, position: tag.position };
}
