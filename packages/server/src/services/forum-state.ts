import { and, asc, eq, inArray } from 'drizzle-orm';
import { MAX_FORUM_TAGS_PER_POST, type ForumPostState } from '@alparts/shared';
import { forumPostTags, forumPosts, forumTags, messagePins } from '../db/schema.js';

/** Post state shared with every viewer; the per-viewer unread flag is added separately. */
export type ForumPostBroadcastState = Omit<ForumPostState, 'unread'>;

type ForumPostRow = typeof forumPosts.$inferSelect;

/** Lock one post row of this channel. Returns null when it does not exist there. */
export async function lockForumPost(
  store: any,
  postId: string,
  channelId: string,
  lock: 'share' | 'update',
): Promise<ForumPostRow | null> {
  const [post] = await store.select()
    .from(forumPosts)
    .where(and(eq(forumPosts.messageId, postId), eq(forumPosts.channelId, channelId)))
    .for(lock);
  return post ?? null;
}

export async function loadForumPostStates(store: any, postIds: string[]): Promise<ForumPostBroadcastState[]> {
  if (postIds.length === 0) return [];
  const rows: ForumPostRow[] = await store.select().from(forumPosts).where(inArray(forumPosts.messageId, postIds));
  return formatForumPostStates(store, rows);
}

export async function formatForumPostStates(
  store: any,
  rows: ForumPostRow[],
): Promise<ForumPostBroadcastState[]> {
  if (rows.length === 0) return [];
  const postIds = rows.map((row) => row.messageId);
  const [tagRows, pinRows] = await Promise.all([
    store.select({ postId: forumPostTags.postId, tagId: forumPostTags.tagId })
      .from(forumPostTags)
      .innerJoin(forumTags, and(eq(forumTags.id, forumPostTags.tagId), eq(forumTags.channelId, forumPostTags.channelId)))
      .where(inArray(forumPostTags.postId, postIds))
      .orderBy(asc(forumTags.position), asc(forumTags.id))
      .limit(postIds.length * MAX_FORUM_TAGS_PER_POST + 1),
    store.select({ messageId: messagePins.messageId })
      .from(messagePins)
      .where(inArray(messagePins.messageId, postIds)),
  ]);
  if (tagRows.length > postIds.length * MAX_FORUM_TAGS_PER_POST) throw new Error('FORUM_TAG_INVARIANT_EXCEEDED');
  const tagsByPost = new Map<string, string[]>();
  for (const row of tagRows as Array<{ postId: string; tagId: string }>) {
    tagsByPost.set(row.postId, [...(tagsByPost.get(row.postId) ?? []), row.tagId]);
  }
  const pinned = new Set((pinRows as Array<{ messageId: string }>).map((row) => row.messageId));
  const byId = new Map(rows.map((row) => [row.messageId, row]));
  return postIds.flatMap((postId) => {
    const row = byId.get(postId);
    return row ? [{
      postId: row.messageId,
      channelId: row.channelId,
      authorId: row.authorId,
      createdAt: row.createdAt.toISOString(),
      lastActivityAt: row.lastActivityAt.toISOString(),
      replyCount: row.replyCount,
      locked: row.lockedAt !== null,
      resolved: row.resolvedAt !== null,
      tagIds: tagsByPost.get(postId) ?? [],
      isPinned: pinned.has(postId),
    }] : [];
  });
}

/**
 * Add tags to a new post; the caller holds the post row lock. Tag ids must
 * name distinct tags of this channel; the composite foreign keys enforce the
 * channel boundary again in the database.
 */
export async function addForumPostTags(store: any, channelId: string, postId: string, tagIds: string[]): Promise<void> {
  await assertForumTagIds(store, channelId, tagIds);
  if (tagIds.length === 0) return;
  await store.insert(forumPostTags).values(tagIds.map((tagId) => ({ postId, channelId, tagId })));
}

export async function assertForumTagIds(store: any, channelId: string, tagIds: string[]): Promise<void> {
  if (tagIds.length > MAX_FORUM_TAGS_PER_POST || new Set(tagIds).size !== tagIds.length) {
    throw new Error('INVALID_FORUM_TAGS');
  }
  if (tagIds.length === 0) return;
  const found = await store.select({ id: forumTags.id })
    .from(forumTags)
    .where(and(eq(forumTags.channelId, channelId), inArray(forumTags.id, tagIds)))
    .for('share');
  if (found.length !== tagIds.length) throw new Error('INVALID_FORUM_TAGS');
}

