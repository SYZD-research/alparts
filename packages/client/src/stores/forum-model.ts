import type { ForumPostState } from '@alparts/shared';

export type ForumSort = 'activity' | 'created';
export type ForumPostBroadcastState = Omit<ForumPostState, 'unread'>;

/** Pinned posts first, then newest by the chosen time, then by id (the server's order). */
export function compareForumPosts(sort: ForumSort, left: ForumPostBroadcastState, right: ForumPostBroadcastState): number {
  if (left.isPinned !== right.isPinned) return left.isPinned ? -1 : 1;
  const leftAt = sort === 'created' ? left.createdAt : left.lastActivityAt;
  const rightAt = sort === 'created' ? right.createdAt : right.lastActivityAt;
  if (leftAt !== rightAt) return leftAt < rightAt ? 1 : -1;
  return left.postId < right.postId ? 1 : left.postId > right.postId ? -1 : 0;
}

/**
 * Whether a message belongs to the given forum post (the post itself or a
 * reply in it). Outside a forum (`postId` undefined) every message does.
 */
export function isInForumPost(message: { id: string; postId?: string | null }, postId: string | undefined): boolean {
  return postId === undefined || (message.postId ?? message.id) === postId;
}

export function matchesForumFilter(state: ForumPostBroadcastState, tagId: string | null): boolean {
  return !tagId || state.tagIds.includes(tagId);
}

/**
 * Unread is judged against the activity time this device last saw as read.
 * An unknown read time counts as unread for other people's posts only.
 */
export function isForumPostUnread(
  state: ForumPostBroadcastState,
  lastReadActivityAt: string | undefined,
  currentUserId: string | null,
): boolean {
  if (lastReadActivityAt === undefined) return state.authorId !== currentUserId;
  return state.lastActivityAt > lastReadActivityAt;
}

/**
 * Merge an updated post into the loaded list. A post that is new to this
 * list is added only when it would appear before the end of what is loaded,
 * so paging never skips or repeats it.
 */
export function placeForumPost(
  postIds: string[],
  states: Record<string, ForumPostBroadcastState>,
  next: ForumPostBroadcastState,
  sort: ForumSort,
  tagId: string | null,
  hasMore: boolean,
): string[] {
  const without = postIds.filter((postId) => postId !== next.postId);
  if (!matchesForumFilter(next, tagId)) return without;
  const loaded = without.flatMap((postId) => states[postId] ? [states[postId]] : []);
  const last = loaded[loaded.length - 1];
  const known = postIds.includes(next.postId);
  if (!known && hasMore && last && compareForumPosts(sort, next, last) > 0) return without;
  const index = loaded.findIndex((state) => compareForumPosts(sort, next, state) < 0);
  const ordered = loaded.map((state) => state.postId);
  ordered.splice(index === -1 ? ordered.length : index, 0, next.postId);
  return ordered;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isUuid = (value: unknown): value is string => typeof value === 'string' && UUID.test(value);
const isTime = (value: unknown): value is string => typeof value === 'string' && Number.isFinite(Date.parse(value));

/** Validate a post state from the network before it reaches the store. */
export function parseForumPostState(value: unknown): ForumPostBroadcastState | null {
  if (!value || typeof value !== 'object') return null;
  const state = value as Record<string, unknown>;
  if (
    !isUuid(state.postId) || !isUuid(state.channelId) || !isUuid(state.authorId)
    || !isTime(state.createdAt) || !isTime(state.lastActivityAt)
    || !Number.isSafeInteger(state.replyCount) || (state.replyCount as number) < 0
    || typeof state.locked !== 'boolean' || typeof state.resolved !== 'boolean' || typeof state.isPinned !== 'boolean'
    || !Array.isArray(state.tagIds) || state.tagIds.length > 5 || !state.tagIds.every(isUuid)
  ) return null;
  return {
    postId: state.postId,
    channelId: state.channelId,
    authorId: state.authorId,
    createdAt: state.createdAt,
    lastActivityAt: state.lastActivityAt,
    replyCount: state.replyCount as number,
    locked: state.locked,
    resolved: state.resolved,
    tagIds: [...state.tagIds] as string[],
    isPinned: state.isPinned,
  };
}

export function parseForumPostUpdated(value: unknown): ForumPostBroadcastState | null {
  if (!value || typeof value !== 'object') return null;
  const event = value as { channelId?: unknown; state?: unknown };
  const state = parseForumPostState(event.state);
  return state && state.channelId === event.channelId ? state : null;
}

export function parseForumPostRef(value: unknown): { channelId: string; postId: string } | null {
  if (!value || typeof value !== 'object') return null;
  const event = value as { channelId?: unknown; postId?: unknown };
  return isUuid(event.channelId) && isUuid(event.postId) ? { channelId: event.channelId, postId: event.postId } : null;
}

export function parseForumTagsUpdated(value: unknown): { channelId: string; tags: Array<{ id: string; channelId: string; name: string; position: number }> } | null {
  if (!value || typeof value !== 'object') return null;
  const event = value as { channelId?: unknown; tags?: unknown };
  if (!isUuid(event.channelId) || !Array.isArray(event.tags) || event.tags.length > 20) return null;
  const tags = event.tags.flatMap((tag) => {
    if (!tag || typeof tag !== 'object') return [];
    const candidate = tag as Record<string, unknown>;
    return isUuid(candidate.id) && candidate.channelId === event.channelId
      && typeof candidate.name === 'string' && candidate.name.length <= 20 && Number.isSafeInteger(candidate.position)
      ? [{ id: candidate.id, channelId: event.channelId as string, name: candidate.name, position: candidate.position as number }]
      : [];
  });
  return tags.length === event.tags.length ? { channelId: event.channelId, tags } : null;
}
