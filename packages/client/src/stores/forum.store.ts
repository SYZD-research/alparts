import { create } from 'zustand';
import type { ForumPostSummary, ForumTag, ForumViewerCapabilities, Message } from '@alparts/shared';
import { api, ApiError } from '../services/api';
import { useAuthStore } from './auth.store';
import { isForumChannel, setForumRetention, useMessageStore } from './message.store';
import {
  isForumPostUnread,
  placeForumPost,
  type ForumPostBroadcastState,
  type ForumSort,
} from './forum-model';

export interface ForumChannelView {
  postIds: string[];
  states: Record<string, ForumPostBroadcastState>;
  /** Activity time this device knows the viewer has read, per post. */
  lastReadAt: Record<string, string>;
  hasMore: boolean;
  cursor: string | null;
  loading: boolean;
  loadingMore: boolean;
  loaded: boolean;
  error: string | null;
  sort: ForumSort;
  tagId: string | null;
  tags: ForumTag[];
  viewer: ForumViewerCapabilities | null;
  activePostId: string | null;
  /** The open post is no longer available (deleted or out of reach). */
  activePostGone: boolean;
  /** The open post could not be loaded for now; it may still exist. */
  activePostFailed: boolean;
  postHasMore: Record<string, boolean>;
  postCursor: Record<string, string | null>;
  postLoading: Record<string, boolean>;
}

interface ForumState {
  channels: Record<string, ForumChannelView>;
  loadPosts: (channelId: string) => Promise<void>;
  loadMorePosts: (channelId: string) => Promise<void>;
  setSort: (channelId: string, sort: ForumSort) => void;
  setTagFilter: (channelId: string, tagId: string | null) => void;
  loadTags: (channelId: string) => Promise<void>;
  openPost: (channelId: string, postId: string | null, options?: { refresh?: boolean }) => Promise<void>;
  loadMorePostMessages: (channelId: string, postId: string) => Promise<void>;
  markRead: (channelId: string, postId: string) => Promise<void>;
  createPost: (
    channelId: string,
    post: { title: string; body: string; tagIds: string[]; mentionedUserIds: string[] },
  ) => Promise<Message>;
  setLocked: (channelId: string, postId: string, locked: boolean) => Promise<void>;
  setResolved: (channelId: string, postId: string, resolved: boolean) => Promise<void>;
  setPinned: (channelId: string, postId: string, pinned: boolean) => Promise<void>;
  setPostTags: (channelId: string, postId: string, tagIds: string[]) => Promise<void>;
  createTag: (channelId: string, name: string) => Promise<void>;
  renameTag: (channelId: string, tagId: string, name: string) => Promise<void>;
  deleteTag: (channelId: string, tagId: string) => Promise<void>;
  applyPostState: (state: ForumPostBroadcastState) => void;
  applyPostRead: (channelId: string, postId: string, lastReadActivityAt: string) => void;
  removePost: (channelId: string, postId: string) => void;
  applyTags: (channelId: string, tags: ForumTag[]) => void;
  revealMessage: (channelId: string, messageId: string) => Promise<boolean>;
  /** Catch up on a loaded forum after missed live updates (e.g. reconnecting). */
  refreshChannel: (channelId: string) => Promise<void>;
  clearChannel: (channelId: string) => void;
  reset: () => void;
}

let forumGeneration = 0;
/** Bumped when a channel's forum state is cleared, so older responses for it are dropped. */
const channelGenerations = new Map<string, number>();
const listVersions = new Map<string, number>();
const pendingReads = new Map<string, ReturnType<typeof setTimeout>>();
/**
 * Live changes per post, in the order they were applied. A list response
 * requested before a change must not undo it.
 */
let changeSequence = 0;
const liveChanges = new Map<string, Map<string, { at: number; removed: boolean }>>();

interface ForumScope {
  forum: number;
  channel: number;
}

function captureScope(channelId: string): ForumScope {
  return { forum: forumGeneration, channel: channelGenerations.get(channelId) ?? 0 };
}

function isScopeCurrent(channelId: string, scope: ForumScope): boolean {
  return scope.forum === forumGeneration && scope.channel === (channelGenerations.get(channelId) ?? 0);
}

function noteChange(channelId: string, postId: string, removed: boolean): void {
  changeSequence += 1;
  let changes = liveChanges.get(channelId);
  if (!changes) {
    changes = new Map();
    liveChanges.set(channelId, changes);
  }
  changes.set(postId, { at: changeSequence, removed });
}

function changeSince(channelId: string, postId: string, since: number): { removed: boolean } | null {
  const change = liveChanges.get(channelId)?.get(postId);
  return change && change.at > since ? change : null;
}

function laterTime(left: string | undefined, right: string): string {
  return left !== undefined && Date.parse(left) >= Date.parse(right) ? left : right;
}

/** A missing post or lost access, as opposed to a failure worth retrying. */
function isPostUnavailable(error: unknown): boolean {
  return (error instanceof ApiError && (error.status === 403 || error.status === 404))
    || (error instanceof Error && error.message === 'POST_MISMATCH');
}

function emptyView(): ForumChannelView {
  return {
    postIds: [],
    states: {},
    lastReadAt: {},
    hasMore: false,
    cursor: null,
    loading: false,
    loadingMore: false,
    loaded: false,
    error: null,
    sort: 'activity',
    tagId: null,
    tags: [],
    viewer: null,
    activePostId: null,
    activePostGone: false,
    activePostFailed: false,
    postHasMore: {},
    postCursor: {},
    postLoading: {},
  };
}

function nextListVersion(channelId: string): number {
  const version = (listVersions.get(channelId) ?? 0) + 1;
  listVersions.set(channelId, version);
  return version;
}

/** Only summaries of this channel whose events are this post's own are used. */
function summariesFor(channelId: string, summaries: ForumPostSummary[]): ForumPostSummary[] {
  return summaries.filter((summary) => (
    summary.state.channelId === channelId
    && summary.root.id === summary.state.postId
    && summary.root.channelId === channelId
    && (!summary.latestEdit || (summary.latestEdit.channelId === channelId && summary.latestEdit.refMessageId === summary.root.id))
  ));
}

/**
 * Posts shown in the list, and the open one, stay in memory however old they
 * are; the message store otherwise keeps only a channel's latest events.
 */
function retainPosts(channelId: string, current: ForumChannelView | undefined, extraPostIds: string[] = []): void {
  const activePostId = current?.activePostId ?? null;
  setForumRetention(channelId, {
    rootIds: new Set([...(current?.postIds ?? []), ...extraPostIds, ...(activePostId ? [activePostId] : [])]),
    activePostId,
  });
}

function hasResidentRoot(channelId: string, postId: string): boolean {
  return (useMessageStore.getState().eventsByChannel[channelId] ?? [])
    .some((event) => event.id === postId && event.type === 'message');
}

/** The latest activity of a post that this device has received and can show. */
function shownActivityAt(channelId: string, postId: string): string | null {
  let latest: string | null = null;
  for (const event of useMessageStore.getState().eventsByChannel[channelId] ?? []) {
    if (event.type !== 'message' || (event.id !== postId && event.postId !== postId)) continue;
    latest = latest === null ? event.createdAt : laterTime(latest, event.createdAt);
  }
  return latest;
}

/** Merge a page of the post list without undoing changes applied after it was requested. */
function mergeListPage(
  channelId: string,
  current: ForumChannelView,
  summaries: ForumPostSummary[],
  requestedAt: number,
  replace: boolean,
): Pick<ForumChannelView, 'postIds' | 'states' | 'lastReadAt'> {
  const states = { ...current.states };
  const lastReadAt = { ...current.lastReadAt };
  const pagePostIds: string[] = [];
  for (const summary of summaries) {
    const postId = summary.state.postId;
    const change = changeSince(channelId, postId, requestedAt);
    if (change?.removed) continue;
    if (!change) states[postId] = stripUnread(summary.state);
    if (!summary.state.unread) lastReadAt[postId] = laterTime(lastReadAt[postId], summary.state.lastActivityAt);
    pagePostIds.push(postId);
  }
  if (!replace) {
    return { postIds: [...current.postIds, ...pagePostIds.filter((id) => !current.postIds.includes(id))], states, lastReadAt };
  }
  // Posts changed meanwhile are placed by their newer state.
  const changed = [...(liveChanges.get(channelId)?.entries() ?? [])]
    .filter(([postId, change]) => change.at > requestedAt && !change.removed && states[postId])
    .map(([postId]) => postId);
  let postIds = pagePostIds.filter((postId) => !changed.includes(postId));
  for (const postId of changed) {
    postIds = placeForumPost(postIds, states, states[postId], current.sort, current.tagId, current.hasMore);
  }
  return { postIds, states, lastReadAt };
}

function stripUnread({ unread: _unread, ...state }: ForumPostSummary['state']): ForumPostBroadcastState {
  return state;
}

function errorText(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

export const useForumStore = create<ForumState>((set, get) => {
  const view = (channelId: string): ForumChannelView => get().channels[channelId] ?? emptyView();
  const update = (channelId: string, change: (current: ForumChannelView) => Partial<ForumChannelView>) => {
    set((state) => {
      const current = state.channels[channelId] ?? emptyView();
      return { channels: { ...state.channels, [channelId]: { ...current, ...change(current) } } };
    });
  };
  const applyState = (channelId: string, next: ForumPostBroadcastState) => {
    noteChange(channelId, next.postId, false);
    update(channelId, (current) => ({
      states: { ...current.states, [next.postId]: next },
      postIds: current.loaded
        ? placeForumPost(current.postIds, current.states, next, current.sort, current.tagId, current.hasMore)
        : current.postIds,
    }));
  };
  /** Hand post events to the message store, which verifies and decrypts them. */
  const ingestSummaries = (channelId: string, summaries: ForumPostSummary[]) => {
    const events = summaries.flatMap((summary) => [summary.root, ...(summary.latestEdit ? [summary.latestEdit] : [])]);
    if (events.length === 0) return;
    retainPosts(channelId, get().channels[channelId], summaries.map((summary) => summary.state.postId));
    useMessageStore.getState().addMessages(channelId, events);
  };
  const setTags = (channelId: string, tags: ForumTag[]) => {
    const current = view(channelId);
    const filterRemoved = current.tagId !== null && !tags.some((tag) => tag.id === current.tagId);
    update(channelId, () => (filterRemoved
      ? { tags, tagId: null, postIds: [], loaded: false, cursor: null, hasMore: false }
      : { tags }));
    // The list was narrowed by the removed tag; show every post again.
    if (filterRemoved) void get().loadPosts(channelId);
  };

  return {
    channels: {},

    loadPosts: async (channelId) => {
      const scope = captureScope(channelId);
      const version = nextListVersion(channelId);
      const requestedAt = changeSequence;
      const { sort, tagId } = view(channelId);
      update(channelId, () => ({ loading: true, error: null }));
      try {
        const response = await api.getForumPosts(channelId, { sort, ...(tagId ? { tagId } : {}) });
        if (!isScopeCurrent(channelId, scope) || listVersions.get(channelId) !== version) return;
        const result = { ...response, data: summariesFor(channelId, response.data) };
        ingestSummaries(channelId, result.data);
        update(channelId, (current) => ({
          ...mergeListPage(channelId, { ...current, hasMore: result.hasMore }, result.data, requestedAt, true),
          hasMore: result.hasMore,
          cursor: result.cursor,
          viewer: result.viewer,
          loading: false,
          loaded: true,
        }));
      } catch (error) {
        if (!isScopeCurrent(channelId, scope) || listVersions.get(channelId) !== version) return;
        update(channelId, () => ({ loading: false, error: errorText(error, '投稿を読み込めませんでした') }));
      }
    },

    loadMorePosts: async (channelId) => {
      const current = view(channelId);
      if (!current.hasMore || !current.cursor || current.loadingMore || current.loading) return;
      const scope = captureScope(channelId);
      const version = listVersions.get(channelId);
      const requestedAt = changeSequence;
      update(channelId, () => ({ loadingMore: true }));
      try {
        const response = await api.getForumPosts(channelId, {
          sort: current.sort,
          ...(current.tagId ? { tagId: current.tagId } : {}),
          cursor: current.cursor,
        });
        if (!isScopeCurrent(channelId, scope) || listVersions.get(channelId) !== version) return;
        const result = { ...response, data: summariesFor(channelId, response.data) };
        ingestSummaries(channelId, result.data);
        update(channelId, (latest) => ({
          ...mergeListPage(channelId, latest, result.data, requestedAt, false),
          hasMore: result.hasMore,
          cursor: result.cursor,
          loadingMore: false,
        }));
      } catch (error) {
        if (!isScopeCurrent(channelId, scope) || listVersions.get(channelId) !== version) return;
        update(channelId, () => ({ loadingMore: false, error: errorText(error, '投稿を読み込めませんでした') }));
      }
    },

    setSort: (channelId, sort) => {
      if (view(channelId).sort === sort) return;
      update(channelId, () => ({ sort, postIds: [], loaded: false, cursor: null, hasMore: false }));
      void get().loadPosts(channelId);
    },

    setTagFilter: (channelId, tagId) => {
      if (view(channelId).tagId === tagId) return;
      update(channelId, () => ({ tagId, postIds: [], loaded: false, cursor: null, hasMore: false }));
      void get().loadPosts(channelId);
    },

    loadTags: async (channelId) => {
      const scope = captureScope(channelId);
      try {
        const tags = await api.getForumTags(channelId);
        if (isScopeCurrent(channelId, scope)) setTags(channelId, tags.filter((tag) => tag.channelId === channelId));
      } catch {
        // Tags are optional for reading; the list still works without them.
      }
    },

    openPost: async (channelId, postId, options) => {
      update(channelId, () => ({ activePostId: postId, activePostGone: false, activePostFailed: false }));
      if (!postId) return;
      const scope = captureScope(channelId);
      try {
        // The post's first message may have left memory even though the list
        // still knows the post; fetch it again rather than wait for it.
        if (options?.refresh || !view(channelId).states[postId] || !hasResidentRoot(channelId, postId)) {
          const summary = await api.getForumPost(postId);
          if (!isScopeCurrent(channelId, scope)) return;
          if (summary.state.postId !== postId || summariesFor(channelId, [summary]).length !== 1) throw new Error('POST_MISMATCH');
          ingestSummaries(channelId, [summary]);
          applyState(channelId, stripUnread(summary.state));
        }
        update(channelId, (current) => ({ postLoading: { ...current.postLoading, [postId]: true } }));
        const page = await api.getForumPostMessages(postId);
        if (!isScopeCurrent(channelId, scope)) return;
        // Only events signed for this post are shown in it; the message store
        // verifies each signature before any of them become visible.
        retainPosts(channelId, get().channels[channelId], [postId]);
        useMessageStore.getState().addMessages(channelId, page.data.filter((event) => event.channelId === channelId));
        update(channelId, (current) => ({
          postLoading: { ...current.postLoading, [postId]: false },
          postHasMore: { ...current.postHasMore, [postId]: page.hasMore },
          postCursor: { ...current.postCursor, [postId]: page.cursor },
        }));
        // Only a post the viewer is still looking at counts as read.
        if (view(channelId).activePostId === postId) void get().markRead(channelId, postId);
      } catch (error) {
        if (!isScopeCurrent(channelId, scope)) return;
        const unavailable = isPostUnavailable(error);
        update(channelId, (current) => ({
          activePostGone: current.activePostGone || (current.activePostId === postId && unavailable),
          activePostFailed: current.activePostId === postId && !unavailable,
          postLoading: { ...current.postLoading, [postId]: false },
        }));
      }
    },

    loadMorePostMessages: async (channelId, postId) => {
      const current = view(channelId);
      const cursor = current.postCursor[postId];
      if (!cursor || !current.postHasMore[postId] || current.postLoading[postId]) return;
      const scope = captureScope(channelId);
      update(channelId, (latest) => ({ postLoading: { ...latest.postLoading, [postId]: true } }));
      try {
        const page = await api.getForumPostMessages(postId, cursor);
        if (!isScopeCurrent(channelId, scope)) return;
        retainPosts(channelId, get().channels[channelId], [postId]);
        useMessageStore.getState().addMessages(channelId, page.data.filter((event) => event.channelId === channelId));
        update(channelId, (latest) => ({
          postLoading: { ...latest.postLoading, [postId]: false },
          postHasMore: { ...latest.postHasMore, [postId]: page.hasMore },
          postCursor: { ...latest.postCursor, [postId]: page.cursor },
        }));
      } catch {
        if (isScopeCurrent(channelId, scope)) {
          update(channelId, (latest) => ({ postLoading: { ...latest.postLoading, [postId]: false } }));
        }
      }
    },

    markRead: async (channelId, postId) => {
      // Only activity this device has received for the post is reported, so
      // replies that arrived later stay unread.
      const shownAt = shownActivityAt(channelId, postId);
      if (!shownAt) return;
      const scope = captureScope(channelId);
      try {
        const read = await api.markForumPostRead(postId, shownAt);
        if (!isScopeCurrent(channelId, scope) || read.postId !== postId || read.channelId !== channelId) return;
        get().applyPostRead(channelId, postId, read.lastReadActivityAt);
      } catch {
        // Unread state is a convenience; failing to record it changes nothing else.
      }
    },

    createPost: async (channelId, post) => {
      const scope = captureScope(channelId);
      const { message, state } = await useMessageStore.getState().createForumPost(channelId, post);
      if (isScopeCurrent(channelId, scope)) {
        applyState(channelId, state);
        get().applyPostRead(channelId, state.postId, state.lastActivityAt);
      }
      return message;
    },

    setLocked: async (channelId, postId, locked) => {
      const scope = captureScope(channelId);
      const state = await api.setForumPostLocked(postId, locked);
      if (isScopeCurrent(channelId, scope) && state.postId === postId && state.channelId === channelId) applyState(channelId, state);
    },

    setResolved: async (channelId, postId, resolved) => {
      const scope = captureScope(channelId);
      const state = await api.setForumPostResolved(postId, resolved);
      if (isScopeCurrent(channelId, scope) && state.postId === postId && state.channelId === channelId) applyState(channelId, state);
    },

    setPinned: async (channelId, postId, pinned) => {
      const scope = captureScope(channelId);
      const result = await api.setForumPostPinned(postId, pinned);
      if (!isScopeCurrent(channelId, scope) || result.messageId !== postId || result.channelId !== channelId) return;
      useMessageStore.getState().applyPinUpdate(channelId, postId, result.pinned);
      // The response carries the post's new place in the list, so the view is
      // right even if no live update follows.
      const state = result.forumPost;
      if (state && state.postId === postId && state.channelId === channelId) applyState(channelId, state);
    },

    setPostTags: async (channelId, postId, tagIds) => {
      const scope = captureScope(channelId);
      const state = await api.setForumPostTags(postId, tagIds);
      if (isScopeCurrent(channelId, scope) && state.postId === postId && state.channelId === channelId) applyState(channelId, state);
    },

    createTag: async (channelId, name) => {
      await api.createForumTag(channelId, name);
      await get().loadTags(channelId);
    },

    renameTag: async (channelId, tagId, name) => {
      if (!view(channelId).tags.some((tag) => tag.id === tagId)) throw new Error('FORUM_TAG_MISMATCH');
      await api.updateForumTag(tagId, { name });
      await get().loadTags(channelId);
    },

    deleteTag: async (channelId, tagId) => {
      // The request names only the tag, so make sure it belongs to this forum.
      if (!view(channelId).tags.some((tag) => tag.id === tagId)) throw new Error('FORUM_TAG_MISMATCH');
      await api.deleteForumTag(tagId);
      await get().loadTags(channelId);
    },

    applyPostState: (state) => {
      if (!get().channels[state.channelId]) return;
      applyState(state.channelId, state);
      // While a post is open, its new replies are being read.
      const current = view(state.channelId);
      if (current.activePostId === state.postId && isForumPostUnread(state, current.lastReadAt[state.postId], useAuthStore.getState().user?.id ?? null)) {
        const key = `${state.channelId}:${state.postId}`;
        clearTimeout(pendingReads.get(key));
        pendingReads.set(key, setTimeout(() => {
          pendingReads.delete(key);
          if (view(state.channelId).activePostId === state.postId) void get().markRead(state.channelId, state.postId);
        }, 1_000));
      }
    },

    applyPostRead: (channelId, postId, lastReadActivityAt) => {
      if (!get().channels[channelId]) return;
      update(channelId, (current) => {
        const previous = current.lastReadAt[postId];
        return previous !== undefined && previous >= lastReadActivityAt
          ? {}
          : { lastReadAt: { ...current.lastReadAt, [postId]: lastReadActivityAt } };
      });
    },

    removePost: (channelId, postId) => {
      if (!get().channels[channelId]) return;
      noteChange(channelId, postId, true);
      update(channelId, (current) => {
        const states = { ...current.states };
        delete states[postId];
        return {
          postIds: current.postIds.filter((id) => id !== postId),
          states,
          activePostGone: current.activePostGone || current.activePostId === postId,
        };
      });
    },

    applyTags: (channelId, tags) => {
      if (!get().channels[channelId]) return;
      setTags(channelId, tags);
    },

    revealMessage: async (channelId, messageId) => {
      if (!isForumChannel(channelId)) return false;
      const event = useMessageStore.getState().eventsByChannel[channelId]?.find((candidate) => candidate.id === messageId);
      if (!event) return false;
      await get().openPost(channelId, event.postId ?? event.id);
      return true;
    },

    refreshChannel: async (channelId) => {
      const current = get().channels[channelId];
      if (!current) return;
      await Promise.all([
        get().loadPosts(channelId),
        get().loadTags(channelId),
        current.activePostId ? get().openPost(channelId, current.activePostId, { refresh: true }) : undefined,
      ]);
    },

    clearChannel: (channelId) => {
      channelGenerations.set(channelId, (channelGenerations.get(channelId) ?? 0) + 1);
      nextListVersion(channelId);
      liveChanges.delete(channelId);
      for (const [key, timer] of pendingReads) {
        if (!key.startsWith(`${channelId}:`)) continue;
        clearTimeout(timer);
        pendingReads.delete(key);
      }
      setForumRetention(channelId, null);
      set((state) => {
        if (!state.channels[channelId]) return state;
        const channels = { ...state.channels };
        delete channels[channelId];
        return { channels };
      });
    },

    reset: () => {
      forumGeneration += 1;
      listVersions.clear();
      liveChanges.clear();
      for (const timer of pendingReads.values()) clearTimeout(timer);
      pendingReads.clear();
      set({ channels: {} });
    },
  };
});
