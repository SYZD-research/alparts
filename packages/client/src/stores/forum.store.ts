import { create } from 'zustand';
import type { ForumPostSummary, ForumTag, ForumViewerCapabilities, Message } from '@alparts/shared';
import { api } from '../services/api';
import { useAuthStore } from './auth.store';
import { isForumChannel, useMessageStore } from './message.store';
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
  openPost: (channelId: string, postId: string | null) => Promise<void>;
  loadMorePostMessages: (channelId: string, postId: string) => Promise<void>;
  markRead: (channelId: string, postId: string) => Promise<void>;
  createPost: (
    channelId: string,
    post: { title: string; body: string; tagIds: string[]; mentionedUserIds: string[] },
  ) => Promise<Message>;
  setLocked: (channelId: string, postId: string, locked: boolean) => Promise<void>;
  setResolved: (channelId: string, postId: string, resolved: boolean) => Promise<void>;
  setPostTags: (channelId: string, postId: string, tagIds: string[]) => Promise<void>;
  createTag: (channelId: string, name: string) => Promise<void>;
  renameTag: (channelId: string, tagId: string, name: string) => Promise<void>;
  deleteTag: (channelId: string, tagId: string) => Promise<void>;
  applyPostState: (state: ForumPostBroadcastState) => void;
  applyPostRead: (channelId: string, postId: string, lastReadActivityAt: string) => void;
  removePost: (channelId: string, postId: string) => void;
  applyTags: (channelId: string, tags: ForumTag[]) => void;
  revealMessage: (channelId: string, messageId: string) => Promise<boolean>;
  clearChannel: (channelId: string) => void;
  reset: () => void;
}

let forumGeneration = 0;
const listVersions = new Map<string, number>();
const pendingReads = new Map<string, ReturnType<typeof setTimeout>>();

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

/** Hand post events to the message store, which verifies and decrypts them. */
function ingestSummaries(channelId: string, summaries: ForumPostSummary[]): void {
  const events = summaries.flatMap((summary) => [summary.root, ...(summary.latestEdit ? [summary.latestEdit] : [])]);
  if (events.length > 0) useMessageStore.getState().addMessages(channelId, events);
}

function summaryReadAt(summary: ForumPostSummary): Record<string, string> {
  return summary.state.unread ? {} : { [summary.state.postId]: summary.state.lastActivityAt };
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
    update(channelId, (current) => ({
      states: { ...current.states, [next.postId]: next },
      postIds: current.loaded
        ? placeForumPost(current.postIds, current.states, next, current.sort, current.tagId, current.hasMore)
        : current.postIds,
    }));
  };

  return {
    channels: {},

    loadPosts: async (channelId) => {
      const generation = forumGeneration;
      const version = nextListVersion(channelId);
      const { sort, tagId } = view(channelId);
      update(channelId, () => ({ loading: true, error: null }));
      try {
        const response = await api.getForumPosts(channelId, { sort, ...(tagId ? { tagId } : {}) });
        if (generation !== forumGeneration || listVersions.get(channelId) !== version) return;
        const result = { ...response, data: summariesFor(channelId, response.data) };
        ingestSummaries(channelId, result.data);
        update(channelId, (current) => ({
          postIds: result.data.map((summary) => summary.state.postId),
          states: {
            ...current.states,
            ...Object.fromEntries(result.data.map((summary) => [summary.state.postId, stripUnread(summary.state)])),
          },
          lastReadAt: Object.assign({}, current.lastReadAt, ...result.data.map(summaryReadAt)),
          hasMore: result.hasMore,
          cursor: result.cursor,
          viewer: result.viewer,
          loading: false,
          loaded: true,
        }));
      } catch (error) {
        if (generation !== forumGeneration || listVersions.get(channelId) !== version) return;
        update(channelId, () => ({ loading: false, error: errorText(error, '投稿を読み込めませんでした') }));
      }
    },

    loadMorePosts: async (channelId) => {
      const current = view(channelId);
      if (!current.hasMore || !current.cursor || current.loadingMore || current.loading) return;
      const generation = forumGeneration;
      const version = listVersions.get(channelId);
      update(channelId, () => ({ loadingMore: true }));
      try {
        const response = await api.getForumPosts(channelId, {
          sort: current.sort,
          ...(current.tagId ? { tagId: current.tagId } : {}),
          cursor: current.cursor,
        });
        if (generation !== forumGeneration || listVersions.get(channelId) !== version) return;
        const result = { ...response, data: summariesFor(channelId, response.data) };
        ingestSummaries(channelId, result.data);
        update(channelId, (latest) => ({
          postIds: [...latest.postIds, ...result.data.map((summary) => summary.state.postId).filter((id) => !latest.postIds.includes(id))],
          states: {
            ...latest.states,
            ...Object.fromEntries(result.data.map((summary) => [summary.state.postId, stripUnread(summary.state)])),
          },
          lastReadAt: Object.assign({}, latest.lastReadAt, ...result.data.map(summaryReadAt)),
          hasMore: result.hasMore,
          cursor: result.cursor,
          loadingMore: false,
        }));
      } catch (error) {
        if (generation !== forumGeneration || listVersions.get(channelId) !== version) return;
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
      const generation = forumGeneration;
      try {
        const tags = await api.getForumTags(channelId);
        if (generation === forumGeneration) update(channelId, () => ({ tags }));
      } catch {
        // Tags are optional for reading; the list still works without them.
      }
    },

    openPost: async (channelId, postId) => {
      update(channelId, () => ({ activePostId: postId, activePostGone: false }));
      if (!postId) return;
      const generation = forumGeneration;
      try {
        if (!view(channelId).states[postId]) {
          const summary = await api.getForumPost(postId);
          if (generation !== forumGeneration) return;
          if (summary.state.postId !== postId || summariesFor(channelId, [summary]).length !== 1) throw new Error('POST_MISMATCH');
          ingestSummaries(channelId, [summary]);
          applyState(channelId, stripUnread(summary.state));
        }
        update(channelId, (current) => ({ postLoading: { ...current.postLoading, [postId]: true } }));
        const page = await api.getForumPostMessages(postId);
        if (generation !== forumGeneration) return;
        // Only events signed for this post are shown in it; the message store
        // verifies each signature before any of them become visible.
        useMessageStore.getState().addMessages(channelId, page.data.filter((event) => event.channelId === channelId));
        update(channelId, (current) => ({
          postLoading: { ...current.postLoading, [postId]: false },
          postHasMore: { ...current.postHasMore, [postId]: page.hasMore },
          postCursor: { ...current.postCursor, [postId]: page.cursor },
        }));
        void get().markRead(channelId, postId);
      } catch {
        if (generation !== forumGeneration) return;
        update(channelId, (current) => ({
          activePostGone: current.activePostId === postId,
          postLoading: { ...current.postLoading, [postId]: false },
        }));
      }
    },

    loadMorePostMessages: async (channelId, postId) => {
      const current = view(channelId);
      const cursor = current.postCursor[postId];
      if (!cursor || !current.postHasMore[postId] || current.postLoading[postId]) return;
      const generation = forumGeneration;
      update(channelId, (latest) => ({ postLoading: { ...latest.postLoading, [postId]: true } }));
      try {
        const page = await api.getForumPostMessages(postId, cursor);
        if (generation !== forumGeneration) return;
        useMessageStore.getState().addMessages(channelId, page.data.filter((event) => event.channelId === channelId));
        update(channelId, (latest) => ({
          postLoading: { ...latest.postLoading, [postId]: false },
          postHasMore: { ...latest.postHasMore, [postId]: page.hasMore },
          postCursor: { ...latest.postCursor, [postId]: page.cursor },
        }));
      } catch {
        if (generation === forumGeneration) {
          update(channelId, (latest) => ({ postLoading: { ...latest.postLoading, [postId]: false } }));
        }
      }
    },

    markRead: async (channelId, postId) => {
      const generation = forumGeneration;
      try {
        const read = await api.markForumPostRead(postId);
        if (generation !== forumGeneration || read.postId !== postId || read.channelId !== channelId) return;
        get().applyPostRead(channelId, postId, read.lastReadActivityAt);
      } catch {
        // Unread state is a convenience; failing to record it changes nothing else.
      }
    },

    createPost: async (channelId, post) => {
      const { message, state } = await useMessageStore.getState().createForumPost(channelId, post);
      applyState(channelId, state);
      get().applyPostRead(channelId, state.postId, state.lastActivityAt);
      return message;
    },

    setLocked: async (channelId, postId, locked) => {
      const state = await api.setForumPostLocked(postId, locked);
      if (state.postId === postId && state.channelId === channelId) applyState(channelId, state);
    },

    setResolved: async (channelId, postId, resolved) => {
      const state = await api.setForumPostResolved(postId, resolved);
      if (state.postId === postId && state.channelId === channelId) applyState(channelId, state);
    },

    setPostTags: async (channelId, postId, tagIds) => {
      const state = await api.setForumPostTags(postId, tagIds);
      if (state.postId === postId && state.channelId === channelId) applyState(channelId, state);
    },

    createTag: async (channelId, name) => {
      await api.createForumTag(channelId, name);
      await get().loadTags(channelId);
    },

    renameTag: async (channelId, tagId, name) => {
      await api.updateForumTag(tagId, { name });
      await get().loadTags(channelId);
    },

    deleteTag: async (channelId, tagId) => {
      await api.deleteForumTag(tagId);
      await get().loadTags(channelId);
      if (view(channelId).tagId === tagId) get().setTagFilter(channelId, null);
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
      update(channelId, (current) => ({
        tags,
        tagId: current.tagId && tags.some((tag) => tag.id === current.tagId) ? current.tagId : null,
      }));
    },

    revealMessage: async (channelId, messageId) => {
      if (!isForumChannel(channelId)) return false;
      const event = useMessageStore.getState().eventsByChannel[channelId]?.find((candidate) => candidate.id === messageId);
      if (!event) return false;
      await get().openPost(channelId, event.postId ?? event.id);
      return true;
    },

    clearChannel: (channelId) => {
      nextListVersion(channelId);
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
      for (const timer of pendingReads.values()) clearTimeout(timer);
      pendingReads.clear();
      set({ channels: {} });
    },
  };
});
