import { create } from 'zustand';
import type {
  ChannelReadState,
  Message,
  MessageBookmark,
  NotificationLevel,
  ReadPosition,
} from '@alparts/shared';
import { api } from '../services/api';
import { useMessageStore } from './message.store';
import { useAuthStore } from './auth.store';
import {
  defaultChannelReadState,
  mergeChannelPreference,
  readAdvanceDecision,
  sortBookmarks,
} from './user-state-model';
import { runBounded } from './workspace-unread-model';

type ChannelStateMap = Record<string, ChannelReadState>;

interface UserStateStore {
  channelStatesByWorkspace: Record<string, ChannelStateMap>;
  loadingByWorkspace: Record<string, boolean>;
  errorsByWorkspace: Record<string, string | null>;
  showHiddenByWorkspace: Record<string, boolean>;
  preferenceSavingByChannel: Record<string, boolean>;
  preferenceErrorsByChannel: Record<string, string | null>;
  readUpdatedAtByChannel: Record<string, string>;
  bookmarks: MessageBookmark[];
  bookmarkedMessageIds: Record<string, boolean>;
  bookmarkSavingByMessage: Record<string, boolean>;
  bookmarksLoading: boolean;
  bookmarkError: string | null;
  loadWorkspaceState: (workspaceId: string) => Promise<ChannelStateMap>;
  loadAllWorkspaceStates: (workspaceIds: string[], concurrency?: number) => Promise<void>;
  updatePreference: (workspaceId: string, channelId: string, updates: {
    favorite?: boolean;
    muted?: boolean;
    hidden?: boolean;
    notificationLevel?: NotificationLevel;
  }) => Promise<void>;
  toggleShowHidden: (workspaceId: string) => void;
  noteBaseMessage: (message: Message) => void;
  markRead: (channelId: string, messageId: string) => Promise<void>;
  applySocketReadPosition: (position: ReadPosition) => void;
  loadBookmarks: (limit?: number) => Promise<void>;
  toggleBookmark: (messageId: string) => Promise<void>;
  clearBookmarkError: () => void;
  clearChannel: (workspaceId: string, channelId: string) => void;
  clearWorkspace: (workspaceId: string) => void;
  reset: () => void;
}

let storeGeneration = 0;
const workspaceRequestVersions = new Map<string, number>();
const bookmarkRequests = new Map<string, symbol>();
const readRequests = new Map<string, string>();
const channelScopeVersions = new Map<string, number>();
let bookmarkListVersion = 0;

function messageForError(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

function mapChannelStates(states: ChannelReadState[]): ChannelStateMap {
  return Object.fromEntries(states.map((state) => [state.channelId, state]));
}

function workspaceForChannel(
  statesByWorkspace: Record<string, ChannelStateMap>,
  channelId: string,
): string | null {
  return Object.keys(statesByWorkspace).find((workspaceId) => Boolean(statesByWorkspace[workspaceId]?.[channelId])) || null;
}

function channelScopeVersion(channelId: string): number {
  return channelScopeVersions.get(channelId) || 0;
}

export const useUserStateStore = create<UserStateStore>((set, get) => ({
  channelStatesByWorkspace: {},
  loadingByWorkspace: {},
  errorsByWorkspace: {},
  showHiddenByWorkspace: {},
  preferenceSavingByChannel: {},
  preferenceErrorsByChannel: {},
  readUpdatedAtByChannel: {},
  bookmarks: [],
  bookmarkedMessageIds: {},
  bookmarkSavingByMessage: {},
  bookmarksLoading: false,
  bookmarkError: null,

  loadWorkspaceState: async (workspaceId) => {
    const generation = storeGeneration;
    const channelScopeSnapshot = new Map(channelScopeVersions);
    const version = (workspaceRequestVersions.get(workspaceId) || 0) + 1;
    workspaceRequestVersions.set(workspaceId, version);
    set((state) => ({
      loadingByWorkspace: { ...state.loadingByWorkspace, [workspaceId]: true },
      errorsByWorkspace: { ...state.errorsByWorkspace, [workspaceId]: null },
    }));
    try {
      const response = await api.getWorkspaceChannelState(workspaceId);
      const states = mapChannelStates(response.filter((channelState) => (
        (channelScopeSnapshot.get(channelState.channelId) || 0) === channelScopeVersion(channelState.channelId)
      )));
      if (generation !== storeGeneration || workspaceRequestVersions.get(workspaceId) !== version) return states;
      set((state) => ({
        channelStatesByWorkspace: { ...state.channelStatesByWorkspace, [workspaceId]: states },
        loadingByWorkspace: { ...state.loadingByWorkspace, [workspaceId]: false },
        errorsByWorkspace: { ...state.errorsByWorkspace, [workspaceId]: null },
      }));
      return states;
    } catch (error) {
      if (generation === storeGeneration && workspaceRequestVersions.get(workspaceId) === version) {
        set((state) => ({
          loadingByWorkspace: { ...state.loadingByWorkspace, [workspaceId]: false },
          errorsByWorkspace: {
            ...state.errorsByWorkspace,
            [workspaceId]: messageForError(error, 'チャンネル状態を読み込めませんでした'),
          },
        }));
      }
      return get().channelStatesByWorkspace[workspaceId] || {};
    }
  },

  loadAllWorkspaceStates: async (workspaceIds, concurrency = 4) => {
    const uniqueWorkspaceIds = [...new Set(workspaceIds)];
    await runBounded(uniqueWorkspaceIds, concurrency, async (workspaceId) => {
      await get().loadWorkspaceState(workspaceId);
    });
  },

  updatePreference: async (workspaceId, channelId, updates) => {
    const generation = storeGeneration;
    const scopeVersion = channelScopeVersion(channelId);
    set((state) => ({
      preferenceSavingByChannel: { ...state.preferenceSavingByChannel, [channelId]: true },
      preferenceErrorsByChannel: { ...state.preferenceErrorsByChannel, [channelId]: null },
    }));
    try {
      const preference = await api.updateChannelPreference(channelId, updates);
      if (generation !== storeGeneration || scopeVersion !== channelScopeVersion(channelId)) return;
      set((state) => {
        const workspaceStates = state.channelStatesByWorkspace[workspaceId] || {};
        return {
          channelStatesByWorkspace: {
            ...state.channelStatesByWorkspace,
            [workspaceId]: {
              ...workspaceStates,
              [channelId]: mergeChannelPreference(workspaceStates[channelId], preference),
            },
          },
          preferenceSavingByChannel: { ...state.preferenceSavingByChannel, [channelId]: false },
        };
      });
      void get().loadWorkspaceState(workspaceId);
    } catch (error) {
      if (generation !== storeGeneration || scopeVersion !== channelScopeVersion(channelId)) return;
      set((state) => ({
        preferenceSavingByChannel: { ...state.preferenceSavingByChannel, [channelId]: false },
        preferenceErrorsByChannel: {
          ...state.preferenceErrorsByChannel,
          [channelId]: messageForError(error, 'チャンネル設定を保存できませんでした'),
        },
      }));
      throw error;
    }
  },

  toggleShowHidden: (workspaceId) => set((state) => ({
    showHiddenByWorkspace: {
      ...state.showHiddenByWorkspace,
      [workspaceId]: !state.showHiddenByWorkspace[workspaceId],
    },
  })),

  noteBaseMessage: (message) => {
    if (message.type !== 'message') return;
    set((state) => {
      const workspaceId = workspaceForChannel(state.channelStatesByWorkspace, message.channelId);
      if (!workspaceId) return state;
      const workspaceStates = state.channelStatesByWorkspace[workspaceId] || {};
      const current = workspaceStates[message.channelId] || defaultChannelReadState(message.channelId);
      const loadedBaseMessages = (useMessageStore.getState().eventsByChannel[message.channelId] || [])
        .filter((event) => event.type === 'message');
      const latestDecision = current.latestMessageId
        ? readAdvanceDecision(current.latestMessageId, message.id, loadedBaseMessages)
        : 'advance';
      if (latestDecision === 'same' || latestDecision === 'behind') return state;
      return {
        channelStatesByWorkspace: {
          ...state.channelStatesByWorkspace,
          [workspaceId]: {
            ...workspaceStates,
            [message.channelId]: {
              ...current,
              latestMessageId: message.id,
              unreadCount: current.lastReadMessageId === message.id || message.authorId === useAuthStore.getState().user?.id
                ? current.unreadCount : current.unreadCount + 1,
            },
          },
        },
      };
    });
  },

  markRead: async (channelId, messageId) => {
    const state = get();
    const workspaceId = workspaceForChannel(state.channelStatesByWorkspace, channelId);
    if (!workspaceId || readRequests.get(channelId) === messageId) return;
    const current = state.channelStatesByWorkspace[workspaceId]?.[channelId];
    const loadedBaseMessages = (useMessageStore.getState().eventsByChannel[channelId] || [])
      .filter((message) => message.type === 'message');
    const decision = readAdvanceDecision(current?.lastReadMessageId || null, messageId, loadedBaseMessages);
    if (decision === 'same' || decision === 'behind') return;
    const generation = storeGeneration;
    const scopeVersion = channelScopeVersion(channelId);
    readRequests.set(channelId, messageId);
    try {
      const position = await api.updateReadPosition(channelId, messageId);
      if (generation !== storeGeneration || scopeVersion !== channelScopeVersion(channelId)) return;
      const latestState = get();
      const latestWorkspaceId = workspaceForChannel(latestState.channelStatesByWorkspace, channelId);
      if (!latestWorkspaceId) return;
      set((storeState) => {
        const knownUpdatedAt = storeState.readUpdatedAtByChannel[channelId];
        if (knownUpdatedAt && position.updatedAt < knownUpdatedAt) return storeState;
        const workspaceStates = storeState.channelStatesByWorkspace[latestWorkspaceId] || {};
        const channelState = workspaceStates[channelId] || defaultChannelReadState(channelId);
        return {
          channelStatesByWorkspace: {
            ...storeState.channelStatesByWorkspace,
            [latestWorkspaceId]: {
              ...workspaceStates,
              [channelId]: {
                ...channelState,
                lastReadMessageId: position.lastReadMessageId,
                unreadCount: position.lastReadMessageId === channelState.latestMessageId ? 0 : channelState.unreadCount,
              },
            },
          },
          readUpdatedAtByChannel: {
            ...storeState.readUpdatedAtByChannel,
            [channelId]: position.updatedAt,
          },
        };
      });
      void get().loadWorkspaceState(latestWorkspaceId);
    } catch (error) {
      if (generation === storeGeneration && scopeVersion === channelScopeVersion(channelId)) {
        set((storeState) => ({
          errorsByWorkspace: {
            ...storeState.errorsByWorkspace,
            [workspaceId]: messageForError(error, '既読位置を同期できませんでした'),
          },
        }));
      }
    } finally {
      if (readRequests.get(channelId) === messageId) readRequests.delete(channelId);
    }
  },

  applySocketReadPosition: (position) => {
    const state = get();
    const workspaceId = workspaceForChannel(state.channelStatesByWorkspace, position.channelId);
    if (!workspaceId) return;
    const current = state.channelStatesByWorkspace[workspaceId]?.[position.channelId];
    const knownUpdatedAt = state.readUpdatedAtByChannel[position.channelId];
    if (knownUpdatedAt && position.updatedAt < knownUpdatedAt) return;
    const loadedBaseMessages = (useMessageStore.getState().eventsByChannel[position.channelId] || [])
      .filter((message) => message.type === 'message');
    const decision = readAdvanceDecision(
      current?.lastReadMessageId || null,
      position.lastReadMessageId || '',
      loadedBaseMessages,
    );
    if (!position.lastReadMessageId || decision === 'behind') return;
    if (decision === 'unknown') {
      void get().loadWorkspaceState(workspaceId);
      return;
    }
    set((storeState) => {
      const workspaceStates = storeState.channelStatesByWorkspace[workspaceId] || {};
      const channelState = workspaceStates[position.channelId] || defaultChannelReadState(position.channelId);
      return {
        channelStatesByWorkspace: {
          ...storeState.channelStatesByWorkspace,
          [workspaceId]: {
            ...workspaceStates,
            [position.channelId]: {
              ...channelState,
              lastReadMessageId: position.lastReadMessageId,
              unreadCount: position.lastReadMessageId === channelState.latestMessageId ? 0 : channelState.unreadCount,
            },
          },
        },
        readUpdatedAtByChannel: {
          ...storeState.readUpdatedAtByChannel,
          [position.channelId]: position.updatedAt,
        },
      };
    });
    if (decision === 'advance') void get().loadWorkspaceState(workspaceId);
  },

  loadBookmarks: async (limit = 100) => {
    const generation = storeGeneration;
    const version = ++bookmarkListVersion;
    set({ bookmarksLoading: true, bookmarkError: null });
    try {
      const bookmarks = sortBookmarks(await api.getMessageBookmarks(limit));
      if (generation !== storeGeneration || version !== bookmarkListVersion) return;
      set({
        bookmarks,
        bookmarkedMessageIds: Object.fromEntries(bookmarks.map((bookmark) => [bookmark.messageId, true])),
        bookmarksLoading: false,
      });
    } catch (error) {
      if (generation === storeGeneration && version === bookmarkListVersion) {
        set({
          bookmarksLoading: false,
          bookmarkError: messageForError(error, '保存済みメッセージを読み込めませんでした'),
        });
      }
    }
  },

  toggleBookmark: async (messageId) => {
    const generation = storeGeneration;
    const requestedChannelId = get().bookmarks.find((bookmark) => bookmark.messageId === messageId)?.channelId
      || Object.entries(useMessageStore.getState().eventsByChannel)
        .find(([, events]) => events.some((event) => event.id === messageId))?.[0]
      || null;
    const requestedScopeVersion = requestedChannelId ? channelScopeVersion(requestedChannelId) : null;
    const request = Symbol();
    bookmarkRequests.set(messageId, request);
    set((state) => ({
      bookmarkSavingByMessage: { ...state.bookmarkSavingByMessage, [messageId]: true },
      bookmarkError: null,
    }));
    try {
      const result = await api.toggleMessageBookmark(messageId);
      if (generation !== storeGeneration || bookmarkRequests.get(messageId) !== request) return;
      if (
        (requestedChannelId && (
          result.channelId !== requestedChannelId
          || requestedScopeVersion !== channelScopeVersion(requestedChannelId)
        ))
        || !workspaceForChannel(get().channelStatesByWorkspace, result.channelId)
      ) return;
      set((state) => {
        const remaining = state.bookmarks.filter((bookmark) => bookmark.messageId !== messageId);
        const bookmarks = result.bookmarked && result.createdAt
          ? sortBookmarks([...remaining, { messageId, channelId: result.channelId, createdAt: result.createdAt }])
          : remaining;
        const bookmarkedMessageIds = { ...state.bookmarkedMessageIds };
        if (result.bookmarked) bookmarkedMessageIds[messageId] = true;
        else delete bookmarkedMessageIds[messageId];
        return {
          bookmarks,
          bookmarkedMessageIds,
          bookmarkSavingByMessage: { ...state.bookmarkSavingByMessage, [messageId]: false },
        };
      });
      void get().loadBookmarks();
    } catch (error) {
      if (generation === storeGeneration
        && bookmarkRequests.get(messageId) === request
        && (!requestedChannelId || requestedScopeVersion === channelScopeVersion(requestedChannelId))) {
        set((state) => ({
          bookmarkSavingByMessage: { ...state.bookmarkSavingByMessage, [messageId]: false },
          bookmarkError: messageForError(error, 'ブックマークを更新できませんでした'),
        }));
      }
      throw error;
    } finally {
      if (bookmarkRequests.get(messageId) === request) {
        bookmarkRequests.delete(messageId);
        set((state) => ({ bookmarkSavingByMessage: withoutKey(state.bookmarkSavingByMessage, messageId) }));
      }
    }
  },

  clearBookmarkError: () => set({ bookmarkError: null }),

  clearChannel: (workspaceId, channelId) => {
    channelScopeVersions.set(channelId, channelScopeVersion(channelId) + 1);
    readRequests.delete(channelId);
    const messageIds = new Set([
      ...(useMessageStore.getState().eventsByChannel[channelId] || []).map((event) => event.id),
      ...get().bookmarks.filter((bookmark) => bookmark.channelId === channelId).map((bookmark) => bookmark.messageId),
    ]);
    for (const messageId of messageIds) bookmarkRequests.delete(messageId);
    set((state) => clearChannelState(state, workspaceId, channelId, messageIds));
  },

  clearWorkspace: (workspaceId) => {
    const channelIds = Object.keys(get().channelStatesByWorkspace[workspaceId] || {});
    const removedMessageIdsByChannel = new Map(channelIds.map((channelId) => [
      channelId,
      new Set([
        ...(useMessageStore.getState().eventsByChannel[channelId] || []).map((event) => event.id),
        ...get().bookmarks.filter((bookmark) => bookmark.channelId === channelId).map((bookmark) => bookmark.messageId),
      ]),
    ]));
    workspaceRequestVersions.set(workspaceId, (workspaceRequestVersions.get(workspaceId) || 0) + 1);
    for (const channelId of channelIds) {
      channelScopeVersions.set(channelId, channelScopeVersion(channelId) + 1);
      readRequests.delete(channelId);
      for (const messageId of removedMessageIdsByChannel.get(channelId) || []) bookmarkRequests.delete(messageId);
    }
    set((state) => {
      let next = state;
      for (const channelId of channelIds) {
        next = {
          ...next,
          ...clearChannelState(next, workspaceId, channelId, removedMessageIdsByChannel.get(channelId)),
        };
      }
      return {
        ...next,
        channelStatesByWorkspace: withoutKey(next.channelStatesByWorkspace, workspaceId),
        loadingByWorkspace: withoutKey(next.loadingByWorkspace, workspaceId),
        errorsByWorkspace: withoutKey(next.errorsByWorkspace, workspaceId),
        showHiddenByWorkspace: withoutKey(next.showHiddenByWorkspace, workspaceId),
      };
    });
  },

  reset: () => {
    storeGeneration += 1;
    bookmarkListVersion += 1;
    workspaceRequestVersions.clear();
    bookmarkRequests.clear();
    readRequests.clear();
    channelScopeVersions.clear();
    set({
      channelStatesByWorkspace: {},
      loadingByWorkspace: {},
      errorsByWorkspace: {},
      showHiddenByWorkspace: {},
      preferenceSavingByChannel: {},
      preferenceErrorsByChannel: {},
      readUpdatedAtByChannel: {},
      bookmarks: [],
      bookmarkedMessageIds: {},
      bookmarkSavingByMessage: {},
      bookmarksLoading: false,
      bookmarkError: null,
    });
  },
}));

function clearChannelState(
  state: UserStateStore,
  workspaceId: string,
  channelId: string,
  removedMessageIds: ReadonlySet<string> = new Set(),
): Partial<UserStateStore> {
  const workspaceStates = withoutKey(state.channelStatesByWorkspace[workspaceId] || {}, channelId);
  const channelStatesByWorkspace = Object.keys(workspaceStates).length > 0
    ? { ...state.channelStatesByWorkspace, [workspaceId]: workspaceStates }
    : withoutKey(state.channelStatesByWorkspace, workspaceId);
  const bookmarks = state.bookmarks.filter((bookmark) => bookmark.channelId !== channelId);
  return {
    channelStatesByWorkspace,
    preferenceSavingByChannel: withoutKey(state.preferenceSavingByChannel, channelId),
    preferenceErrorsByChannel: withoutKey(state.preferenceErrorsByChannel, channelId),
    readUpdatedAtByChannel: withoutKey(state.readUpdatedAtByChannel, channelId),
    bookmarks,
    bookmarkedMessageIds: Object.fromEntries(bookmarks.map((bookmark) => [bookmark.messageId, true])),
    bookmarkSavingByMessage: Object.fromEntries(Object.entries(state.bookmarkSavingByMessage)
      .filter(([messageId]) => !removedMessageIds.has(messageId))),
  };
}

function withoutKey<T>(record: Record<string, T>, key: string): Record<string, T> {
  if (!(key in record)) return record;
  const next = { ...record };
  delete next[key];
  return next;
}
