import { create } from 'zustand';
import {
  deleteLocalDraft,
  deleteLocalDraftsForChannel,
  loadLocalDraft,
  saveLocalDraft,
} from '../services/local-state.service';
import { draftScopeBelongsToChannel as belongsToChannel, draftScopeChannelId } from './draft-scope';
import { t } from '../i18n';

export { forumPostDraftScope } from './draft-scope';

function isRevoked(scope: string): boolean {
  return revokedChannels.has(draftScopeChannelId(scope));
}

/** Keys are draft scopes: a channel id, or a forum post scope. */
interface DraftState {
  drafts: Record<string, string>;
  loadedByChannel: Record<string, boolean>;
  loadingByChannel: Record<string, boolean>;
  errorsByChannel: Record<string, string | null>;
  loadDraft: (channelId: string) => Promise<void>;
  setDraft: (channelId: string, content: string) => void;
  clearDraft: (channelId: string) => Promise<void>;
  clearChannel: (channelId: string) => Promise<void>;
  restoreChannel: (channelId: string) => Promise<void>;
  clearError: (channelId: string) => void;
  reset: () => void;
}

const SAVE_DELAY_MS = 300;
const saveTimers = new Map<string, ReturnType<typeof setTimeout>>();
const persistQueues = new Map<string, Promise<void>>();
interface PendingPersistence {
  generation: number;
  operation: () => Promise<void>;
  onError: (error: unknown) => void;
  promise: Promise<void>;
  resolve: () => void;
}
const pendingPersistence = new Map<string, PendingPersistence>();
const draftVersions = new Map<string, number>();
const revokedChannels = new Set<string>();
let draftGeneration = 0;

function errorMessage(error: unknown): string {
  return error instanceof Error && error.message
    ? error.message
    : t('下書きを端末へ保存できませんでした');
}

function nextDraftVersion(channelId: string): number {
  const version = (draftVersions.get(channelId) || 0) + 1;
  draftVersions.set(channelId, version);
  return version;
}

function queuePersistence(
  channelId: string,
  generation: number,
  operation: () => Promise<void>,
  onError: (error: unknown) => void,
): Promise<void> {
  const existing = pendingPersistence.get(channelId);
  let resolve = existing?.resolve;
  let promise = existing?.promise;
  if (!resolve || !promise) {
    promise = new Promise<void>((resolvePromise) => { resolve = resolvePromise; });
  }
  pendingPersistence.set(channelId, {
    generation,
    operation,
    onError,
    promise,
    resolve: resolve!,
  });
  if (!persistQueues.has(channelId)) drainPersistence(channelId);
  return promise;
}

function drainPersistence(channelId: string): void {
  let worker!: Promise<void>;
  worker = (async () => {
    for (;;) {
      const pending = pendingPersistence.get(channelId);
      if (!pending) return;
      pendingPersistence.delete(channelId);
      try {
        if (pending.generation === draftGeneration) await pending.operation();
      } catch (error) {
        pending.onError(error);
      } finally {
        pending.resolve();
      }
    }
  })().finally(() => {
    if (persistQueues.get(channelId) === worker) persistQueues.delete(channelId);
  });
  persistQueues.set(channelId, worker);
}

export const useDraftStore = create<DraftState>((set, get) => ({
  drafts: {},
  loadedByChannel: {},
  loadingByChannel: {},
  errorsByChannel: {},

  loadDraft: async (channelId) => {
    if (isRevoked(channelId)) return;
    if (get().loadedByChannel[channelId] || get().loadingByChannel[channelId]) return;
    const generation = draftGeneration;
    const version = draftVersions.get(channelId) || 0;
    set((state) => ({
      loadingByChannel: { ...state.loadingByChannel, [channelId]: true },
      errorsByChannel: { ...state.errorsByChannel, [channelId]: null },
    }));
    try {
      const content = await loadLocalDraft(channelId);
      if (generation !== draftGeneration || (draftVersions.get(channelId) || 0) !== version) return;
      set((state) => ({
        drafts: { ...state.drafts, [channelId]: content || '' },
        loadedByChannel: { ...state.loadedByChannel, [channelId]: true },
        loadingByChannel: { ...state.loadingByChannel, [channelId]: false },
      }));
    } catch (error) {
      if (generation !== draftGeneration || (draftVersions.get(channelId) || 0) !== version || isRevoked(channelId)) return;
      set((state) => ({
        loadedByChannel: { ...state.loadedByChannel, [channelId]: true },
        loadingByChannel: { ...state.loadingByChannel, [channelId]: false },
        errorsByChannel: { ...state.errorsByChannel, [channelId]: errorMessage(error) },
      }));
    }
  },

  setDraft: (channelId, content) => {
    if (isRevoked(channelId)) return;
    const generation = draftGeneration;
    nextDraftVersion(channelId);
    const existingTimer = saveTimers.get(channelId);
    if (existingTimer) clearTimeout(existingTimer);
    set((state) => ({
      drafts: { ...state.drafts, [channelId]: content },
      loadedByChannel: { ...state.loadedByChannel, [channelId]: true },
      loadingByChannel: { ...state.loadingByChannel, [channelId]: false },
      errorsByChannel: { ...state.errorsByChannel, [channelId]: null },
    }));
    const timer = setTimeout(() => {
      saveTimers.delete(channelId);
      void queuePersistence(
        channelId,
        generation,
        async () => {
          if (!isRevoked(channelId)) {
            if (content) await saveLocalDraft(channelId, content);
            else await deleteLocalDraft(channelId);
          }
        },
        (error) => {
          if (generation === draftGeneration && !isRevoked(channelId)) {
            set((state) => ({ errorsByChannel: { ...state.errorsByChannel, [channelId]: errorMessage(error) } }));
          }
        },
      );
    }, SAVE_DELAY_MS);
    saveTimers.set(channelId, timer);
  },

  clearDraft: async (channelId) => {
    const generation = draftGeneration;
    nextDraftVersion(channelId);
    const timer = saveTimers.get(channelId);
    if (timer) clearTimeout(timer);
    saveTimers.delete(channelId);
    set((state) => {
      const drafts = { ...state.drafts };
      delete drafts[channelId];
      return {
        drafts,
        loadedByChannel: { ...state.loadedByChannel, [channelId]: true },
        errorsByChannel: { ...state.errorsByChannel, [channelId]: null },
      };
    });
    await queuePersistence(
      channelId,
      generation,
      () => deleteLocalDraft(channelId),
      (error) => {
        if (generation === draftGeneration) {
          set((state) => ({ errorsByChannel: { ...state.errorsByChannel, [channelId]: errorMessage(error) } }));
        }
      },
    );
  },

  clearChannel: async (channelId) => {
    revokedChannels.add(channelId);
    const generation = draftGeneration;
    const scopes = new Set([channelId, ...Object.keys(get().drafts).filter((scope) => belongsToChannel(scope, channelId))]);
    for (const scope of saveTimers.keys()) if (belongsToChannel(scope, channelId)) scopes.add(scope);
    for (const scope of scopes) {
      nextDraftVersion(scope);
      const timer = saveTimers.get(scope);
      if (timer) clearTimeout(timer);
      saveTimers.delete(scope);
    }
    set((state) => ({
      drafts: withoutScopes(state.drafts, channelId),
      loadedByChannel: withoutScopes(state.loadedByChannel, channelId),
      loadingByChannel: withoutScopes(state.loadingByChannel, channelId),
      errorsByChannel: withoutScopes(state.errorsByChannel, channelId),
    }));
    // Wait for saves already running in any of the channel's scopes, then
    // delete them all, so the final persistent state is absent even in a race.
    await Promise.all([...persistQueues.entries()]
      .filter(([scope]) => scope !== channelId && belongsToChannel(scope, channelId))
      .map(([, queue]) => queue));
    await queuePersistence(channelId, generation, () => deleteLocalDraftsForChannel(channelId), () => undefined);
  },

  restoreChannel: async (channelId) => {
    const generation = draftGeneration;
    const version = draftVersions.get(channelId);
    await persistQueues.get(channelId);
    if (generation === draftGeneration && version === draftVersions.get(channelId)) revokedChannels.delete(channelId);
  },

  clearError: (channelId) => set((state) => ({
    errorsByChannel: { ...state.errorsByChannel, [channelId]: null },
  })),

  reset: () => {
    draftGeneration += 1;
    for (const timer of saveTimers.values()) clearTimeout(timer);
    saveTimers.clear();
    draftVersions.clear();
    revokedChannels.clear();
    set({ drafts: {}, loadedByChannel: {}, loadingByChannel: {}, errorsByChannel: {} });
  },
}));

function withoutScopes<T>(record: Record<string, T>, channelId: string): Record<string, T> {
  const scopes = Object.keys(record).filter((scope) => belongsToChannel(scope, channelId));
  if (scopes.length === 0) return record;
  const next = { ...record };
  for (const scope of scopes) delete next[scope];
  return next;
}
