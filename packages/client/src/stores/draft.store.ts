import { create } from 'zustand';
import { deleteLocalDraft, loadLocalDraft, saveLocalDraft } from '../services/local-state.service';

interface DraftState {
  drafts: Record<string, string>;
  loadedByChannel: Record<string, boolean>;
  loadingByChannel: Record<string, boolean>;
  errorsByChannel: Record<string, string | null>;
  loadDraft: (channelId: string) => Promise<void>;
  setDraft: (channelId: string, content: string) => void;
  clearDraft: (channelId: string) => Promise<void>;
  clearChannel: (channelId: string) => Promise<void>;
  clearError: (channelId: string) => void;
  reset: () => void;
}

const SAVE_DELAY_MS = 300;
const saveTimers = new Map<string, ReturnType<typeof setTimeout>>();
const persistQueues = new Map<string, Promise<void>>();
const draftVersions = new Map<string, number>();
let draftGeneration = 0;

function errorMessage(error: unknown): string {
  return error instanceof Error && error.message
    ? error.message
    : '暗号化した下書きを端末へ保存できませんでした';
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
  const previous = persistQueues.get(channelId) || Promise.resolve();
  const next = previous.catch(() => undefined).then(async () => {
    if (generation !== draftGeneration) return;
    await operation();
  });
  persistQueues.set(channelId, next);
  void next.catch(onError).finally(() => {
    if (persistQueues.get(channelId) === next) persistQueues.delete(channelId);
  });
  return next.catch(() => undefined);
}

export const useDraftStore = create<DraftState>((set, get) => ({
  drafts: {},
  loadedByChannel: {},
  loadingByChannel: {},
  errorsByChannel: {},

  loadDraft: async (channelId) => {
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
      if (generation !== draftGeneration) return;
      set((state) => ({
        loadedByChannel: { ...state.loadedByChannel, [channelId]: true },
        loadingByChannel: { ...state.loadingByChannel, [channelId]: false },
        errorsByChannel: { ...state.errorsByChannel, [channelId]: errorMessage(error) },
      }));
    }
  },

  setDraft: (channelId, content) => {
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
        () => content ? saveLocalDraft(channelId, content) : deleteLocalDraft(channelId),
        (error) => {
          if (generation === draftGeneration) {
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
    const generation = draftGeneration;
    nextDraftVersion(channelId);
    const timer = saveTimers.get(channelId);
    if (timer) clearTimeout(timer);
    saveTimers.delete(channelId);
    set((state) => ({
      drafts: withoutChannel(state.drafts, channelId),
      loadedByChannel: withoutChannel(state.loadedByChannel, channelId),
      loadingByChannel: withoutChannel(state.loadingByChannel, channelId),
      errorsByChannel: withoutChannel(state.errorsByChannel, channelId),
    }));
    // This delete is serialized after any already-running save for the same
    // channel, so the final persistent state is absent even during a race.
    await queuePersistence(channelId, generation, () => deleteLocalDraft(channelId), () => undefined);
  },

  clearError: (channelId) => set((state) => ({
    errorsByChannel: { ...state.errorsByChannel, [channelId]: null },
  })),

  reset: () => {
    draftGeneration += 1;
    for (const timer of saveTimers.values()) clearTimeout(timer);
    saveTimers.clear();
    persistQueues.clear();
    draftVersions.clear();
    set({ drafts: {}, loadedByChannel: {}, loadingByChannel: {}, errorsByChannel: {} });
  },
}));

function withoutChannel<T>(record: Record<string, T>, channelId: string): Record<string, T> {
  if (!(channelId in record)) return record;
  const next = { ...record };
  delete next[channelId];
  return next;
}
