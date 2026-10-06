import { create } from 'zustand';
import { api, type DirectMessageConversation } from '../services/api';
import { findReusableOneToOneDm } from './dm-model';
import { useWorkspaceStore } from './workspace.store';
import { t } from '../i18n';

interface DmState {
  conversationsByWorkspace: Record<string, DirectMessageConversation[]>;
  loadingByWorkspace: Record<string, boolean>;
  errorsByWorkspace: Record<string, string | null>;
  loadDms: (workspaceId: string) => Promise<DirectMessageConversation[] | null>;
  createOrReuseDm: (
    workspaceId: string,
    currentUserId: string,
    selectedMemberIds: string[],
  ) => Promise<DirectMessageConversation>;
  upsertDm: (conversation: DirectMessageConversation) => void;
  clearError: (workspaceId: string) => void;
  clearWorkspace: (workspaceId: string) => void;
  clearChannel: (channelId: string) => void;
  reset: () => void;
}

let dmGeneration = 0;
const loadVersions = new Map<string, number>();
const creations = new Map<string, Promise<DirectMessageConversation>>();
const workspaceEpochs = new Map<string, number>();
const revokedChannelIds = new Set<string>();

function workspaceEpoch(workspaceId: string): number {
  return workspaceEpochs.get(workspaceId) || 0;
}

function errorMessage(error: unknown): string {
  return error instanceof Error && error.message ? error.message : t('DMを処理できませんでした');
}

function ordered(conversations: DirectMessageConversation[]): DirectMessageConversation[] {
  return [...conversations].sort((left, right) => (
    right.createdAt.localeCompare(left.createdAt)
    || (left.id < right.id ? -1 : left.id > right.id ? 1 : 0)
  ));
}

export const useDmStore = create<DmState>((set, get) => ({
  conversationsByWorkspace: {},
  loadingByWorkspace: {},
  errorsByWorkspace: {},

  loadDms: async (workspaceId) => {
    const generation = dmGeneration;
    const epoch = workspaceEpoch(workspaceId);
    const version = (loadVersions.get(workspaceId) || 0) + 1;
    loadVersions.set(workspaceId, version);
    set((state) => ({
      loadingByWorkspace: { ...state.loadingByWorkspace, [workspaceId]: true },
      errorsByWorkspace: { ...state.errorsByWorkspace, [workspaceId]: null },
    }));
    try {
      const conversations = ordered(await api.getDms(workspaceId));
      if (generation === dmGeneration
        && epoch === workspaceEpoch(workspaceId)
        && loadVersions.get(workspaceId) === version) {
        for (const conversation of conversations) revokedChannelIds.delete(conversation.channelId);
        set((state) => ({
          conversationsByWorkspace: { ...state.conversationsByWorkspace, [workspaceId]: conversations },
          loadingByWorkspace: { ...state.loadingByWorkspace, [workspaceId]: false },
        }));
        return conversations;
      }
      return null;
    } catch (error) {
      if (generation === dmGeneration
        && epoch === workspaceEpoch(workspaceId)
        && loadVersions.get(workspaceId) === version) {
        set((state) => ({
          loadingByWorkspace: { ...state.loadingByWorkspace, [workspaceId]: false },
          errorsByWorkspace: { ...state.errorsByWorkspace, [workspaceId]: errorMessage(error) },
        }));
      }
      return null;
    }
  },

  createOrReuseDm: async (workspaceId, currentUserId, selectedMemberIds) => {
    const memberIds = [...new Set(selectedMemberIds)].filter((id) => id !== currentUserId).sort();
    if (memberIds.length < 1 || memberIds.length > 19) throw new Error(t('1〜19人のメンバーを選択してください'));
    // Refresh immediately before creation so a DM made in another tab/device
    // is reused whenever it is already visible to the server.
    const conversations = await get().loadDms(workspaceId);
    const loadError = get().errorsByWorkspace[workspaceId];
    if (!conversations || loadError) throw new Error(t('DMを確認できませんでした。もう一度お試しください。'));
    if (memberIds.length === 1) {
      const existing = findReusableOneToOneDm(
        conversations,
        currentUserId,
        memberIds[0],
      );
      if (existing) return existing;
    }

    const requestKey = `${workspaceId}:${[currentUserId, ...memberIds].sort().join(':')}`;
    const pending = creations.get(requestKey);
    if (pending) return pending;
    const generation = dmGeneration;
    const epoch = workspaceEpoch(workspaceId);
    const creation = api.createDm(workspaceId, memberIds).then((conversation) => {
      if (generation === dmGeneration && epoch === workspaceEpoch(workspaceId)) get().upsertDm(conversation);
      return conversation;
    }).catch((error) => {
      if (generation === dmGeneration && epoch === workspaceEpoch(workspaceId)) {
        set((state) => ({ errorsByWorkspace: { ...state.errorsByWorkspace, [workspaceId]: errorMessage(error) } }));
      }
      throw error;
    }).finally(() => {
      if (creations.get(requestKey) === creation) creations.delete(requestKey);
    });
    creations.set(requestKey, creation);
    return creation;
  },

  upsertDm: (conversation) => set((state) => {
    if (revokedChannelIds.has(conversation.channelId)
      || !useWorkspaceStore.getState().workspaces.some((workspace) => workspace.id === conversation.workspaceId)) {
      return state;
    }
    const current = state.conversationsByWorkspace[conversation.workspaceId] || [];
    const conversations = ordered([
      ...current.filter((candidate) => candidate.id !== conversation.id),
      conversation,
    ]);
    return {
      conversationsByWorkspace: {
        ...state.conversationsByWorkspace,
        [conversation.workspaceId]: conversations,
      },
    };
  }),

  clearError: (workspaceId) => set((state) => ({
    errorsByWorkspace: { ...state.errorsByWorkspace, [workspaceId]: null },
  })),

  clearWorkspace: (workspaceId) => {
    workspaceEpochs.set(workspaceId, workspaceEpoch(workspaceId) + 1);
    loadVersions.set(workspaceId, (loadVersions.get(workspaceId) || 0) + 1);
    for (const key of creations.keys()) {
      if (key.startsWith(`${workspaceId}:`)) creations.delete(key);
    }
    set((state) => ({
      conversationsByWorkspace: withoutWorkspace(state.conversationsByWorkspace, workspaceId),
      loadingByWorkspace: withoutWorkspace(state.loadingByWorkspace, workspaceId),
      errorsByWorkspace: withoutWorkspace(state.errorsByWorkspace, workspaceId),
    }));
  },

  clearChannel: (channelId) => {
    revokedChannelIds.add(channelId);
    set((state) => ({
      conversationsByWorkspace: Object.fromEntries(Object.entries(state.conversationsByWorkspace)
        .map(([workspaceId, conversations]) => [
          workspaceId,
          conversations.filter((conversation) => conversation.channelId !== channelId),
        ])),
    }));
  },

  reset: () => {
    dmGeneration += 1;
    loadVersions.clear();
    creations.clear();
    workspaceEpochs.clear();
    revokedChannelIds.clear();
    set({ conversationsByWorkspace: {}, loadingByWorkspace: {}, errorsByWorkspace: {} });
  },
}));

function withoutWorkspace<T>(record: Record<string, T>, workspaceId: string): Record<string, T> {
  if (!(workspaceId in record)) return record;
  const next = { ...record };
  delete next[workspaceId];
  return next;
}
