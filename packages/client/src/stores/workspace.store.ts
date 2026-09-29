import { create } from 'zustand';
import { api } from '../services/api';
import type { Workspace, Category, WorkspaceMember } from '@alparts/shared';
import { useChannelStore } from './channel.store';
import { useMessageStore } from './message.store';
import { usePresenceStore } from './presence.store';
import type { WarnedUsers } from './profile-visibility';

interface WorkspaceState {
  workspaces: Workspace[];
  activeWorkspaceId: string | null;
  categories: Category[];
  members: WorkspaceMember[];
  warnedUsers: WarnedUsers | null;
  isLoading: boolean;
  error: string | null;

  /** Null means this request failed or was superseded before it could apply. */
  loadWorkspaces: () => Promise<Workspace[] | null>;
  setActiveWorkspace: (id: string) => Promise<void>;
  createWorkspace: (name: string) => Promise<void>;
  loadCategories: (workspaceId: string) => Promise<void>;
  loadMembers: (workspaceId: string) => Promise<void>;
  createCategory: (workspaceId: string, name: string) => Promise<void>;
  removeWorkspace: (workspaceId: string) => void;
  reset: () => void;
}

let workspaceListGeneration = 0;
let workspaceSelectionGeneration = 0;
let listLoading = false;
let selectionLoading = false;

export const useWorkspaceStore = create<WorkspaceState>((set, get) => ({
  workspaces: [],
  activeWorkspaceId: null,
  categories: [],
  members: [],
  warnedUsers: null,
  isLoading: false,
  error: null,

  loadWorkspaces: async () => {
    const generation = ++workspaceListGeneration;
    listLoading = true;
    set({ isLoading: true, error: null });
    try {
      const workspaces = await api.getWorkspaces();
      if (generation !== workspaceListGeneration) return null;
      listLoading = false;
      set({ workspaces, isLoading: selectionLoading });
      return workspaces;
    } catch (error) {
      if (generation === workspaceListGeneration) {
        // Preserve the last validated list on transient refresh failures. The
        // caller can fail closed using `error` without converting a network
        // outage into a false membership revocation.
        listLoading = false;
        set({ isLoading: selectionLoading, error: error instanceof Error ? error.message : 'ワークスペースを読み込めませんでした' });
      }
      return null;
    }
  },

  setActiveWorkspace: async (id) => {
    const currentChannels = useChannelStore.getState();
    if (
      get().activeWorkspaceId === id
      && currentChannels.workspaceId === id
      && currentChannels.channels.length > 0
    ) return;
    const generation = ++workspaceSelectionGeneration;
    selectionLoading = true;
    useMessageStore.getState().reset();
    useChannelStore.getState().reset();
    set({ activeWorkspaceId: id, categories: [], members: [], warnedUsers: null, isLoading: true, error: null });

    try {
      const [categories, members, channels] = await Promise.all([
        api.getCategories(id),
        api.getWorkspaceMembers(id),
        useChannelStore.getState().loadChannels(id),
      ]);
      if (generation !== workspaceSelectionGeneration || get().activeWorkspaceId !== id) return;

      selectionLoading = false;
      set({ categories, members, isLoading: listLoading });
      const firstChannel = channels?.find((channel) => channel.type !== 'voice') ?? null;
      useChannelStore.getState().setActiveChannel(firstChannel?.id ?? null);
    } catch (error) {
      if (generation !== workspaceSelectionGeneration || get().activeWorkspaceId !== id) return;
      useChannelStore.getState().reset();
      selectionLoading = false;
      set({ categories: [], members: [], warnedUsers: null, isLoading: listLoading, error: error instanceof Error ? error.message : 'ワークスペースを読み込めませんでした' });
    }
  },

  createWorkspace: async (name) => {
    const workspace = await api.createWorkspace(name);
    set(state => ({ workspaces: [...state.workspaces, workspace] }));
  },

  loadCategories: async (workspaceId) => {
    const generation = workspaceSelectionGeneration;
    try {
      const categories = await api.getCategories(workspaceId);
      if (generation === workspaceSelectionGeneration && get().activeWorkspaceId === workspaceId) set({ categories });
    } catch (error) {
      if (generation === workspaceSelectionGeneration && get().activeWorkspaceId === workspaceId) {
        set({ error: error instanceof Error ? error.message : 'カテゴリーを読み込めませんでした' });
      }
    }
  },

  loadMembers: async (workspaceId) => {
    const generation = workspaceSelectionGeneration;
    try {
      const [members, warned] = await Promise.all([
        api.getWorkspaceMembers(workspaceId),
        api.getWarnedUsers(workspaceId).catch(() => null),
      ]);
      if (generation === workspaceSelectionGeneration && get().activeWorkspaceId === workspaceId) {
        set({ members, warnedUsers: warned ? { ids: new Set(warned.userIds), complete: warned.complete } : null });
        // The list carries each member's current presence; events keep it fresh afterwards.
        usePresenceStore.getState().seedStatuses(
          Object.fromEntries(members.map((member) => [member.userId, member.user.status ?? 'offline'])),
        );
      }
    } catch (error) {
      if (generation === workspaceSelectionGeneration && get().activeWorkspaceId === workspaceId) {
        set({ error: error instanceof Error ? error.message : 'メンバーを読み込めませんでした' });
      }
    }
  },

  createCategory: async (workspaceId, name) => {
    await api.createCategory(workspaceId, name);
    await get().loadCategories(workspaceId);
  },

  removeWorkspace: (workspaceId) => {
    // A list request started before direct revocation must not re-add this
    // workspace when its stale response arrives.
    workspaceListGeneration += 1;
    listLoading = false;
    const wasActive = get().activeWorkspaceId === workspaceId;
    if (wasActive) {
      workspaceSelectionGeneration += 1;
      selectionLoading = false;
    }
    set((state) => ({
      workspaces: state.workspaces.filter((workspace) => workspace.id !== workspaceId),
      isLoading: selectionLoading,
      ...(wasActive ? {
        activeWorkspaceId: null,
        categories: [],
        members: [],
        warnedUsers: null,
        isLoading: false,
        error: null,
      } : {}),
    }));
    if (wasActive) {
      useMessageStore.getState().reset();
      useChannelStore.getState().reset();
    }
  },

  reset: () => {
    workspaceListGeneration += 1;
    workspaceSelectionGeneration += 1;
    listLoading = false;
    selectionLoading = false;
    set({ workspaces: [], activeWorkspaceId: null, categories: [], members: [], warnedUsers: null, isLoading: false, error: null });
  },
}));
