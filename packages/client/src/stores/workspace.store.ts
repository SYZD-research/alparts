import { create } from 'zustand';
import { api } from '../services/api';
import type { Workspace, Category } from '@alparts/shared';

interface WorkspaceState {
  workspaces: Workspace[];
  activeWorkspaceId: string | null;
  categories: Category[];
  members: any[];
  isLoading: boolean;

  loadWorkspaces: () => Promise<void>;
  setActiveWorkspace: (id: string) => Promise<void>;
  createWorkspace: (name: string) => Promise<void>;
  loadCategories: (workspaceId: string) => Promise<void>;
  loadMembers: (workspaceId: string) => Promise<void>;
  createCategory: (workspaceId: string, name: string) => Promise<void>;
}

export const useWorkspaceStore = create<WorkspaceState>((set, get) => ({
  workspaces: [],
  activeWorkspaceId: null,
  categories: [],
  members: [],
  isLoading: false,

  loadWorkspaces: async () => {
    set({ isLoading: true });
    try {
      const workspaces = await api.getWorkspaces();
      set({ workspaces, isLoading: false });
    } catch {
      set({ isLoading: false });
    }
  },

  setActiveWorkspace: async (id) => {
    set({ activeWorkspaceId: id });
    await Promise.all([
      get().loadCategories(id),
      get().loadMembers(id),
    ]);
  },

  createWorkspace: async (name) => {
    const workspace = await api.createWorkspace(name);
    set(state => ({ workspaces: [...state.workspaces, workspace] }));
  },

  loadCategories: async (workspaceId) => {
    try {
      const categories = await api.getCategories(workspaceId);
      set({ categories });
    } catch {
      // ignore
    }
  },

  loadMembers: async (workspaceId) => {
    try {
      const members = await api.getWorkspaceMembers(workspaceId);
      set({ members });
    } catch {
      // ignore
    }
  },

  createCategory: async (workspaceId, name) => {
    await api.createCategory(workspaceId, name);
    await get().loadCategories(workspaceId);
  },
}));
