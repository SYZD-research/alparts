import { create } from 'zustand';
import { api } from '../services/api';
import type { Channel } from '@alparts/shared';

interface ChannelState {
  activeChannelId: string | null;
  setActiveChannel: (id: string) => void;
  channels: Channel[];
  loadChannels: (workspaceId: string) => Promise<void>;
  createChannel: (workspaceId: string, name: string, options?: { categoryId?: string; isPrivate?: boolean }) => Promise<void>;
}

export const useChannelStore = create<ChannelState>((set) => ({
  activeChannelId: null,
  channels: [],

  setActiveChannel: (id) => {
    set({ activeChannelId: id });
  },

  loadChannels: async (workspaceId) => {
    try {
      const channels = await api.getChannels(workspaceId);
      set({ channels });
    } catch {
      // ignore
    }
  },

  createChannel: async (workspaceId, name, options) => {
    await api.createChannel(workspaceId, name, options);
    await useChannelStore.getState().loadChannels(workspaceId);
  },
}));
