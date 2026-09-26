import { create } from 'zustand';
import { api } from '../services/api';
import type { Channel } from '@alparts/shared';
import { restoreChannelKeyScope } from '../services/crypto.service';
import { useDraftStore } from './draft.store';

interface ChannelState {
  activeChannelId: string | null;
  workspaceId: string | null;
  setActiveChannel: (id: string | null) => void;
  channels: Channel[];
  error: string | null;
  loadChannels: (workspaceId: string) => Promise<Channel[] | null>;
  createChannel: (workspaceId: string, name: string, options?: {
    categoryId?: string;
    isPrivate?: boolean;
    type?: 'text' | 'announcement' | 'voice';
  }) => Promise<void>;
  removeChannel: (channelId: string, workspaceId?: string) => void;
  reset: () => void;
}

let channelRequestGeneration = 0;
let channelRequestWorkspaceId: string | null = null;

export const useChannelStore = create<ChannelState>((set) => ({
  activeChannelId: null,
  workspaceId: null,
  channels: [],
  error: null,

  setActiveChannel: (id) => {
    set((state) => {
      if (id === null) return { activeChannelId: null };
      const channel = state.channels.find((candidate) => candidate.id === id);
      return channel && isMessageChannel(channel) ? { activeChannelId: id } : state;
    });
  },

  loadChannels: async (workspaceId) => {
    const generation = ++channelRequestGeneration;
    channelRequestWorkspaceId = workspaceId;
    try {
      const channels = await api.getChannels(workspaceId);
      if (generation === channelRequestGeneration) {
        await Promise.all(channels.map((channel) => restoreChannelKeyScope(channel.id)));
        if (generation !== channelRequestGeneration) return null;
        await Promise.all(channels.map((channel) => useDraftStore.getState().restoreChannel(channel.id)));
        if (generation !== channelRequestGeneration) return null;
        set((state) => {
          const activeStillVisible = state.workspaceId === workspaceId
            && Boolean(state.activeChannelId)
            && channels.some((channel) => channel.id === state.activeChannelId);
          const firstChannel = channels.find(isMessageChannel) ?? null;
          return {
            channels,
            workspaceId,
            activeChannelId: activeStillVisible ? state.activeChannelId : firstChannel?.id ?? null,
            error: null,
          };
        });
        channelRequestWorkspaceId = null;
        return channels;
      }
      // Never expose an authorization list that was invalidated by a direct
      // revoke/removal while the request was in flight.
      return null;
    } catch {
      if (generation === channelRequestGeneration) {
        channelRequestWorkspaceId = null;
        set({ error: 'チャンネルを読み込めませんでした。接続を確認して再度お試しください。' });
      }
      return null;
    }
  },

  createChannel: async (workspaceId, name, options) => {
    await api.createChannel(workspaceId, name, options);
    await useChannelStore.getState().loadChannels(workspaceId);
  },

  removeChannel: (channelId, workspaceId) => {
    const current = useChannelStore.getState();
    if (
      workspaceId === undefined
      || current.workspaceId === workspaceId
      || channelRequestWorkspaceId === workspaceId
    ) {
      channelRequestGeneration += 1;
      channelRequestWorkspaceId = null;
    }
    set((state) => {
      const channels = state.channels.filter((channel) => channel.id !== channelId);
      const nextActive = state.activeChannelId === channelId
        ? (channels.find(isMessageChannel) ?? null)?.id ?? null
        : state.activeChannelId;
      return { channels, activeChannelId: nextActive };
    });
  },

  reset: () => {
    channelRequestGeneration += 1;
    channelRequestWorkspaceId = null;
    set({ activeChannelId: null, workspaceId: null, channels: [], error: null });
  },
}));

function isMessageChannel(channel: Channel): boolean {
  return channel.type !== 'voice';
}
