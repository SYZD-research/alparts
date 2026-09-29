import { create } from 'zustand';
import type { AttentionNotificationKind, WsAttentionNotification } from '@alparts/shared';
import { attentionNotificationKey } from '../services/attention-model';
import { useUserStateStore } from './user-state.store';

export interface AttentionItem extends WsAttentionNotification {
  receivedAt: number;
}

interface AttentionState {
  items: AttentionItem[];
  add: (notification: WsAttentionNotification) => void;
  dismissKind: (kind: AttentionNotificationKind) => void;
  clearChannel: (channelId: string) => void;
  reset: () => void;
}

const MAX_ATTENTION_ITEMS = 100;

export const useAttentionStore = create<AttentionState>((set, get) => ({
  items: [],

  add: (notification) => {
    const preference = useUserStateStore.getState()
      .channelStatesByWorkspace[notification.workspaceId]?.[notification.channelId];
    const channelNotice = notification.kind === 'channel-restarted';
    if (!channelNotice && (!preference || preference.muted || preference.notificationLevel === 'none')) return;
    const key = attentionNotificationKey(notification);
    if (get().items.some((item) => attentionNotificationKey(item) === key)) return;
    set((state) => ({
      items: [...state.items, { ...notification, receivedAt: Date.now() }].slice(-MAX_ATTENTION_ITEMS),
    }));
  },

  dismissKind: (kind) => set((state) => ({
    items: state.items.filter((item) => item.kind !== kind),
  })),

  clearChannel: (channelId) => set((state) => ({
    items: state.items.filter((item) => item.channelId !== channelId),
  })),

  reset: () => set({ items: [] }),
}));
