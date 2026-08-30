import { create } from 'zustand';
import type { UserStatusType } from '@alparts/shared';

interface PresenceState {
  statuses: Record<string, UserStatusType>;
  typingUsers: Record<string, Record<string, boolean>>; // channelId -> userId -> isTyping

  setStatus: (userId: string, status: UserStatusType) => void;
  setTyping: (channelId: string, userId: string, isTyping: boolean) => void;
  clearChannel: (channelId: string) => void;
  reset: () => void;
}

export const usePresenceStore = create<PresenceState>((set) => ({
  statuses: {},
  typingUsers: {},

  setStatus: (userId, status) => {
    set(state => ({
      statuses: { ...state.statuses, [userId]: status },
    }));
  },

  setTyping: (channelId, userId, isTyping) => {
    set(state => {
      const channelTyping = { ...state.typingUsers[channelId] };
      if (isTyping) channelTyping[userId] = true;
      else delete channelTyping[userId];

      const typingUsers = { ...state.typingUsers };
      if (Object.keys(channelTyping).length > 0) typingUsers[channelId] = channelTyping;
      else delete typingUsers[channelId];
      return { typingUsers };
    });
  },

  clearChannel: (channelId) => set((state) => {
    if (!(channelId in state.typingUsers)) return state;
    const typingUsers = { ...state.typingUsers };
    delete typingUsers[channelId];
    return { typingUsers };
  }),

  reset: () => set({ statuses: {}, typingUsers: {} }),
}));
