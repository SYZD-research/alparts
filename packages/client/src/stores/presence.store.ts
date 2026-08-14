import { create } from 'zustand';
import type { UserStatusType } from '@alparts/shared';

interface PresenceState {
  statuses: Record<string, UserStatusType>;
  typingUsers: Record<string, Record<string, boolean>>; // channelId -> userId -> isTyping

  setStatus: (userId: string, status: UserStatusType) => void;
  setTyping: (channelId: string, userId: string, isTyping: boolean) => void;
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
    set(state => ({
      typingUsers: {
        ...state.typingUsers,
        [channelId]: {
          ...(state.typingUsers[channelId] || {}),
          [userId]: isTyping,
        },
      },
    }));
  },
}));
