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

const typingTimers = new Map<string, Map<string, ReturnType<typeof setTimeout>>>();
const TYPING_TIMEOUT_MS = 8_000;

export const usePresenceStore = create<PresenceState>((set, get) => ({
  statuses: {},
  typingUsers: {},

  setStatus: (userId, status) => {
    set(state => ({
      statuses: { ...state.statuses, [userId]: status },
    }));
  },

  setTyping: (channelId, userId, isTyping) => {
    const timers = typingTimers.get(channelId) ?? new Map();
    clearTimeout(timers.get(userId));
    timers.delete(userId);
    if (isTyping) timers.set(userId, setTimeout(() => get().setTyping(channelId, userId, false), TYPING_TIMEOUT_MS));
    if (timers.size) typingTimers.set(channelId, timers);
    else typingTimers.delete(channelId);
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

  clearChannel: (channelId) => {
    for (const timer of typingTimers.get(channelId)?.values() ?? []) clearTimeout(timer);
    typingTimers.delete(channelId);
    set((state) => {
    if (!(channelId in state.typingUsers)) return state;
    const typingUsers = { ...state.typingUsers };
    delete typingUsers[channelId];
    return { typingUsers };
    });
  },

  reset: () => {
    for (const timers of typingTimers.values()) for (const timer of timers.values()) clearTimeout(timer);
    typingTimers.clear();
    set({ statuses: {}, typingUsers: {} });
  },
}));
