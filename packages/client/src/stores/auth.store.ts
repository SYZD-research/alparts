import { create } from 'zustand';
import { api } from '../services/api';
import { connectSocket, disconnectSocket } from '../services/socket';
import type { User } from '@alparts/shared';

interface AuthState {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, displayName: string) => Promise<void>;
  logout: () => void;
  loadUser: () => Promise<void>;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  token: localStorage.getItem('token'),
  isLoading: false,
  error: null,

  login: async (email, password) => {
    set({ isLoading: true, error: null });
    try {
      const result = await api.login(email, password);
      localStorage.setItem('token', result.token);
      api.setToken(result.token);
      connectSocket(result.token);
      set({ user: result.user, token: result.token, isLoading: false });
    } catch (err: any) {
      set({ error: err.message, isLoading: false });
      throw err;
    }
  },

  register: async (email, password, displayName) => {
    set({ isLoading: true, error: null });
    try {
      await api.register(email, password, displayName);
      // Auto-login after registration
      await get().login(email, password);
    } catch (err: any) {
      set({ error: err.message, isLoading: false });
      throw err;
    }
  },

  logout: () => {
    const token = get().token;
    if (token) {
      api.logout().catch(() => {});
    }
    localStorage.removeItem('token');
    api.setToken(null);
    disconnectSocket();
    set({ user: null, token: null });
  },

  loadUser: async () => {
    const token = get().token;
    if (!token) return;

    set({ isLoading: true });
    try {
      api.setToken(token);
      const user = await api.getMe();
      connectSocket(token);
      set({ user, isLoading: false });
    } catch {
      // Token invalid
      localStorage.removeItem('token');
      api.setToken(null);
      set({ user: null, token: null, isLoading: false });
    }
  },
}));
