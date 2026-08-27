import { create } from 'zustand';
import type { User } from '@alparts/shared';
import { api } from '../services/api';
import { clearActiveDevice, ensureDeviceSession } from '../services/crypto.service';
import { connectSocket, disconnectSocket, setSocketUnauthorizedHandler } from '../services/socket';
import { resetAuthenticatedState } from './reset';

interface AuthState {
  user: User | null;
  isLoading: boolean;
  isInitialized: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, displayName: string, inviteToken: string) => Promise<void>;
  logout: () => Promise<void>;
  loadUser: () => Promise<void>;
}

async function initializeAuthenticatedClient(user: User, stepUpPassword?: string): Promise<void> {
  await ensureDeviceSession(user, stepUpPassword);
  connectSocket();
}

function authErrorMessage(error: unknown): string {
  return error instanceof Error && error.message ? error.message : '認証に失敗しました';
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  isLoading: false,
  isInitialized: false,
  error: null,

  login: async (email, password) => {
    set({ isLoading: true, error: null });
    try {
      const result = await api.login(email, password);
      if (get().user?.id && get().user?.id !== result.user.id) {
        clearActiveDevice();
        resetAuthenticatedState();
      }
      await initializeAuthenticatedClient(result.user, password);
      set({ user: result.user, isLoading: false, isInitialized: true });
    } catch (error) {
      await api.logout().catch(() => undefined);
      resetAuthenticatedState();
      clearActiveDevice();
      set({ user: null, error: authErrorMessage(error), isLoading: false, isInitialized: true });
      throw error;
    }
  },

  register: async (email, password, displayName, inviteToken) => {
    set({ isLoading: true, error: null });
    try {
      await api.register(email, password, displayName, inviteToken);
      await get().login(email, password);
    } catch (error) {
      set({ error: authErrorMessage(error), isLoading: false, isInitialized: true });
      throw error;
    }
  },

  logout: async () => {
    await api.logout().catch(() => undefined);
    disconnectSocket();
    clearActiveDevice();
    resetAuthenticatedState();
    set({ user: null, error: null, isInitialized: true });
  },

  loadUser: async () => {
    set({ isLoading: true });
    try {
      const user = await api.getMe();
      if (get().user?.id && get().user?.id !== user.id) {
        clearActiveDevice();
        resetAuthenticatedState();
      }
      await initializeAuthenticatedClient(user);
      set({ user, isLoading: false, isInitialized: true });
    } catch {
      disconnectSocket();
      clearActiveDevice();
      resetAuthenticatedState();
      set({ user: null, isLoading: false, isInitialized: true });
    }
  },
}));

function invalidateExpiredSession(): void {
  disconnectSocket();
  clearActiveDevice();
  resetAuthenticatedState();
  useAuthStore.setState({
    user: null,
    isLoading: false,
    isInitialized: true,
    error: 'セッションの有効期限が切れたか、失効されました。再度ログインしてください。',
  });
}

api.setUnauthorizedHandler(invalidateExpiredSession);
setSocketUnauthorizedHandler(invalidateExpiredSession);
