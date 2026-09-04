import { create } from 'zustand';
import type { User } from '@alparts/shared';
import { api, ApiError } from '../services/api';
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

let authenticationGeneration = 0;

async function initializeAuthenticatedClient(user: User, stepUpPassword?: string): Promise<void> {
  await ensureDeviceSession(user, stepUpPassword);
  connectSocket();
}

function authErrorMessage(error: unknown, action: 'login' | 'register'): string {
  if (error instanceof ApiError) {
    if (error.code === 'UNAUTHORIZED') return 'メールアドレスまたはパスワードが正しくありません。';
    if (error.code === 'INVITE_REQUIRED') return '招待コードが正しくないか、有効期限が切れています。';
    if (error.code === 'SESSION_LIMIT_REACHED') return 'ログイン中の端末が上限に達しています。別の端末からログアウトしてお試しください。';
    if (error.code === 'DEVICE_LIMIT_REACHED') return '登録済みの端末が上限に達しています。不要な端末の登録を解除してください。';
    if (error.code === 'WORKSPACE_MEMBER_LIMIT') return 'このワークスペースは参加人数の上限に達しています。';
    if (error.code === 'VALIDATION') {
      return action === 'register'
        ? '入力内容を確認してください。パスワードは12文字以上必要です。'
        : 'メールアドレスとパスワードを確認してください。';
    }
  }
  return action === 'register'
    ? 'アカウントを作成できませんでした。もう一度お試しください。'
    : 'ログインできませんでした。もう一度お試しください。';
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
      set({ user: null, error: authErrorMessage(error, 'login'), isLoading: false, isInitialized: true });
      throw error;
    }
  },

  register: async (email, password, displayName, inviteToken) => {
    set({ isLoading: true, error: null });
    try {
      await api.register(email, password, displayName, inviteToken);
      await get().login(email, password);
    } catch (error) {
      set({ error: authErrorMessage(error, 'register'), isLoading: false, isInitialized: true });
      throw error;
    }
  },

  logout: async () => {
    authenticationGeneration += 1;
    await api.logout().catch(() => undefined);
    disconnectSocket();
    clearActiveDevice();
    resetAuthenticatedState();
    set({ user: null, error: null, isInitialized: true });
  },

  loadUser: async () => {
    const generation = authenticationGeneration;
    set({ isLoading: true });
    try {
      const user = await api.getMe();
      if (generation !== authenticationGeneration) return;
      if (get().user?.id && get().user?.id !== user.id) {
        clearActiveDevice();
        resetAuthenticatedState();
      }
      await initializeAuthenticatedClient(user);
      if (generation !== authenticationGeneration) {
        disconnectSocket();
        clearActiveDevice();
        resetAuthenticatedState();
        return;
      }
      set({ user, isLoading: false, isInitialized: true });
    } catch {
      disconnectSocket();
      clearActiveDevice();
      resetAuthenticatedState();
      set({ user: null, isLoading: false, isInitialized: true });
    }
  },
}));

/** Clear decrypted state without ending the durable server session. */
export function lockAuthenticatedClient(): User | null {
  const user = useAuthStore.getState().user;
  authenticationGeneration += 1;
  disconnectSocket();
  clearActiveDevice();
  resetAuthenticatedState();
  useAuthStore.setState({ user: null, isLoading: false, isInitialized: true, error: null });
  return user;
}

/** Re-open a locally locked desktop session after checking the account password. */
export async function unlockAuthenticatedClient(expectedUser: User | null, password: string): Promise<User> {
  const generation = authenticationGeneration;
  const user = await api.reauthenticate(password);
  if (
    generation !== authenticationGeneration
    || (expectedUser !== null && user.id !== expectedUser.id)
  ) throw new Error('UNLOCK_SESSION_CHANGED');
  await initializeAuthenticatedClient(user, password);
  if (generation !== authenticationGeneration) {
    disconnectSocket();
    clearActiveDevice();
    resetAuthenticatedState();
    throw new Error('UNLOCK_SESSION_CHANGED');
  }
  useAuthStore.setState({ user, isLoading: false, isInitialized: true, error: null });
  return user;
}

function invalidateExpiredSession(): void {
  authenticationGeneration += 1;
  disconnectSocket();
  clearActiveDevice();
  resetAuthenticatedState();
  useAuthStore.setState({
    user: null,
    isLoading: false,
    isInitialized: true,
    error: 'ログインの有効期限が切れました。もう一度ログインしてください。',
  });
}

api.setUnauthorizedHandler(invalidateExpiredSession);
setSocketUnauthorizedHandler(invalidateExpiredSession);
