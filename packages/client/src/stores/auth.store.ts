import { loginWithPasskey } from '../services/passkey.service';
import { create } from 'zustand';
import type { User } from '@alparts/shared';
import { api } from '../services/api';
import { getDesktopBridge } from '../services/desktop.service';
import { clearActiveDevice, ensureDeviceSession } from '../services/crypto.service';
import { connectSocket, disconnectSocket, setSocketUnauthorizedHandler } from '../services/socket';
import { resetAuthenticatedState } from './reset';
import { authErrorMessage } from './auth-error';

interface AuthState {
  user: User | null;
  isLoading: boolean;
  isInitialized: boolean;
  error: string | null;
  loginPasskey: () => Promise<void>;
  login: (email: string, password: string) => Promise<void>;
  /** Without emailCode, mails a code first; resolves 'code-sent' when one is needed. */
  register: (email: string, password: string, displayName: string, inviteToken: string, emailCode?: string) => Promise<'code-sent' | 'registered'>;
  logout: () => Promise<void>;
  loadUser: () => Promise<void>;
}

let authenticationGeneration = 0;
let authenticationTransport = Promise.resolve();
function serializeAuthentication<T>(operation: () => Promise<T>): Promise<T> {
  const next = authenticationTransport.then(operation, operation);
  authenticationTransport = next.then(() => undefined, () => undefined);
  return next;
}

async function initializeAuthenticatedClient(user: User, generation: number, stepUpPassword?: string): Promise<void> {
  const device = await ensureDeviceSession(user, stepUpPassword);
  if (generation !== authenticationGeneration) throw new Error('AUTHENTICATION_CHANGED');
  if (device.approved) {
    connectSocket();
    // Best effort: history backups that failed earlier are retried in the background.
    void import('../services/recovery.service')
      .then(({ retryPendingHistoryBackups }) => retryPendingHistoryBackups())
      .catch(() => undefined);
  }
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  isLoading: false,
  isInitialized: false,
  error: null,

  login: async (email, password) => {
    const generation = ++authenticationGeneration;
    set({ isLoading: true, error: null });
    try {
      const result = await serializeAuthentication(() => api.login(email, password));
      if (generation !== authenticationGeneration) return;
      if (get().user?.id && get().user?.id !== result.user.id) {
        clearActiveDevice();
        resetAuthenticatedState();
      }
      await initializeAuthenticatedClient(result.user, generation, password);
      set({ user: result.user, isLoading: false, isInitialized: true });
    } catch (error) {
      if (generation !== authenticationGeneration) return;
      await serializeAuthentication(() => api.logout()).catch(() => undefined);
      if (generation !== authenticationGeneration) return;
      disconnectSocket();
      resetAuthenticatedState();
      clearActiveDevice();
      set({ user: null, error: authErrorMessage(error, 'login'), isLoading: false, isInitialized: true });
      throw error;
    }
  },

  loginPasskey: async () => {
    const generation = ++authenticationGeneration;
    set({ isLoading: true, error: null });
    try {
      const result = await serializeAuthentication(loginWithPasskey);
      if (generation !== authenticationGeneration) return;
      clearActiveDevice(); resetAuthenticatedState();
      await initializeAuthenticatedClient(result.user, generation);
      set({ user: result.user, isLoading: false, isInitialized: true });
    } catch (error) {
      if (generation !== authenticationGeneration) return;
      await serializeAuthentication(() => api.logout()).catch(() => undefined);
      if (generation !== authenticationGeneration) return;
      disconnectSocket();
      resetAuthenticatedState();
      clearActiveDevice();
      set({ user: null, error: 'パスキーでログインできませんでした。もう一度お試しください。', isLoading: false, isInitialized: true });
      throw error;
    }
  },

  register: async (email, password, displayName, inviteToken, emailCode) => {
    const generation = authenticationGeneration;
    set({ isLoading: true, error: null });
    try {
      if (!emailCode && (await api.requestRegistrationCode(email, inviteToken)).required) {
        if (generation === authenticationGeneration) set({ isLoading: false });
        return 'code-sent';
      }
      await api.register(email, password, displayName, inviteToken, emailCode);
      if (generation !== authenticationGeneration) return 'registered';
      await get().login(email, password);
      return 'registered';
    } catch (error) {
      if (generation !== authenticationGeneration) throw error;
      set({ error: authErrorMessage(error, 'register'), isLoading: false, isInitialized: true });
      throw error;
    }
  },

  logout: async () => {
    authenticationGeneration += 1;
    disconnectSocket();
    clearActiveDevice();
    resetAuthenticatedState();
    set({ user: null, error: null, isLoading: false, isInitialized: true });
    await serializeAuthentication(() => api.logout()).catch(() => undefined);
    await getDesktopBridge()?.clearHttpCache().catch(() => undefined);
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
      await initializeAuthenticatedClient(user, generation);
      if (generation !== authenticationGeneration) {
        return;
      }
      set({ user, isLoading: false, isInitialized: true });
    } catch {
      if (generation !== authenticationGeneration) return;
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
  await initializeAuthenticatedClient(user, generation, password);
  if (generation !== authenticationGeneration) {
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
    // Expiry and a sign-out from another device look the same here; say both.
    error: 'ログイン状態が終了しました。もう一度ログインしてください。心当たりがない場合は、ログイン後にログイン中の端末を確認してください。',
  });
}

api.setUnauthorizedHandler(invalidateExpiredSession);
setSocketUnauthorizedHandler(invalidateExpiredSession);
