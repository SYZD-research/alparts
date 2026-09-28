import { afterEach, beforeEach, expect, it, vi } from 'vitest';
const dependencies = vi.hoisted(() => ({ login: vi.fn(), logout: vi.fn(), device: vi.fn(), connect: vi.fn(), reset: vi.fn() }));
vi.mock('../services/api', () => ({ api: { login: dependencies.login, logout: dependencies.logout, setUnauthorizedHandler: vi.fn() } }));
vi.mock('../services/passkey.service', () => ({ loginWithPasskey: dependencies.login }));
vi.mock('../services/crypto.service', () => ({ ensureDeviceSession: dependencies.device, clearActiveDevice: vi.fn() }));
vi.mock('../services/socket', () => ({ connectSocket: dependencies.connect, disconnectSocket: vi.fn(), setSocketUnauthorizedHandler: vi.fn() }));
vi.mock('./reset', () => ({ resetAuthenticatedState: dependencies.reset }));
import { useAuthStore } from './auth.store';

beforeEach(() => { vi.clearAllMocks(); dependencies.logout.mockResolvedValue(undefined); dependencies.device.mockResolvedValue({ approved: true }); });
afterEach(async () => { await useAuthStore.getState().logout(); });
it.each(['login', 'loginPasskey'] as const)('does not revive authentication after a late %s response', async (method) => {
  let finish!: (value: unknown) => void;
  dependencies.login.mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
  const loggingIn = method === 'login' ? useAuthStore.getState().login('alice', 'password') : useAuthStore.getState().loginPasskey();
  await Promise.resolve();
  const loggingOut = useAuthStore.getState().logout();
  expect(useAuthStore.getState().user).toBeNull();
  expect(dependencies.logout).not.toHaveBeenCalled();
  finish({ user: { id: 'alice' } });
  await Promise.all([loggingIn, loggingOut]);
  expect(dependencies.device).not.toHaveBeenCalled();
  expect(dependencies.connect).not.toHaveBeenCalled();
  expect(dependencies.logout).toHaveBeenCalledOnce();
  expect(useAuthStore.getState().isLoading).toBe(false);
});
