import { beforeEach, expect, it, vi } from 'vitest';

const api = vi.hoisted(() => ({
  requestRegistrationCode: vi.fn(),
  register: vi.fn(),
  login: vi.fn(),
  logout: vi.fn(),
  setUnauthorizedHandler: vi.fn(),
}));
vi.mock('../services/api', () => ({ api }));
vi.mock('../services/passkey.service', () => ({ loginWithPasskey: vi.fn() }));
vi.mock('../services/crypto.service', () => ({ ensureDeviceSession: vi.fn(async () => ({ approved: false })), clearActiveDevice: vi.fn() }));
vi.mock('../services/socket', () => ({ connectSocket: vi.fn(), disconnectSocket: vi.fn(), setSocketUnauthorizedHandler: vi.fn() }));
vi.mock('./reset', () => ({ resetAuthenticatedState: vi.fn() }));
const { useAuthStore } = await import('./auth.store');

beforeEach(() => {
  vi.clearAllMocks();
  api.register.mockResolvedValue({ id: 'new-user' });
  api.login.mockResolvedValue({ user: { id: 'new-user' } });
});

it('mails a code first and creates the account only with it', async () => {
  api.requestRegistrationCode.mockResolvedValue({ required: true });
  const store = useAuthStore.getState();

  expect(await store.register('new@example.test', 'long-enough-password', 'New', 'invite')).toBe('code-sent');
  expect(api.requestRegistrationCode).toHaveBeenCalledWith('new@example.test', 'invite');
  expect(api.register).not.toHaveBeenCalled();
  expect(useAuthStore.getState().isLoading).toBe(false);

  expect(await store.register('new@example.test', 'long-enough-password', 'New', 'invite', '123456')).toBe('registered');
  expect(api.register).toHaveBeenCalledWith('new@example.test', 'long-enough-password', 'New', 'invite', '123456');
  expect(api.requestRegistrationCode).toHaveBeenCalledTimes(1);
});

it('registers at once when the server asks for no code', async () => {
  api.requestRegistrationCode.mockResolvedValue({ required: false });
  expect(await useAuthStore.getState().register('new@example.test', 'long-enough-password', 'New', 'invite')).toBe('registered');
  expect(api.register).toHaveBeenCalledWith('new@example.test', 'long-enough-password', 'New', 'invite', undefined);
});
