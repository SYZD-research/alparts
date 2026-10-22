import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AlpartsDesktopBridge } from '../types/desktop';

const mocks = vi.hoisted(() => ({
  ensureDeviceSession: vi.fn(),
  clearActiveDevice: vi.fn(),
  connectSocket: vi.fn(),
  disconnectSocket: vi.fn(),
  resetAuthenticatedState: vi.fn(),
}));
vi.mock('../services/crypto.service', () => ({
  ensureDeviceSession: mocks.ensureDeviceSession,
  clearActiveDevice: mocks.clearActiveDevice,
}));
vi.mock('../services/socket', () => ({
  connectSocket: mocks.connectSocket,
  disconnectSocket: mocks.disconnectSocket,
  setSocketUnauthorizedHandler: vi.fn(),
}));
vi.mock('./reset', () => ({ resetAuthenticatedState: mocks.resetAuthenticatedState }));
vi.mock('../services/passkey.service', () => ({ loginWithPasskey: vi.fn() }));

const MARKER = 'alparts.signOutPending';
const USER = { id: 'alice', displayName: 'Alice' };

// What the server does with the one session behind the browser's cookie.
const server = {
  sessionAlive: true,
  login: 'ok' as 'ok' | 'wrong-password',
  logout: 'ok' as 'ok' | 'audit-unavailable' | 'rate-limited' | 'offline',
  requests: [] as string[],
};

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

function installServer(): void {
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const request = `${init?.method ?? 'GET'} ${url}`;
    server.requests.push(request);
    if (request === 'POST /api/auth/logout') {
      if (server.logout === 'offline') throw new TypeError('Failed to fetch');
      if (server.logout === 'audit-unavailable') return json(503, { error: 'AUDIT_UNAVAILABLE' });
      if (server.logout === 'rate-limited') return json(429, { error: 'RATE_LIMITED' });
      if (!server.sessionAlive) return json(401, { error: 'UNAUTHORIZED' });
      server.sessionAlive = false;
      return json(200, { success: true });
    }
    if (request === 'GET /api/auth/me') return server.sessionAlive ? json(200, USER) : json(401, { error: 'UNAUTHORIZED' });
    if (request === 'POST /api/auth/login') {
      if (server.login === 'wrong-password') return json(401, { error: 'UNAUTHORIZED' });
      server.sessionAlive = true;
      return json(200, { user: USER });
    }
    throw new Error(`unexpected request ${request}`);
  }));
}

// Like a browser's storage: kept across a restart, unlike the page's memory.
function installStorage(): Map<string, string> {
  const stored = new Map<string, string>();
  vi.stubGlobal('localStorage', {
    getItem: (key: string) => stored.get(key) ?? null,
    setItem: (key: string, value: string) => void stored.set(key, value),
    removeItem: (key: string) => void stored.delete(key),
  });
  return stored;
}

function installDesktopBridge() {
  const clearHttpCache = vi.fn(async () => true);
  // The language store listens for language changes on the window.
  vi.stubGlobal('window', {
    addEventListener: vi.fn(),
    alpartsDesktop: { clearHttpCache } as unknown as AlpartsDesktopBridge,
  });
  return clearHttpCache;
}

// A fresh page: every module starts over, only the storage and the server remain.
async function startApp() {
  vi.resetModules();
  (await import('../i18n')).useLocaleStore.setState({ preference: 'ja', locale: 'ja' });
  const { useAuthStore } = await import('./auth.store');
  await useAuthStore.getState().loadUser();
  return useAuthStore;
}

let stored: Map<string, string>;

beforeEach(() => {
  server.sessionAlive = true;
  server.login = 'ok';
  server.logout = 'ok';
  server.requests = [];
  vi.clearAllMocks();
  mocks.ensureDeviceSession.mockResolvedValue({ approved: true });
  stored = installStorage();
  installServer();
  vi.stubGlobal('navigator', { platform: 'Linux', userAgent: 'test', language: 'ja-JP', languages: ['ja-JP'] });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('sign-out the server does not confirm', () => {
  it.each(['audit-unavailable', 'rate-limited', 'offline'] as const)(
    'keeps the sign-out pending and says so when the request fails (%s)',
    async (failure) => {
      const store = await startApp();
      expect(store.getState().user).toEqual(USER);
      server.logout = failure;
      server.requests = [];

      await store.getState().logout();

      expect(server.requests).toEqual(['POST /api/auth/logout']);
      expect(store.getState().user).toBeNull();
      expect(store.getState().error).toContain('ログアウトを完了できませんでした');
      expect(stored.get(MARKER)).toBe('1');
      // The server still has the session, and so does the cookie.
      expect(server.sessionAlive).toBe(true);
    },
  );

  it('does not resume the account when the app starts again', async () => {
    const first = await startApp();
    server.logout = 'offline';
    await first.getState().logout();

    // The server answers again but still cannot end the session, which is still valid.
    server.logout = 'audit-unavailable';
    server.requests = [];
    const restarted = await startApp();

    expect(server.requests).toEqual(['POST /api/auth/logout']);
    expect(server.sessionAlive).toBe(true);
    expect(restarted.getState().user).toBeNull();
    expect(restarted.getState().isInitialized).toBe(true);
    expect(restarted.getState().isLoading).toBe(false);
    expect(restarted.getState().error).toContain('ログアウトを完了できませんでした');
    expect(stored.get(MARKER)).toBe('1');
    expect(mocks.ensureDeviceSession).toHaveBeenCalledTimes(1);
  });

  it('finishes the sign-out at the next start and then clears the marker', async () => {
    const first = await startApp();
    server.logout = 'offline';
    await first.getState().logout();

    server.logout = 'ok';
    server.requests = [];
    const restarted = await startApp();

    // The sign-out comes first; the probe afterwards finds no session.
    expect(server.requests).toEqual(['POST /api/auth/logout', 'GET /api/auth/me']);
    expect(server.sessionAlive).toBe(false);
    expect(restarted.getState().user).toBeNull();
    expect(restarted.getState().error).toBeNull();
    expect(stored.has(MARKER)).toBe(false);

    // Nothing is pending any more, so the following start only probes.
    server.requests = [];
    await startApp();
    expect(server.requests).toEqual(['GET /api/auth/me']);
  });

  it('counts a session the server no longer knows as signed out', async () => {
    const first = await startApp();
    server.logout = 'offline';
    await first.getState().logout();

    server.sessionAlive = false;
    server.logout = 'ok';
    server.requests = [];
    const restarted = await startApp();

    expect(restarted.getState().user).toBeNull();
    // Not the message for a login that ended on its own.
    expect(restarted.getState().error).toBeNull();
    expect(stored.has(MARKER)).toBe(false);
  });

  it('lets a new sign-in replace the pending one', async () => {
    const first = await startApp();
    server.logout = 'offline';
    await first.getState().logout();
    expect(stored.get(MARKER)).toBe('1');

    await first.getState().login('alice@example.test', 'long-enough-password');
    expect(first.getState().user).toEqual(USER);
    expect(stored.has(MARKER)).toBe(false);

    // The next start resumes the new session instead of signing it out.
    server.logout = 'ok';
    server.requests = [];
    const restarted = await startApp();
    expect(server.requests).toEqual(['GET /api/auth/me']);
    expect(restarted.getState().user).toEqual(USER);
  });

  it('does not treat a failed sign-in attempt as a sign-out to finish', async () => {
    const store = await startApp();
    await store.getState().logout();
    expect(stored.has(MARKER)).toBe(false);
    server.login = 'wrong-password';
    server.logout = 'offline';

    await expect(store.getState().login('alice@example.test', 'not-the-password')).rejects.toThrow();

    expect(store.getState().user).toBeNull();
    expect(store.getState().error).toContain('メールアドレスまたはパスワードが正しくありません');
    expect(stored.has(MARKER)).toBe(false);
  });

  it('still drops the desktop cookies and caches', async () => {
    const store = await startApp();
    const clearHttpCache = installDesktopBridge();
    server.logout = 'offline';

    await store.getState().logout();

    expect(clearHttpCache).toHaveBeenCalledOnce();
  });
});

describe('sign-out the server confirms', () => {
  it('clears everything as before and shows no message', async () => {
    const store = await startApp();
    const clearHttpCache = installDesktopBridge();
    server.requests = [];

    await store.getState().logout();

    expect(server.requests).toEqual(['POST /api/auth/logout']);
    expect(server.sessionAlive).toBe(false);
    expect(store.getState()).toMatchObject({ user: null, error: null, isLoading: false, isInitialized: true });
    expect(stored.has(MARKER)).toBe(false);
    expect(clearHttpCache).toHaveBeenCalledOnce();
    expect(mocks.disconnectSocket).toHaveBeenCalled();
    expect(mocks.clearActiveDevice).toHaveBeenCalled();
    expect(mocks.resetAuthenticatedState).toHaveBeenCalled();

    // The next start only checks for a session.
    server.requests = [];
    await startApp();
    expect(server.requests).toEqual(['GET /api/auth/me']);
  });

  it('does not tell a user who signed out that their login ended', async () => {
    const store = await startApp();
    server.sessionAlive = false;

    await store.getState().logout();

    expect(store.getState().error).toBeNull();
    expect(stored.has(MARKER)).toBe(false);
  });
});
