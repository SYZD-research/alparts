import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, ApiConnectionError, ApiError } from '../services/api';
import { authErrorMessage } from './auth-error';

afterEach(() => {
  vi.unstubAllGlobals();
  api.setUnauthorizedHandler(() => {});
});

async function loginFailure(): Promise<unknown> {
  vi.stubGlobal('navigator', { platform: 'Android', userAgent: 'WebView', language: 'ja' });
  return api.login('test@example.com', 'not-a-real-password').catch((error: unknown) => error);
}

describe('login connection failures', () => {
  it('does not expire a session on the first startup probe, while retaining protected-request expiry', async () => {
    const unauthorized = vi.fn();
    api.setUnauthorizedHandler(unauthorized);
    vi.stubGlobal('fetch', vi.fn().mockImplementation(() => Promise.resolve(
      Response.json({ error: 'UNAUTHORIZED' }, { status: 401 }),
    )));
    await expect(api.getMe()).rejects.toMatchObject({ status: 401 });
    expect(unauthorized).not.toHaveBeenCalled();
    await expect(api.getDevices()).rejects.toMatchObject({ status: 401 });
    expect(unauthorized).toHaveBeenCalledOnce();
  });

  it('reports an unreachable server separately from account credentials', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));
    const error = await loginFailure();
    expect(error).toBeInstanceOf(ApiConnectionError);
    expect(error).toBeInstanceOf(TypeError);
    expect(authErrorMessage(error, 'login')).toContain('通信環境を確認');
  });

  it('recognizes a proxy error even when its response is empty or HTML', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('<html>Bad gateway</html>', { status: 502 })));
    expect(authErrorMessage(await loginFailure(), 'login')).toContain('接続先が応答していません');
  });

  it('keeps invalid credentials and rejected deployment configuration distinct', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ error: 'UNAUTHORIZED' }, { status: 401 })));
    expect(authErrorMessage(await loginFailure(), 'login')).toBe('メールアドレスまたはパスワードが正しくありません。');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ error: 'ORIGIN_FORBIDDEN' }, { status: 403 })));
    expect(authErrorMessage(await loginFailure(), 'login')).toContain('管理者に確認');
  });

  it('does not describe device setup errors as incorrect passwords', () => {
    expect(authErrorMessage(new Error('SECURE_DEVICE_STORAGE_INVALID'), 'login')).toBe('ログインできませんでした。もう一度お試しください。');
    expect(authErrorMessage(new ApiError('limit', 409, 'DEVICE_LIMIT_REACHED'), 'login')).toContain('不要な端末の登録を解除');
    expect(authErrorMessage(new Error('API_REQUEST_TIMEOUT'), 'login')).toContain('接続に時間がかかっています');
  });
});
