import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => {
  class ApiError extends Error {
    constructor(message: string, readonly status: number, readonly code: string | null = null, readonly retryAfterSeconds?: number) {
      super(message);
    }
  }
  return { ApiError, api: { getAvatarBytes: vi.fn() } };
});

vi.mock('../services/api', () => ({ api: mocks.api, ApiError: mocks.ApiError }));

const { clearAvatarCache, loadAvatar, MAX_CONCURRENT_AVATAR_FETCHES } = await import('./avatar-cache');

function deferred() {
  let resolve!: (bytes: ArrayBuffer) => void;
  const promise = new Promise<ArrayBuffer>((done) => { resolve = done; });
  return { promise, resolve };
}

const url = (index: number) => `/api/users/${'0'.repeat(8)}-0000-0000-0000-${String(index).padStart(12, '0')}/avatar/${'1'.repeat(8)}-1111-1111-1111-111111111111`;

describe('avatar cache', () => {
  beforeEach(() => {
    clearAvatarCache();
    mocks.api.getAvatarBytes.mockReset();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('sends only a few avatar requests at a time and queues the rest', async () => {
    const requests: Array<ReturnType<typeof deferred>> = [];
    mocks.api.getAvatarBytes.mockImplementation(() => {
      const request = deferred();
      requests.push(request);
      return request.promise;
    });
    const loads = Array.from({ length: MAX_CONCURRENT_AVATAR_FETCHES + 2 }, (_, index) => loadAvatar(url(index)));
    await Promise.resolve();
    expect(mocks.api.getAvatarBytes).toHaveBeenCalledTimes(MAX_CONCURRENT_AVATAR_FETCHES);

    requests[0].resolve(new ArrayBuffer(4));
    await vi.waitFor(() => expect(mocks.api.getAvatarBytes).toHaveBeenCalledTimes(MAX_CONCURRENT_AVATAR_FETCHES + 1));
    for (const request of requests.slice(1)) request.resolve(new ArrayBuffer(4));
    await vi.waitFor(() => expect(mocks.api.getAvatarBytes).toHaveBeenCalledTimes(MAX_CONCURRENT_AVATAR_FETCHES + 2));
    requests[requests.length - 1].resolve(new ArrayBuffer(4));
    const sources = await Promise.all(loads);
    expect(sources.every((source) => typeof source === 'string')).toBe(true);
  });

  it('retries an avatar the server was too busy to send', async () => {
    vi.useFakeTimers();
    mocks.api.getAvatarBytes
      .mockRejectedValueOnce(new mocks.ApiError('busy', 429, 'DOWNLOAD_LIMIT_REACHED'))
      .mockResolvedValueOnce(new ArrayBuffer(4));
    const load = loadAvatar(url(1));
    await vi.advanceTimersByTimeAsync(300);
    expect(await load).toEqual(expect.any(String));
    expect(mocks.api.getAvatarBytes).toHaveBeenCalledTimes(2);
  });

  it('does not retry an avatar that is gone', async () => {
    mocks.api.getAvatarBytes.mockRejectedValueOnce(new mocks.ApiError('missing', 404, 'NOT_FOUND'));
    expect(await loadAvatar(url(2))).toBeNull();
    expect(mocks.api.getAvatarBytes).toHaveBeenCalledTimes(1);
  });

  it('drops queued and unfinished avatar requests on sign-out', async () => {
    const requests: Array<ReturnType<typeof deferred>> = [];
    mocks.api.getAvatarBytes.mockImplementation(() => {
      const request = deferred();
      requests.push(request);
      return request.promise;
    });
    const loads = Array.from({ length: MAX_CONCURRENT_AVATAR_FETCHES + 2 }, (_, index) => loadAvatar(url(index)));
    await Promise.resolve();
    clearAvatarCache();
    for (const request of requests) request.resolve(new ArrayBuffer(4));
    expect(await Promise.all(loads)).toEqual(loads.map(() => null));
    expect(mocks.api.getAvatarBytes).toHaveBeenCalledTimes(MAX_CONCURRENT_AVATAR_FETCHES);

    // Every slot is free again for the next session.
    mocks.api.getAvatarBytes.mockReset();
    mocks.api.getAvatarBytes.mockResolvedValue(new ArrayBuffer(4));
    const next = await Promise.all(Array.from({ length: MAX_CONCURRENT_AVATAR_FETCHES }, (_, index) => loadAvatar(url(index + 10))));
    expect(next.every((source) => typeof source === 'string')).toBe(true);
  });
});
