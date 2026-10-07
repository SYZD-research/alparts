import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, ApiError } from './api';

function respond(status: number, body: unknown, headers: Record<string, string> = {}) {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })));
}

async function refusal(run: () => Promise<unknown>): Promise<ApiError> {
  try {
    await run();
  } catch (error) {
    expect(error).toBeInstanceOf(ApiError);
    return error as ApiError;
  }
  throw new Error('expected a refusal');
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('API refusals', () => {
  it('carries the refusal reason and current version that key recovery decides on', async () => {
    respond(400, { error: 'INVALID_MESSAGE', code: 'KEY_VERSION_STALE', currentVersion: 3, message: 'stale' });
    const stale = await refusal(() => api.getMessages('11111111-1111-4111-8111-111111111111'));
    expect([stale.status, stale.code, stale.reason, stale.currentVersion]).toEqual([400, 'INVALID_MESSAGE', 'KEY_VERSION_STALE', 3]);

    respond(409, { error: 'GROUP_STATE_CHANGED', code: 'ALREADY_MEMBER' }, { 'Retry-After': '7' });
    const member = await refusal(() => api.getKeyRecipients('11111111-1111-4111-8111-111111111111'));
    expect([member.status, member.code, member.reason, member.currentVersion, member.retryAfterSeconds])
      .toEqual([409, 'GROUP_STATE_CHANGED', 'ALREADY_MEMBER', null, 7]);
  });

  it('drops a reason or version that is not in the expected form', async () => {
    for (const code of ['already_member', 'A'.repeat(65), 'KEY VERSION', 7]) {
      respond(409, { error: 'GROUP_STATE_CHANGED', code, currentVersion: 1.5 });
      const error = await refusal(() => api.getKeyRecipients('11111111-1111-4111-8111-111111111111'));
      expect([error.reason, error.currentVersion]).toEqual([null, null]);
    }
  });
});
