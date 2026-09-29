import { describe, expect, it } from 'vitest';
import { assertSafeApiPath } from './api';

describe('API path parameters', () => {
  it('accepts server-issued identifiers and encoded values', () => {
    for (const path of [
      '/auth/me',
      '/channels/11111111-1111-4111-8111-111111111111/keys?versions=1%2C2',
      `/messages/11111111-1111-4111-8111-111111111111/reactions/${encodeURIComponent('😀')}`,
      '/auth/passkeys/AbC-_123',
    ]) expect(() => assertSafeApiPath(path)).not.toThrow();
  });

  it('rejects values that would traverse or re-route the request', () => {
    for (const path of [
      '/channels/../auth/sessions',
      '/channels/%2e%2e/auth',
      '/channels/a%2Fb/keys',
      '/channels//keys',
      '/channels/a b',
      'channels/x',
      '/channels/x#frag',
      '/channels/%zz',
      '//evil.example/api',
    ]) expect(() => assertSafeApiPath(path), path).toThrow('INVALID_API_PATH');
  });
});
