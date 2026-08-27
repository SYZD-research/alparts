import { describe, expect, it } from 'vitest';
import {
  isStaleAuthorizationPreviewError,
  withExpectedAuthorizationRevision,
} from './role-authorization-revision';

describe('role authorization revision contract', () => {
  it('copies the exact preview revision into every mutation body', () => {
    const revision = 'a'.repeat(64);
    const update = { name: 'Operators', permissions: 17 };

    expect(withExpectedAuthorizationRevision(update, revision)).toEqual({
      name: 'Operators',
      permissions: 17,
      expectedAuthorizationRevision: revision,
    });
    expect(withExpectedAuthorizationRevision({}, revision)).toEqual({
      expectedAuthorizationRevision: revision,
    });
    expect(() => withExpectedAuthorizationRevision({}, 'stale-or-malformed')).toThrow('revision is invalid');
  });

  it('only requests a fresh preview for the server stale-preview conflict', () => {
    expect(isStaleAuthorizationPreviewError({ status: 409, code: 'STALE_PREVIEW' })).toBe(true);
    expect(isStaleAuthorizationPreviewError({ status: 409, code: 'ROLE_CONFLICT' })).toBe(false);
    expect(isStaleAuthorizationPreviewError({ status: 400, code: 'STALE_PREVIEW' })).toBe(false);
  });
});
