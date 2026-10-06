import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { isSensitiveRequest } from '@alparts/shared';

describe('identity confirmation for channel changes (SEC-02)', () => {
  it('requires it when a channel update changes privacy or category', () => {
    assert.equal(isSensitiveRequest('PUT', '/api/channels/c1', { isPrivate: false }), true);
    assert.equal(isSensitiveRequest('put', '/API/Channels/c1/', { categoryId: null }), true);
    assert.equal(isSensitiveRequest('PUT', '/api/channels/c1', { name: 'x', isPrivate: true }), true);
  });

  it('does not require it for a plain rename or topic change', () => {
    assert.equal(isSensitiveRequest('PUT', '/api/channels/c1', { name: 'renamed', topic: 't' }), false);
    assert.equal(isSensitiveRequest('PUT', '/api/channels/c1', null), false);
    assert.equal(isSensitiveRequest('GET', '/api/channels/c1', { isPrivate: false }), false);
    assert.equal(isSensitiveRequest('PUT', '/api/channels/c1/preferences', { isPrivate: false }), false);
  });

  it('keeps every path-only sensitive action', () => {
    assert.equal(isSensitiveRequest('POST', '/api/channels/c1/members', {}), true);
    assert.equal(isSensitiveRequest('DELETE', '/api/channels/c1', undefined), true);
  });
});

describe('identity confirmation for password settings (SEC-06)', () => {
  it('requires it to change the password or the password login setting', () => {
    assert.equal(isSensitiveRequest('PUT', '/api/auth/password', { newPassword: 'x' }), true);
    assert.equal(isSensitiveRequest('PUT', '/api/auth/password-login', { enabled: false }), true);
    assert.equal(isSensitiveRequest('GET', '/api/auth/password-login', undefined), false);
  });
});
