import assert from 'node:assert/strict';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  APP_URL,
  assertSecretName,
  deploymentNamespace,
  isAllowedBackendRequestDestination,
  isBackendPath,
  isAllowedExternalUrl,
  isTrustedRendererUrl,
  normalizeIdleLockMinutes,
  normalizeServerUrl,
  resolveBundledPath,
  withBackendRequestOrigin,
} from './security-policy.js';

describe('desktop security policy', () => {
  it('accepts secure deployment origins and loopback development origins', () => {
    assert.equal(normalizeServerUrl('https://chat.example.test/'), 'https://chat.example.test');
    assert.equal(normalizeServerUrl('http://127.0.0.1:3000'), 'http://127.0.0.1:3000');
    assert.equal(normalizeServerUrl('http://[::1]:3000'), 'http://[::1]:3000');
  });

  it('rejects unsafe or ambiguous deployment URLs', () => {
    for (const candidate of [
      'http://chat.example.test',
      'file:///tmp/index.html',
      'https://user@example.test',
      'https://example.test/subpath',
      'https://example.test/?token=secret',
      'javascript:alert(1)',
    ]) {
      assert.throws(() => normalizeServerUrl(candidate));
    }
  });

  it('allows only the configured idle lock values', () => {
    assert.equal(normalizeIdleLockMinutes(15), 15);
    assert.throws(() => normalizeIdleLockMinutes(0));
    assert.throws(() => normalizeIdleLockMinutes(2));
  });

  it('keeps external navigation to credential-free web URLs', () => {
    assert.equal(isAllowedExternalUrl('https://example.test/report?id=1'), true);
    assert.equal(isAllowedExternalUrl('http://example.test'), true);
    assert.equal(isAllowedExternalUrl('mailto:admin@example.test'), false);
    assert.equal(isAllowedExternalUrl('https://user@example.test'), false);
    assert.equal(isAllowedExternalUrl('file:///etc/passwd'), false);
  });

  it('trusts only the bundled UI, configured origin, and explicit development origin', () => {
    assert.equal(isTrustedRendererUrl(APP_URL, 'https://chat.example.test'), true);
    assert.equal(isTrustedRendererUrl('https://chat.example.test/login', 'https://chat.example.test'), true);
    assert.equal(isTrustedRendererUrl('https://chat.example.test/api/auth/me', 'https://chat.example.test'), false);
    assert.equal(isTrustedRendererUrl('https://chat.example.test/socket.io/', 'https://chat.example.test'), false);
    assert.equal(isTrustedRendererUrl('https://evil.example/login', 'https://chat.example.test'), false);
    assert.equal(isTrustedRendererUrl('http://localhost:5173/login', null, 'http://localhost:5173'), true);
  });

  it('keeps backend routes data-only', () => {
    assert.equal(isBackendPath('/api/auth/me'), true);
    assert.equal(isBackendPath('/socket.io/'), true);
    assert.equal(isBackendPath('/health/ready'), true);
    assert.equal(isBackendPath('/assets/index.js'), false);
    assert.equal(isAllowedBackendRequestDestination('', 'empty'), true);
    assert.equal(isAllowedBackendRequestDestination('', null), true);
    assert.equal(isAllowedBackendRequestDestination('script', 'script'), false);
    assert.equal(isAllowedBackendRequestDestination('document', 'document'), false);
  });

  it('restores the exact configured origin when forwarding backend requests', async () => {
    const incoming = new Request('https://chat.example.test/api/devices/challenge', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'https://untrusted.example.test',
      },
      body: '{}',
      credentials: 'same-origin',
    });
    const forwarded = withBackendRequestOrigin(incoming, 'https://chat.example.test/');

    assert.equal(forwarded.headers.get('Origin'), 'https://chat.example.test');
    assert.equal(forwarded.headers.get('Content-Type'), 'application/json');
    assert.equal(forwarded.credentials, 'same-origin');
    assert.equal(await forwarded.text(), '{}');
  });

  it('validates the three bounded vault namespaces', () => {
    const one = '11111111-1111-4111-8111-111111111111';
    const two = '22222222-2222-4222-8222-222222222222';
    const three = '33333333-3333-4333-8333-333333333333';
    assert.equal(assertSecretName(`device:${one}`), `device:${one}`);
    assert.equal(assertSecretName(`local:${one}:${two}`), `local:${one}:${two}`);
    assert.equal(assertSecretName(`channel:${one}:${two}:${three}:42`), `channel:${one}:${two}:${three}:42`);
    assert.throws(() => assertSecretName('device:anything'));
    assert.throws(() => assertSecretName(`channel:${one}:${two}:../../escape:1`));
  });

  it('resolves bundle paths without traversal', () => {
    const root = path.resolve('/opt/alparts/renderer');
    assert.equal(resolveBundledPath(root, '/assets/app.js'), path.join(root, 'assets/app.js'));
    assert.equal(resolveBundledPath(root, '/'), null);
    assert.equal(resolveBundledPath(root, '/../secret'), null);
    assert.equal(resolveBundledPath(root, '/%2e%2e/secret'), null);
    assert.equal(resolveBundledPath(root, '/assets\\secret'), null);
  });

  it('creates distinct normalized deployment namespaces', () => {
    assert.equal(deploymentNamespace('https://chat.example.test/'), deploymentNamespace('https://chat.example.test'));
    assert.notEqual(deploymentNamespace('https://a.example.test'), deploymentNamespace('https://b.example.test'));
    assert.match(deploymentNamespace('https://chat.example.test'), /^[A-Za-z0-9_-]{43}$/);
  });
});

// Permission queries and requests use this same predicate.
it('only grants explicit audio capture, never unspecified media or camera', async () => {
  const { isAllowedMediaPermission } = await import('./security-policy.js');
  assert.equal(isAllowedMediaPermission('media'), false);
  assert.equal(isAllowedMediaPermission('media', []), false);
  assert.equal(isAllowedMediaPermission('media', ['video']), false);
  assert.equal(isAllowedMediaPermission('media', ['audio', 'video']), false);
  assert.equal(isAllowedMediaPermission('media', ['audio']), true);
  assert.equal(isAllowedMediaPermission('speaker-selection'), true);
  assert.equal(isAllowedMediaPermission('geolocation'), false);
});
