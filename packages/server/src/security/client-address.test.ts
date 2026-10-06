import assert from 'node:assert/strict';
import type { IncomingMessage } from 'node:http';
import { describe, it } from 'node:test';

process.env.DATABASE_URL ||= 'postgres://test:test@127.0.0.1:5432/alparts_test';
process.env.S3_ACCESS_KEY ||= 'test-access-key';
process.env.S3_SECRET_KEY ||= 'test-secret-key';
process.env.AUDIT_INTEGRITY_KEY ||= 'test-audit-integrity-key-at-least-32-bytes';
process.env.PASSWORD_PEPPER ||= 'test-only-password-pepper-at-least-32-bytes';
process.env.TRUSTED_PROXIES = '127.0.0.1';

const { rateLimitSource, requestClientAddress } = await import('./client-address.js');

const request = (peer: string, forwardedFor?: string) => ({
  socket: { remoteAddress: peer },
  connection: { remoteAddress: peer },
  headers: forwardedFor ? { 'x-forwarded-for': forwardedFor } : {},
}) as unknown as IncomingMessage;

describe('client address behind a reverse proxy (SEC-03)', () => {
  it('uses the forwarded client only when the peer is a trusted proxy', () => {
    assert.equal(requestClientAddress(request('127.0.0.1', '203.0.113.9')), '203.0.113.9');
    assert.equal(requestClientAddress(request('198.51.100.7', '203.0.113.9')), '198.51.100.7');
    assert.equal(requestClientAddress(request('127.0.0.1')), '127.0.0.1');
  });

  it('counts one IPv6 /64 as one client and IPv4-mapped addresses as IPv4', () => {
    assert.equal(rateLimitSource('2001:db8:1:2:aaaa::1'), '2001:db8:1:2::/64');
    assert.equal(rateLimitSource('2001:db8:1:2:ffff:ffff:ffff:ffff'), '2001:db8:1:2::/64');
    assert.equal(rateLimitSource('2001:0db8:0001:0002::5'), '2001:db8:1:2::/64');
    assert.equal(rateLimitSource('2001:db8::1'), '2001:db8:0:0::/64');
    assert.equal(rateLimitSource('::1'), '0:0:0:0::/64');
    assert.equal(rateLimitSource('fe80::1%eth0'), 'fe80:0:0:0::/64');
    assert.equal(rateLimitSource('::ffff:203.0.113.9'), '203.0.113.9');
    assert.equal(rateLimitSource('203.0.113.9'), '203.0.113.9');
    assert.equal(rateLimitSource(undefined), 'unknown');
  });
});
