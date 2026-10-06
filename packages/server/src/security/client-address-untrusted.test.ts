import assert from 'node:assert/strict';
import type { IncomingMessage } from 'node:http';
import { it } from 'node:test';

process.env.DATABASE_URL ||= 'postgres://test:test@127.0.0.1:5432/alparts_test';
process.env.S3_ACCESS_KEY ||= 'test-access-key';
process.env.S3_SECRET_KEY ||= 'test-secret-key';
process.env.AUDIT_INTEGRITY_KEY ||= 'test-audit-integrity-key-at-least-32-bytes';
process.env.PASSWORD_PEPPER ||= 'test-only-password-pepper-at-least-32-bytes';
delete process.env.TRUSTED_PROXIES;

const { reportUntrustedForwarding, requestClientAddress } = await import('./client-address.js');

it('warns once when a proxy forwards requests but no proxy is trusted (SEC-03)', (t) => {
  const warn = t.mock.method(console, 'warn', () => undefined);
  const plain = { socket: { remoteAddress: '127.0.0.1' }, headers: {} } as unknown as IncomingMessage;
  const forwarded = {
    socket: { remoteAddress: '127.0.0.1' },
    connection: { remoteAddress: '127.0.0.1' },
    headers: { 'x-forwarded-for': '203.0.113.9' },
  } as unknown as IncomingMessage;
  reportUntrustedForwarding(plain);
  assert.equal(warn.mock.callCount(), 0);
  reportUntrustedForwarding(forwarded);
  reportUntrustedForwarding(forwarded);
  assert.equal(warn.mock.callCount(), 1);
  assert.match(String(warn.mock.calls[0]!.arguments[0]), /forwarded_without_trusted_proxy/);
  // Without a trusted proxy the header is ignored.
  assert.equal(requestClientAddress(forwarded), '127.0.0.1');
});
