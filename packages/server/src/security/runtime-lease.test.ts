import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { describe, it } from 'node:test';

process.env.DATABASE_URL ||= 'postgres://test:test@127.0.0.1:5432/alparts_test';
process.env.MINIO_ACCESS_KEY ||= 'test-access-key';
process.env.MINIO_SECRET_KEY ||= 'test-secret-key';
process.env.AUDIT_INTEGRITY_KEY ||= 'test-audit-integrity-key-at-least-32-bytes';
process.env.PASSWORD_PEPPER ||= 'test-only-password-pepper-at-least-32-bytes';

const { RuntimeLease } = await import('./runtime-lease.js');

function fakeClient() {
  const client = new EventEmitter() as EventEmitter & { end: () => Promise<void> };
  client.end = async () => { client.emit('end'); };
  return client;
}

describe('runtime lease', () => {
  it('reports a lost connection to its listeners', () => {
    const client = fakeClient();
    const lease = new RuntimeLease(client as never, 1);
    let lost = 0;
    lease.onLost(() => { lost += 1; });
    client.emit('error', new Error('connection reset'));
    assert.equal(lost, 1);
    assert.equal(lease.isAlive(), false);
  });

  it('does not treat its own release during shutdown as a loss', async () => {
    const client = fakeClient();
    const lease = new RuntimeLease(client as never, 1);
    let lost = 0;
    lease.onLost(() => { lost += 1; });
    await lease.close();
    assert.equal(lost, 0);
    assert.equal(lease.isAlive(), false);
  });
});
