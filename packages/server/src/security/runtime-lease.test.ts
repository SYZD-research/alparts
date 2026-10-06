import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { describe, it } from 'node:test';

process.env.DATABASE_URL ||= 'postgres://test:test@127.0.0.1:5432/alparts_test';
process.env.S3_ACCESS_KEY ||= 'test-access-key';
process.env.S3_SECRET_KEY ||= 'test-secret-key';
process.env.AUDIT_INTEGRITY_KEY ||= 'test-audit-integrity-key-at-least-32-bytes';
process.env.PASSWORD_PEPPER ||= 'test-only-password-pepper-at-least-32-bytes';

const { RuntimeLease } = await import('./runtime-lease.js');

function fakeClient(query: () => Promise<{ rows: unknown[] }> = async () => ({ rows: [{}] })) {
  const client = new EventEmitter() as EventEmitter & {
    end: () => Promise<void>;
    query: () => Promise<{ rows: unknown[] }>;
    queries: number;
  };
  client.end = async () => { client.emit('end'); };
  client.queries = 0;
  client.query = () => {
    client.queries += 1;
    return query();
  };
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

  it('asks its own session, and concurrent checks share one query', async () => {
    const client = fakeClient();
    const lease = new RuntimeLease(client as never, 1);
    await Promise.all([lease.check(), lease.check(), lease.check()]);
    assert.equal(client.queries, 1);
    await lease.check();
    assert.equal(client.queries, 2);
    assert.equal(lease.isAlive(), true);
  });

  it('is lost when its session no longer holds the lock or cannot answer', async () => {
    for (const query of [async () => ({ rows: [] }), async () => { throw new Error('Connection terminated'); }]) {
      const lease = new RuntimeLease(fakeClient(query) as never, 1);
      let lost = 0;
      lease.onLost(() => { lost += 1; });
      await assert.rejects(lease.check(), /RUNTIME_LEASE_LOST/);
      assert.equal(lost, 1);
      assert.equal(lease.isAlive(), false);
    }
  });

  it('refuses the operation but keeps the lease when another connection fails the check', async () => {
    const lease = new RuntimeLease(fakeClient() as never, 1);
    let lost = 0;
    lease.onLost(() => { lost += 1; });
    const failing = { execute: async () => { throw new Error('canceling statement due to statement timeout'); } };
    await assert.rejects(lease.check(failing), /RUNTIME_LEASE_UNCONFIRMED/);
    assert.equal(lost, 0);
    assert.equal(lease.isAlive(), true);

    const missing = { execute: async () => ({ rows: [] }) };
    await assert.rejects(lease.check(missing), /RUNTIME_LEASE_LOST/);
    assert.equal(lost, 1);
  });
});
