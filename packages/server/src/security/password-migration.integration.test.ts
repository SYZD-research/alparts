import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { promisify } from 'node:util';
import { it } from 'node:test';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import { verifyPassword, closePasswordWorkers } from './password-work.js';

const run = promisify(execFile);
it('migrates retained password hashes atomically, idempotently, and only with a stopped runtime', {
  skip: process.env.RUN_ACCOUNT_SECURITY_INTEGRATION !== '1',
}, async () => {
  assert.match(process.env.DATABASE_URL ?? '', /alparts_(?:security_)?test/);
  const admin = new pg.Client({ connectionString: process.env.DATABASE_URL });
  const name = `alparts_security_test_password_${randomUUID().replaceAll('-', '')}`;
  const url = new URL(process.env.DATABASE_URL!);
  url.pathname = `/${name}`;
  const client = new pg.Client({ connectionString: url.toString() });
  process.env.PASSWORD_PEPPER = 'migration-test-only-independent-pepper-32-bytes';
  const migrate = (overrides: NodeJS.ProcessEnv = {}) => run(process.execPath,
    ['--import', './node_modules/tsx/dist/loader.mjs', 'src/scripts/migrate-runtime.ts'],
    { env: { ...process.env, DATABASE_URL: url.toString(), ...overrides }, timeout: 30_000 });
  await admin.connect();
  try {
    await admin.query(`create database ${name}`);
    await client.connect();
    await migrate();
    const original = await bcrypt.hash('retained-valid-password', 12);
    const weak = await bcrypt.hash('weak-test-only-password', 4);
    const id = randomUUID();
    const weakId = randomUUID();
    await client.query('insert into users (id,email,password_hash,display_name) values ($1,$2,$3,$4),($5,$6,$7,$8)',
      [id, 'valid@example.test', original, 'Valid', weakId, 'weak@example.test', weak, 'Weak']);
    await assert.rejects(migrate(), /UNSUPPORTED_PASSWORD_HASH/);
    assert.equal((await client.query('select password_hash from users where id = $1', [id])).rows[0].password_hash, original);
    await client.query('delete from users where id = $1', [weakId]);
    await migrate();
    const stored = (await client.query('select password_hash from users where id = $1', [id])).rows[0].password_hash;
    assert.match(stored, /^p1:/);
    assert.equal(await verifyPassword('retained-valid-password', stored), true);
    await migrate();
    assert.equal((await client.query('select password_hash from users where id = $1', [id])).rows[0].password_hash, stored);
    await assert.rejects(migrate({ PASSWORD_PEPPER: '', PASSWORD_PEPPER_FILE: '' }), /PASSWORD_PEPPER_REQUIRED/);
    await client.query('select pg_advisory_lock(1095520341)');
    try { await assert.rejects(migrate(), /STOP_RUNTIME_BEFORE_MIGRATION/); }
    finally { await client.query('select pg_advisory_unlock(1095520341)'); }
  } finally {
    await closePasswordWorkers();
    await client.end().catch(() => undefined);
    await admin.query(`drop database if exists ${name} with (force)`);
    await admin.end();
  }
});
