import assert from 'node:assert/strict';
import { test } from 'node:test';
import { grantsSql, provisionSql } from './database.ts';
import { scramSha256Verifier } from './secrets.ts';

test('role provisioning takes verifiers only and keeps every role unprivileged', () => {
  const sql = provisionSql({
    alparts_owner: scramSha256Verifier('a'),
    alparts_app: scramSha256Verifier('b'),
    alparts_backup: scramSha256Verifier('c'),
  });
  assert.equal(sql.match(/NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'SCRAM-SHA-256\$4096:/g)?.length, 3);
  assert.match(sql, /CREATE DATABASE alparts OWNER alparts_owner/);
  assert.match(sql, /REVOKE ALL ON DATABASE alparts FROM PUBLIC;/);
  assert.doesNotMatch(sql, /GRANT [^;]*(CREATE|TRUNCATE|REFERENCES|TRIGGER)[^;]* TO alparts_(app|backup)/);
  assert.throws(() => provisionSql({ alparts_owner: "x'; DROP", alparts_app: 'x', alparts_backup: 'x' }));
});

test('after migrations the app may only change rows and the backup role only read', () => {
  const sql = grantsSql();
  assert.match(sql, /GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO alparts_app;/);
  assert.match(sql, /GRANT SELECT ON ALL TABLES IN SCHEMA drizzle TO alparts_app, alparts_backup;/);
  assert.doesNotMatch(sql, /alparts_backup[^;]*(INSERT|UPDATE|DELETE)|(INSERT|UPDATE|DELETE)[^;]*alparts_backup/);
});
