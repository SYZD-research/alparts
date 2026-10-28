import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { test } from 'node:test';
import { grantsSql, provisionSql, type DatabaseNames, type Role } from './database.ts';
import { repositoryRoot } from './paths.ts';
import { scramSha256Verifier } from './secrets.ts';

// The roles and grants the setup gives PostgreSQL, applied to a disposable
// PostgreSQL 16 server together with the server's own migrations, then probed
// with what each role must and must not be able to do. SETUP_TEST_DATABASE_URL
// names a superuser on that server, as in CI's integration job; without it the
// test is skipped. It needs psql, pg_dump and the built server
// (pnpm --filter @alparts/server build). The database and the roles it
// creates have unique names and are dropped at the end.

const server = process.env.SETUP_TEST_DATABASE_URL;

function clientEnvironment(url: URL): NodeJS.ProcessEnv {
  return {
    ...process.env,
    PGHOST: url.hostname,
    PGPORT: url.port || '5432',
    PGUSER: decodeURIComponent(url.username),
    PGPASSWORD: decodeURIComponent(url.password),
  };
}

/** Runs SQL through psql as the user of `url`, connected to `database`. */
function psql(url: URL, database: string, sql: string): { ok: boolean; stdout: string; stderr: string } {
  const result = spawnSync('psql', ['-X', '-q', '-At', '-v', 'ON_ERROR_STOP=1', '-d', database], {
    input: sql,
    encoding: 'utf8',
    env: clientEnvironment(url),
  });
  return { ok: result.status === 0, stdout: result.stdout.trim(), stderr: result.stderr };
}

test('each database role can do what the setup grants it, and nothing more', { skip: server ? false : 'SETUP_TEST_DATABASE_URL is not set' }, () => {
  const admin = new URL(server!);
  const adminDatabase = decodeURIComponent(admin.pathname.slice(1)) || 'postgres';
  const prefix = `setup_it_${randomBytes(4).toString('hex')}`;
  const names: DatabaseNames = { name: prefix, owner: `${prefix}_owner`, app: `${prefix}_app`, backup: `${prefix}_backup` };
  const outsider = `${prefix}_outsider`;
  const passwords = { owner: '', app: '', backup: '', outsider: '' };
  for (const role of Object.keys(passwords) as Array<keyof typeof passwords>) passwords[role] = randomBytes(24).toString('hex');
  const login = (role: Role | 'outsider') => {
    const url = new URL(admin.href);
    url.username = role === 'outsider' ? outsider : names[role];
    url.password = passwords[role];
    url.pathname = `/${names.name}`;
    return url;
  };
  const allowed = (url: URL, sql: string) => {
    const result = psql(url, names.name, sql);
    assert.ok(result.ok, `${url.username} could not run: ${sql}\n${result.stderr}`);
    return result.stdout;
  };
  const refused = (url: URL, sql: string, reason: RegExp) => {
    const result = psql(url, names.name, sql);
    assert.ok(!result.ok, `${url.username} could run: ${sql}`);
    assert.match(result.stderr, reason);
  };

  try {
    const verifiers = { owner: scramSha256Verifier(passwords.owner), app: scramSha256Verifier(passwords.app), backup: scramSha256Verifier(passwords.backup) };
    // Each step twice: a second run of the setup converges on the same state.
    for (let round = 0; round < 2; round += 1) {
      const result = psql(admin, adminDatabase, provisionSql(verifiers, names));
      assert.ok(result.ok, result.stderr);
    }
    execFileSync(process.execPath, [join(repositoryRoot(), 'packages', 'server', 'dist', 'scripts', 'migrate-runtime.js')], {
      env: { ...process.env, NODE_ENV: 'test', DATABASE_URL: login('owner').href, DB_SSL: 'false', PASSWORD_PEPPER: randomBytes(32).toString('hex') },
      stdio: 'pipe',
    });
    for (let round = 0; round < 2; round += 1) {
      const result = psql(admin, names.name, grantsSql(names));
      assert.ok(result.ok, result.stderr);
    }

    // No role holds a privilege of its own, and each password is stored as a SCRAM verifier.
    assert.equal(allowed(admin, `SELECT count(*) FROM pg_authid WHERE rolname IN ('${names.owner}', '${names.app}', '${names.backup}')
      AND NOT (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls) AND rolpassword LIKE 'SCRAM-SHA-256$4096:%'`), '3');

    // The app reads and writes rows, and never changes the schema or the migration records.
    allowed(login('app'), 'SELECT count(*) FROM users');
    allowed(login('app'), 'SELECT count(*) FROM drizzle.__drizzle_migrations');
    refused(login('app'), 'CREATE TABLE intruder (id int)', /permission denied for schema public/);
    refused(login('app'), 'ALTER TABLE users ADD COLUMN intruder int', /must be owner of table users/);
    refused(login('app'), 'DROP TABLE users', /must be owner of table users/);
    refused(login('app'), 'TRUNCATE users', /permission denied for table users/);
    refused(login('app'), 'DELETE FROM drizzle.__drizzle_migrations', /permission denied/);

    // The backup role reads everything pg_dump needs, as backup.sh runs it, and changes nothing.
    const dump = spawnSync('pg_dump', ['--format=custom', '--no-owner', '--no-privileges', '--no-sync', '--file=/dev/null', '-d', names.name], {
      encoding: 'utf8',
      env: clientEnvironment(login('backup')),
    });
    assert.equal(dump.status, 0, dump.stderr);
    refused(login('backup'), 'UPDATE users SET email = email', /permission denied for table users/);
    refused(login('backup'), 'DELETE FROM users', /permission denied for table users/);
    refused(login('backup'), 'CREATE TABLE intruder (id int)', /permission denied for schema public/);

    // Any other role is kept out of the database.
    allowed(admin, `CREATE ROLE ${outsider} LOGIN PASSWORD '${scramSha256Verifier(passwords.outsider)}'`);
    refused(login('outsider'), 'SELECT 1', /permission denied for database/);
  } finally {
    psql(admin, adminDatabase, `DROP DATABASE IF EXISTS ${names.name} WITH (FORCE)`);
    psql(admin, adminDatabase, `DROP ROLE IF EXISTS ${names.owner}, ${names.app}, ${names.backup}, ${outsider}`);
  }
});
