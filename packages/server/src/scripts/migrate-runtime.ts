import { drizzle } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import pg from 'pg';
import { loadDatabaseRuntimeConfig } from '../config/database.js';
import { resolveMigrationsFolder } from '../db/migration-bundle.js';
import { passwordPepper, protectPasswordHash, passwordSalt } from '../security/password-pepper.js';

const MIGRATION_LOCK_ID = 1_095_520_323;
const migrationsFolder = resolveMigrationsFolder();
const databaseConfig = loadDatabaseRuntimeConfig();
const client = new pg.Client({
  connectionString: databaseConfig.url,
  ssl: databaseConfig.ssl ? { rejectUnauthorized: true } : undefined,
  connectionTimeoutMillis: databaseConfig.connectTimeoutMs,
  query_timeout: databaseConfig.statementTimeoutMs + 1_000,
  statement_timeout: databaseConfig.statementTimeoutMs,
  application_name: 'alparts-runtime-migrator',
});

try {
  passwordPepper();
  await client.connect();
  const lock = await client.query<{ acquired: boolean }>(
    'select pg_try_advisory_lock($1) as acquired',
    [MIGRATION_LOCK_ID],
  );
  if (lock.rows[0]?.acquired !== true) {
    throw new Error('MIGRATION_ALREADY_RUNNING');
  }
  try {
    // Never rewrite credentials while a serving runtime owns the database.
    const runtimeLock = await client.query<{ acquired: boolean }>(
      'select pg_try_advisory_lock(1095520341) as acquired',
    );
    if (!runtimeLock.rows[0]?.acquired) throw new Error('STOP_RUNTIME_BEFORE_MIGRATION');
    await client.query('select pg_advisory_lock(1095520342)');
    await migrate(drizzle(client), { migrationsFolder });
    await client.query('begin');
    try {
      await client.query(
        'declare alparts_password_rows no scroll cursor for select id, password_hash from users for update',
      );
      for (;;) {
        const result = await client.query<{ id: string; password_hash: string }>(
          'fetch forward 128 from alparts_password_rows',
        );
        if (!result.rows.length) break;
        for (const row of result.rows) {
          if (row.password_hash.startsWith('p1:')) {
            passwordSalt(row.password_hash);
          } else {
            const protectedHash = protectPasswordHash(row.password_hash);
            await client.query('update users set password_hash = $1 where id = $2', [
              protectedHash,
              row.id,
            ]);
          }
        }
      }
      await client.query('close alparts_password_rows');
      await client.query('commit');
    } catch (error) {
      await client.query('rollback');
      throw error;
    }
    process.stdout.write('Runtime migrations applied successfully.\n');
  } finally {
    await client.query('select pg_advisory_unlock($1)', [MIGRATION_LOCK_ID]);
  }
} finally {
  await client.end().catch(() => undefined);
}
