import { drizzle } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import pg from 'pg';
import { loadDatabaseRuntimeConfig } from '../config/database.js';
import { resolveMigrationsFolder } from '../db/migration-bundle.js';

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
  await client.connect();
  const lock = await client.query<{ acquired: boolean }>(
    'select pg_try_advisory_lock($1) as acquired',
    [MIGRATION_LOCK_ID],
  );
  if (lock.rows[0]?.acquired !== true) {
    throw new Error('MIGRATION_ALREADY_RUNNING');
  }
  try {
    await migrate(drizzle(client), { migrationsFolder });
    process.stdout.write('Runtime migrations applied successfully.\n');
  } finally {
    await client.query('select pg_advisory_unlock($1)', [MIGRATION_LOCK_ID]);
  }
} finally {
  await client.end().catch(() => undefined);
}
