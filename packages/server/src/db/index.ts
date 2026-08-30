import { drizzle } from 'drizzle-orm/node-postgres';
import { sql } from 'drizzle-orm';
import pg from 'pg';
import { config } from '../config/index.js';
import * as schema from './schema.js';
import { assertAppliedMigrations, expectedMigrations, type MigrationFingerprint } from './migration-bundle.js';
import { assertSchemaCatalogMatches, loadSchemaCatalogSnapshot } from './schema-catalog.js';

const pool = new pg.Pool({
  connectionString: config.db.url,
  ssl: config.db.ssl ? { rejectUnauthorized: true } : undefined,
  max: config.db.poolMax,
  connectionTimeoutMillis: config.db.connectTimeoutMs,
  idleTimeoutMillis: 30_000,
  statement_timeout: config.db.statementTimeoutMs,
  query_timeout: config.db.statementTimeoutMs + 1_000,
  application_name: 'alparts-server',
});

export const db = drizzle(pool, { schema });

export async function checkDb(): Promise<void> {
  await db.execute(sql`select 1`);
}

export async function checkDatabaseSchema(): Promise<number> {
  let client: pg.PoolClient | null = null;
  let transactionStarted = false;
  try {
    client = await pool.connect();
    await client.query('begin isolation level repeatable read read only');
    transactionStarted = true;
    await client.query('set local search_path = pg_catalog');
    const result = await client.query<MigrationFingerprint>(`
      select hash, created_at::text as "createdAt"
      from drizzle.__drizzle_migrations
      order by created_at asc
      limit $1
    `, [expectedMigrations.length + 1]);
    assertAppliedMigrations(expectedMigrations, result.rows);
    assertSchemaCatalogMatches(await loadSchemaCatalogSnapshot(client));
    await client.query('commit');
    transactionStarted = false;
    return result.rows.length;
  } catch (error) {
    if (transactionStarted && client) await client.query('rollback').catch(() => undefined);
    if (error instanceof Error && error.message.startsWith('DATABASE_SCHEMA_')) throw error;
    throw new Error('DATABASE_SCHEMA_CHECK_FAILED');
  } finally {
    client?.release();
  }
}

export async function closeDb() {
  await pool.end();
}

export function dbPoolSnapshot() {
  return {
    total: pool.totalCount,
    idle: pool.idleCount,
    waiting: pool.waitingCount,
    max: config.db.poolMax,
  };
}
