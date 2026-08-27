import { drizzle } from 'drizzle-orm/node-postgres';
import { sql } from 'drizzle-orm';
import pg from 'pg';
import { config } from '../config/index.js';
import * as schema from './schema.js';

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

export async function closeDb() {
  await pool.end();
}
