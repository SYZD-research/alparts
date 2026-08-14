import { drizzle } from 'drizzle-orm/node-postgres';
import pg from 'pg';
import { config } from '../config/index.js';
import * as schema from './schema.js';

const pool = new pg.Pool({
  connectionString: config.db.url,
});

export const db = drizzle(pool, { schema });

export async function closeDb() {
  await pool.end();
}
