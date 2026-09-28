import { createHash } from 'node:crypto';
import { asc, sql } from 'drizzle-orm';
import {
  DIRECTORY_GENESIS,
  serializeDirectoryEntry,
  type DirectoryEntry,
  type DirectoryHead,
} from '@alparts/shared';
import pg from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import { loadDatabaseRuntimeConfig } from '../config/database.js';
import { deviceDirectoryEvents } from '../db/schema.js';

const config = loadDatabaseRuntimeConfig();
const client = new pg.Client({
  connectionString: config.url,
  ssl: config.ssl ? { rejectUnauthorized: true } : undefined,
  connectionTimeoutMillis: config.connectTimeoutMs,
  statement_timeout: config.statementTimeoutMs,
});
const db = drizzle(client);
await client.connect();
// Run offline against the reviewed migration inventory. The output is a
// candidate trust root, not evidence that a live/untrusted database is honest.
try {
  const rows = await db
    .select()
    .from(deviceDirectoryEvents)
    .where(sql`${deviceDirectoryEvents.event}->>'kind' = 'legacy'`)
    .orderBy(asc(deviceDirectoryEvents.userId), asc(deviceDirectoryEvents.sequence))
    .limit(100_001);
  if (rows.length > 100_000) throw new Error('MIGRATION_INVENTORY_LIMIT');
  const heads: Record<string, DirectoryHead> = {};
  for (const row of rows) {
    const entry = row as DirectoryEntry;
    const previous = heads[entry.userId] ?? {
      userId: entry.userId,
      sequence: 0,
      hash: DIRECTORY_GENESIS,
    };
    if (
      entry.sequence !== previous.sequence + 1 ||
      entry.previousHash !== previous.hash ||
      entry.hash !== createHash('sha256').update(serializeDirectoryEntry(entry)).digest('hex')
    )
      throw new Error('MIGRATION_INVENTORY_INVALID');
    heads[entry.userId] = {
      userId: entry.userId,
      sequence: entry.sequence,
      hash: entry.hash,
    };
  }
  process.stdout.write(`${JSON.stringify(heads, null, 2)}\n`);
} finally {
  await client.end();
}
