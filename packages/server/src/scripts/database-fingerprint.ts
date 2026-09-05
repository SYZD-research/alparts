import { createHash } from 'node:crypto';
import { writeFile, readFile } from 'node:fs/promises';
import pg from 'pg';
import { loadDatabaseRuntimeConfig } from '../config/database.js';

interface Fingerprint {
  version: 1;
  capturedAt: string;
  serverMajor: string;
  tables: Array<{ name: string; columns: string; rows: number; sha256: string }>;
}
const [operation, output, comparison] = process.argv.slice(2);
if (operation === 'compare' && output && comparison) {
  const left = JSON.parse(await readFile(output, 'utf8')) as Fingerprint;
  const right = JSON.parse(await readFile(comparison, 'utf8')) as Fingerprint;
  if (left.version !== 1 || right.version !== 1 || !Array.isArray(left.tables) || !left.tables.length
      || left.serverMajor !== right.serverMajor || JSON.stringify(left.tables) !== JSON.stringify(right.tables)) {
    throw new Error('MIGRATION_FINGERPRINT_MISMATCH');
  }
  console.log(`Verified ${left.tables.length} tables: identical columns, row counts and content hashes`);
} else if (operation === 'capture' && output && !comparison) {
  const config = loadDatabaseRuntimeConfig(process.env, process.env.NODE_ENV || 'development');
  const client = new pg.Client({ connectionString: config.url,
    ssl: config.ssl ? { rejectUnauthorized: true } : undefined,
    connectionTimeoutMillis: config.connectTimeoutMs, statement_timeout: 300_000,
    application_name: 'alparts-migration-verifier' });
  await client.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    await client.query("SET LOCAL TIME ZONE 'UTC'");
    await client.query("SET LOCAL search_path = pg_catalog");
    const version = await client.query<{ server_version_num: string }>('SHOW server_version_num');
    const tables = await client.query<{ name: string }>(`
      SELECT c.relname AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind = 'r' ORDER BY c.relname COLLATE "C"
    `);
    if (tables.rows.length === 0 || tables.rows.length > 1024) throw new Error('INVALID_TABLE_COUNT');
    const result: Fingerprint = { version: 1, capturedAt: new Date().toISOString(),
      serverMajor: String(Math.floor(Number(version.rows[0]!.server_version_num) / 10000)), tables: [] };
    for (const { name } of tables.rows) {
      const columns = await client.query(`
        SELECT a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod) AS type, a.attnotnull
        FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname = $1 AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum
      `, [name]);
      const identifier = '"' + name.replaceAll('"', '""') + '"';
      // Sorting canonical jsonb values works for every table, including composite keys.
      // The cursor bounds client memory; PostgreSQL can spill its sort to disk.
      await client.query(`DECLARE alparts_rows NO SCROLL CURSOR FOR SELECT to_jsonb(t)::text AS value FROM public.${identifier} t ORDER BY to_jsonb(t)::text COLLATE "C"`);
      const hash = createHash('sha256');
      let count = 0;
      for (;;) {
        const batch = await client.query<{ value: string }>('FETCH FORWARD 128 FROM alparts_rows');
        if (!batch.rows.length) break;
        for (const row of batch.rows) {
          hash.update(String(Buffer.byteLength(row.value))).update(':').update(row.value).update('\n');
          count += 1;
        }
      }
      await client.query('CLOSE alparts_rows');
      result.tables.push({ name, columns: JSON.stringify(columns.rows), rows: count, sha256: hash.digest('hex') });
    }
    await client.query('COMMIT');
    await writeFile(output, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    console.log(`Captured ${result.tables.length} tables; no row contents written to the report`);
  } finally { await client.end(); }
} else {
  throw new Error('Usage: database-fingerprint capture new-report.json | compare source.json target.json');
}
