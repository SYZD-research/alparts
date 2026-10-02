import { createHash } from 'node:crypto';
import { closeSync, existsSync, fstatSync, openSync, readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const MAX_MIGRATIONS = 1_024;
const MAX_MIGRATION_BYTES = 16 * 1024 * 1024;
const TAG_PATTERN = /^\d{4}_[a-z0-9_]+$/;
const HASH_PATTERN = /^[a-f0-9]{64}$/;

export interface MigrationFingerprint {
  createdAt: string;
  hash: string;
}

interface JournalEntry {
  idx: number;
  tag: string;
  when: number;
}

function readBoundedText(path: string, maximumBytes: number): string {
  // Check and read the same open file, so it cannot be swapped in between.
  const descriptor = openSync(path, 'r');
  try {
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.size > maximumBytes) {
      throw new Error('MIGRATION_BUNDLE_INVALID');
    }
    return readFileSync(descriptor, 'utf8');
  } finally {
    closeSync(descriptor);
  }
}

export function resolveMigrationsFolder(): string {
  // Compiled OCI layout: dist/db -> ../../migrations. Local compiled layout:
  // dist/db -> ../../src/db/migrations. Source/tsx layout: src/db ->
  // ./migrations. Requiring one of these explicit paths couples the running
  // code to the exact ordered SQL bundle that it validates.
  const candidates = [
    fileURLToPath(new URL('./migrations/', import.meta.url)),
    fileURLToPath(new URL('../../src/db/migrations/', import.meta.url)),
    fileURLToPath(new URL('../../migrations/', import.meta.url)),
  ];
  const existing = [...new Set(candidates
    .filter((candidate) => existsSync(candidate))
    .map((candidate) => realpathSync(candidate)))];
  if (existing.length === 0) throw new Error('MIGRATION_BUNDLE_MISSING');
  // A source checkout and an OCI bundle must never silently compete: an old
  // copied directory could otherwise validate a different journal than the
  // SQL an operator believes is deployed.
  if (existing.length !== 1) throw new Error('MIGRATION_BUNDLE_AMBIGUOUS');
  return existing[0];
}

export function loadExpectedMigrations(
  migrationsFolder = resolveMigrationsFolder(),
): readonly MigrationFingerprint[] {
  const journalText = readBoundedText(`${migrationsFolder}/meta/_journal.json`, 1024 * 1024);
  let document: unknown;
  try {
    document = JSON.parse(journalText);
  } catch {
    throw new Error('MIGRATION_BUNDLE_INVALID');
  }
  if (!document || typeof document !== 'object' || !Array.isArray((document as { entries?: unknown }).entries)) {
    throw new Error('MIGRATION_BUNDLE_INVALID');
  }
  const entries = (document as { entries: unknown[] }).entries;
  if (entries.length < 1 || entries.length > MAX_MIGRATIONS) {
    throw new Error('MIGRATION_BUNDLE_INVALID');
  }

  let previousTimestamp = -1;
  const result = entries.map((candidate, index): MigrationFingerprint => {
    if (!candidate || typeof candidate !== 'object') throw new Error('MIGRATION_BUNDLE_INVALID');
    const { idx, tag, when } = candidate as Partial<JournalEntry>;
    if (
      idx !== index
      || typeof tag !== 'string'
      || !TAG_PATTERN.test(tag)
      || !tag.startsWith(`${String(index).padStart(4, '0')}_`)
      || !Number.isSafeInteger(when)
      || (when as number) <= previousTimestamp
    ) {
      throw new Error('MIGRATION_BUNDLE_INVALID');
    }
    previousTimestamp = when as number;
    const sql = readBoundedText(`${migrationsFolder}/${tag}.sql`, MAX_MIGRATION_BYTES);
    return Object.freeze({
      createdAt: String(when),
      hash: createHash('sha256').update(sql).digest('hex'),
    });
  });
  return Object.freeze(result);
}

export function assertAppliedMigrations(
  expected: readonly MigrationFingerprint[],
  applied: readonly MigrationFingerprint[],
): void {
  if (applied.length !== expected.length) throw new Error('DATABASE_SCHEMA_MISMATCH');
  for (let index = 0; index < expected.length; index += 1) {
    const wanted = expected[index];
    const actual = applied[index];
    if (
      !wanted
      || !actual
      || !HASH_PATTERN.test(actual.hash)
      || actual.createdAt !== wanted.createdAt
      || actual.hash !== wanted.hash
    ) {
      throw new Error('DATABASE_SCHEMA_MISMATCH');
    }
  }
}

export const expectedMigrations = loadExpectedMigrations();
