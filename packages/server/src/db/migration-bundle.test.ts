import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  assertAppliedMigrations,
  expectedMigrations,
  loadExpectedMigrations,
  resolveMigrationsFolder,
} from './migration-bundle.js';

describe('runtime migration bundle', () => {
  it('loads a bounded ordered fingerprint set from the source or OCI layout', () => {
    const loaded = loadExpectedMigrations(resolveMigrationsFolder());
    assert.equal(loaded.length, expectedMigrations.length);
    assert.ok(loaded.length > 0);
    assert.match(loaded.at(-1)?.hash ?? '', /^[a-f0-9]{64}$/);
    assert.doesNotThrow(() => assertAppliedMigrations(expectedMigrations, [...loaded]));
  });

  it('fails closed for missing, extra, reordered, or modified migration records', () => {
    const applied = expectedMigrations.map((migration) => ({ ...migration }));
    assert.throws(
      () => assertAppliedMigrations(expectedMigrations, applied.slice(0, -1)),
      /DATABASE_SCHEMA_MISMATCH/,
    );
    assert.throws(
      () => assertAppliedMigrations(expectedMigrations, [...applied, applied.at(-1)!]),
      /DATABASE_SCHEMA_MISMATCH/,
    );
    assert.throws(
      () => assertAppliedMigrations(expectedMigrations, [...applied].reverse()),
      /DATABASE_SCHEMA_MISMATCH/,
    );
    const modified = applied.map((migration) => ({ ...migration }));
    modified[modified.length - 1]!.hash = '0'.repeat(64);
    assert.throws(
      () => assertAppliedMigrations(expectedMigrations, modified),
      /DATABASE_SCHEMA_MISMATCH/,
    );
  });
});
