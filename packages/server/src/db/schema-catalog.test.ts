import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  assertSchemaCatalogMatches,
  fingerprintSchemaCatalogDescriptors,
} from './schema-catalog.js';

describe('database schema catalog fingerprint', () => {
  it('binds a sorted descriptor sequence including record boundaries', () => {
    const descriptors = ['["column","a"]', '["relation","a"]'];
    const expected = createHash('sha256')
      .update(`${descriptors[0]}\n${descriptors[1]}\n`)
      .digest('hex');
    assert.equal(fingerprintSchemaCatalogDescriptors(descriptors), expected);
    assert.throws(
      () => fingerprintSchemaCatalogDescriptors([...descriptors].reverse()),
      /DATABASE_SCHEMA_CATALOG_INVALID/,
    );
    assert.throws(
      () => fingerprintSchemaCatalogDescriptors([descriptors[0], descriptors[0]]),
      /DATABASE_SCHEMA_CATALOG_INVALID/,
    );
  });

  it('rejects an altered entry count or catalog digest', () => {
    const expected = { entryCount: 2, sha256: 'a'.repeat(64) };
    assert.doesNotThrow(() => assertSchemaCatalogMatches({ ...expected }, expected));
    assert.throws(
      () => assertSchemaCatalogMatches({ ...expected, entryCount: 1 }, expected),
      /DATABASE_SCHEMA_CATALOG_MISMATCH/,
    );
    assert.throws(
      () => assertSchemaCatalogMatches({ ...expected, sha256: 'b'.repeat(64) }, expected),
      /DATABASE_SCHEMA_CATALOG_MISMATCH/,
    );
  });
});
