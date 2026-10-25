import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dirDocPath, driftItems, fileDocPath, parseLog, renderDocsTask } from './docs-drift.mjs';

test('description paths sit in the directory of what they describe', () => {
  assert.equal(fileDocPath('packages/server/src/app.ts'), 'packages/server/src/.dirdoc/app.ts.dirdoc_pfd');
  assert.equal(dirDocPath('packages/server/src'), 'packages/server/src/.dirdoc/.dirdoc_dsd');
});

test('parseLog keeps the latest change of each path and of each directory\'s files', () => {
  const log = [
    '@300', '', 'M\tpackages/server/src/app.ts', 'A\tpackages/server/src/new.ts',
    '@200', '', 'A\tpackages/server/src/app.ts', 'D\tpackages/server/src/routes/old.ts', 'M\t"docs/odd\\tname.md"',
    '@100', '', 'A\tpackages/server/src/new.ts',
  ].join('\n');
  const { changed, structure } = parseLog(log);
  assert.equal(changed.get('packages/server/src/app.ts'), 300);
  assert.equal(changed.get('packages/server/src/new.ts'), 300);
  assert.equal(changed.get('packages/server/src/routes/old.ts'), 200);
  assert.equal(changed.size, 3);
  assert.equal(structure.get('packages/server/src'), 300);
  assert.equal(structure.get('packages/server/src/routes'), 200);
});

const src = 'packages/server/src';

test('driftItems finds stale, missing and orphaned descriptions in the writable areas', () => {
  const files = [
    `${src}/.dirdoc/.dirdoc_dsd`,
    `${src}/app.ts`, `${src}/.dirdoc/app.ts.dirdoc_pfd`,
    `${src}/index.ts`, `${src}/.dirdoc/index.ts.dirdoc_pfd`,
    `${src}/new.ts`, `${src}/schema.json`,
    `${src}/.dirdoc/gone.ts.dirdoc_pfd`,
    `${src}/routes/a.ts`,
    'scripts/x.mjs', 'packages/server/package.json', 'README.md',
  ];
  const changed = new Map([
    [`${src}/app.ts`, 300], [`${src}/.dirdoc/app.ts.dirdoc_pfd`, 200],
    [`${src}/index.ts`, 200], [`${src}/.dirdoc/index.ts.dirdoc_pfd`, 200],
    [`${src}/.dirdoc/.dirdoc_dsd`, 250],
  ]);
  const structure = new Map([[src, 300]]);
  assert.deepEqual(driftItems(files, { changed, structure }), [
    { kind: 'file-changed', path: `${src}/app.ts` },
    { kind: 'dir-changed', path: `${src}/` },
    { kind: 'file-missing', path: `${src}/new.ts` },
    { kind: 'file-missing', path: `${src}/routes/a.ts` },
    { kind: 'dir-missing', path: `${src}/routes/` },
    { kind: 'orphan', path: `${src}/.dirdoc/gone.ts.dirdoc_pfd` },
  ]);
});

test('a description written in the same commit as the code is current', () => {
  const files = [`${src}/.dirdoc/.dirdoc_dsd`, `${src}/app.ts`, `${src}/.dirdoc/app.ts.dirdoc_pfd`];
  const changed = new Map(files.map((file) => [file, 100]));
  assert.deepEqual(driftItems(files, { changed, structure: new Map([[src, 100]]) }), []);
});

test('renderDocsTask groups the items and says how many are left', () => {
  const task = renderDocsTask([
    { kind: 'file-changed', path: `${src}/app.ts` },
    { kind: 'dir-missing', path: `${src}/routes/` },
  ], 5);
  assert.match(task, /## Files whose code changed after their description\n\n- packages\/server\/src\/app\.ts\n/);
  assert.match(task, /## Directories without a description\n\n- packages\/server\/src\/routes\/\n/);
  assert.doesNotMatch(task, /Files without a description/);
  assert.match(task, /3 more items are left for later runs/);
});
