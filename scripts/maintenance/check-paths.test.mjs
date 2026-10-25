import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseRawDiff, refusedChanges } from './check-paths.mjs';

const zero = '0'.repeat(40);
const raw = (entries) => entries.map(([mode, status, path]) => `:100644 ${mode} ${zero} ${zero} ${status}\0${path}\0`).join('');

test('parseRawDiff reads the new mode and the path of each change', () => {
  const text = raw([['100644', 'M', 'docs/a b.md'], ['000000', 'D', 'packages/server/src/old.ts'], ['120000', 'A', 'docs/link']]);
  assert.deepEqual(parseRawDiff(text), [
    { mode: '100644', path: 'docs/a b.md' },
    { mode: '000000', path: 'packages/server/src/old.ts' },
    { mode: '120000', path: 'docs/link' },
  ]);
  assert.deepEqual(parseRawDiff(''), []);
});

test('refusedChanges accepts source and documentation changes and deletions', () => {
  const entries = [
    { mode: '100644', path: 'packages/server/src/index.ts' },
    { mode: '100755', path: 'packages/client/src/tool.ts' },
    { mode: '000000', path: 'docs/old.md' },
  ];
  assert.deepEqual(refusedChanges(entries), []);
});

test('refusedChanges refuses other paths, links and submodules, and paths outside the repository', () => {
  const entries = [
    { mode: '100644', path: '.pnpmfile.mjs' },
    { mode: '100644', path: 'packages/evil/package.yaml' },
    { mode: '000000', path: '.github/workflows/ci.yml' },
    { mode: '120000', path: 'packages/server/src/link.ts' },
    { mode: '160000', path: 'docs/vendor' },
    { mode: '100644', path: '../outside' },
  ];
  assert.deepEqual(refusedChanges(entries), [
    '.pnpmfile.mjs',
    'packages/evil/package.yaml',
    '.github/workflows/ci.yml',
    'packages/server/src/link.ts (not a regular file)',
    'docs/vendor (not a regular file)',
    '../outside',
  ]);
});

test('refusedChanges applies the manifest rules only to workspace manifests, and only when asked', () => {
  const checked = [];
  const manifestViolations = (path) => {
    checked.push(path);
    return path === 'packages/server/package.json' ? ['packages/server/package.json: "scripts" changed'] : [];
  };
  const entries = [
    { mode: '100644', path: 'package.json' },
    { mode: '100644', path: 'packages/server/package.json' },
    { mode: '100644', path: 'packages/server/src/package.json' },
    { mode: '100644', path: 'pnpm-lock.yaml' },
  ];
  assert.deepEqual(refusedChanges(entries, { allowManifests: true, allowed: ['pnpm-lock.yaml'], manifestViolations }), [
    'packages/server/package.json: "scripts" changed',
    'packages/server/src/package.json',
  ]);
  assert.deepEqual(checked, ['package.json', 'packages/server/package.json']);
  assert.deepEqual(refusedChanges(entries, { manifestViolations }), [
    'package.json', 'packages/server/package.json', 'packages/server/src/package.json', 'pnpm-lock.yaml',
  ]);
});

test('an allowed path still has to be a regular file', () => {
  assert.deepEqual(refusedChanges([{ mode: '120000', path: 'pnpm-lock.yaml' }], { allowed: ['pnpm-lock.yaml'] }), [
    'pnpm-lock.yaml (not a regular file)',
  ]);
});

test('docsOnly accepts nothing but dirdoc descriptions', () => {
  const entries = [
    { mode: '100644', path: 'packages/server/src/.dirdoc/app.ts.dirdoc_pfd' },
    { mode: '000000', path: 'packages/server/src/.dirdoc/old.ts.dirdoc_pfd' },
    { mode: '100644', path: 'packages/server/src/app.ts' },
    { mode: '100644', path: 'scripts/.dirdoc/.dirdoc_dsd' },
    { mode: '120000', path: 'docs/.dirdoc/.dirdoc_dsd' },
  ];
  assert.deepEqual(refusedChanges(entries, { docsOnly: true }), [
    'packages/server/src/app.ts', 'scripts/.dirdoc/.dirdoc_dsd', 'docs/.dirdoc/.dirdoc_dsd (not a regular file)',
  ]);
  assert.deepEqual(refusedChanges(entries.slice(0, 3)), []);
});
