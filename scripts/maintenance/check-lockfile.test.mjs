import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { lockfileViolations } from './check-lockfile.mjs';

const lockfile = (resolution) => `lockfileVersion: '9.0'

importers:

  packages/server:
    dependencies:
      '@alparts/shared':
        specifier: workspace:*
        version: link:../shared

packages:

  zod@4.6.7:
    resolution: {integrity: sha512-AbC+/9=}

  left-pad@1.3.0:
${resolution}
`;

test('lockfileViolations accepts registry packages pinned by their hash', () => {
  assert.deepEqual(lockfileViolations(lockfile('    resolution: {integrity: sha1-xyz0+/=}')), []);
});

test('lockfileViolations refuses tarball, git and directory resolutions', () => {
  for (const resolution of [
    '    resolution: {tarball: https://example.test/left-pad.tgz}',
    '    resolution: {integrity: sha512-AbC=, tarball: https://example.test/left-pad.tgz}',
    '    resolution: {commit: 0123abc, repo: https://example.test/left-pad.git, type: git}',
    '    resolution: {directory: ../left-pad, type: directory}',
    '    resolution:\n      tarball: https://example.test/left-pad.tgz',
  ]) {
    assert.notDeepEqual(lockfileViolations(lockfile(resolution)), [], resolution);
  }
  assert.deepEqual(lockfileViolations(lockfile('    resolution: {tarball: https://example.test/x.tgz}')), [
    'line 17: resolution: {tarball: https://example.test/x.tgz}',
  ]);
});

test('the repository lockfile passes', () => {
  const text = readFileSync(new URL('../../pnpm-lock.yaml', import.meta.url), 'utf8');
  assert.deepEqual(lockfileViolations(text), []);
});
