import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseLockfile, releaseLine, assessPackage, runtimeVersions, assessRuntime,
  renderReport, fingerprint, countFindings,
} from './end-of-support.mjs';

const NOW = new Date('2026-10-06T00:00:00Z');

const LOCKFILE = `lockfileVersion: '9.0'

importers:

  .:
    devDependencies:
      secretlint:
        specifier: 13.0.5
        version: 13.0.5(supports-color@10.2.2)

  packages/client:
    dependencies:
      '@alparts/shared':
        specifier: workspace:*
        version: link:../shared
      react:
        specifier: ^18.3.1
        version: 18.3.1
    devDependencies:
      '@types/react':
        specifier: ^18.3.12
        version: 18.3.31

packages:

  '@esbuild-kit/core-utils@3.3.2':
    resolution: {integrity: sha512-x}
    deprecated: 'Merged into tsx: https://tsx.hirok.io'

  glob@7.2.3:
    resolution: {integrity: sha512-y}
    deprecated: 'Old versions of glob are not supported, isn''t it'

  react@18.3.1:
    resolution: {integrity: sha512-z}

snapshots:

  react@18.3.1:
    deprecated: not a package entry
`;

test('parseLockfile reads direct dependencies and deprecated packages', () => {
  const { direct, deprecated } = parseLockfile(LOCKFILE);
  assert.deepEqual(direct, [
    { name: 'secretlint', importer: '.', version: '13.0.5' },
    { name: 'react', importer: 'packages/client', version: '18.3.1' },
    { name: '@types/react', importer: 'packages/client', version: '18.3.31' },
  ]);
  assert.deepEqual(deprecated, [
    { name: '@esbuild-kit/core-utils', version: '3.3.2', message: 'Merged into tsx: https://tsx.hirok.io' },
    { name: 'glob', version: '7.2.3', message: "Old versions of glob are not supported, isn't it" },
  ]);
});

test('releaseLine follows semver compatibility', () => {
  assert.deepEqual(releaseLine('18.3.1'), [18]);
  assert.deepEqual(releaseLine('0.5.2'), [0, 5]);
  assert.equal(releaseLine('not-a-version'), null);
});

function registryDoc(times, distTags, versions = {}) {
  return { 'dist-tags': distTags, time: { created: '2010-01-01T00:00:00Z', ...times }, versions };
}

test('assessPackage flags a release line left behind by a newer major', () => {
  const doc = registryDoc({
    '18.3.1': '2024-04-26T00:00:00Z',
    '19.0.0': '2024-12-05T00:00:00Z',
    '19.3.0': '2026-09-09T00:00:00Z',
  }, { latest: '19.3.0' });
  assert.deepEqual(assessPackage(doc, '18.3.1', NOW), {
    kind: 'stale-line', line: '18.x', lastVersion: '18.3.1', lastPublished: '2024-04-26', latest: '19.3.0',
  });
  assert.equal(assessPackage(doc, '19.3.0', NOW), null);
});

test('assessPackage ignores prereleases when finding the last release of a line', () => {
  const doc = registryDoc({
    '5.9.3': '2025-09-30T00:00:00Z',
    '5.10.0-dev.1': '2026-09-01T00:00:00Z',
    '7.0.2': '2026-09-20T00:00:00Z',
  }, { latest: '7.0.2' });
  assert.equal(assessPackage(doc, '5.9.3', NOW).lastVersion, '5.9.3');
});

test('assessPackage keeps recently patched and LTS-tagged lines', () => {
  const patched = registryDoc({
    '3.4.18': '2025-01-01T00:00:00Z',
    '3.4.19': '2026-06-01T00:00:00Z',
    '4.3.3': '2026-09-01T00:00:00Z',
  }, { latest: '4.3.3' });
  assert.equal(assessPackage(patched, '3.4.18', NOW), null);
  const lts = registryDoc({ '3.4.19': '2025-01-01T00:00:00Z', '4.3.3': '2026-09-01T00:00:00Z' },
    { latest: '4.3.3', 'v3-lts': '3.4.19' });
  assert.equal(assessPackage(lts, '3.4.19', NOW), null);
});

test('assessPackage treats each 0.x minor as its own line', () => {
  const doc = registryDoc({ '0.5.2': '2024-01-01T00:00:00Z', '0.6.0': '2026-09-01T00:00:00Z' }, { latest: '0.6.0' });
  assert.equal(assessPackage(doc, '0.5.2', NOW).line, '0.5.x');
});

test('assessPackage reports a deprecated installed version first', () => {
  const doc = registryDoc({ '1.0.6': '2016-01-01T00:00:00Z' }, { latest: '1.0.6' },
    { '1.0.6': { deprecated: 'This module is not supported' } });
  assert.deepEqual(assessPackage(doc, '1.0.6', NOW), { kind: 'deprecated', message: 'This module is not supported' });
});

test('runtimeVersions collects runtimes from images, workflows and Electron', () => {
  const runtimes = runtimeVersions({
    dockerfile: 'FROM node:24-alpine3.22@sha256:abc AS build\nFROM node:24-alpine3.22@sha256:abc AS runtime\n',
    compose: '    image: postgres:16.10-alpine3.22@sha256:def\n',
    workflows: [['.github/workflows/ci.yml', '          node-version: "24.8.0"\n']],
    direct: [{ name: 'electron', version: '44.1.0', importer: 'packages/desktop' }],
  });
  assert.deepEqual(runtimes, [
    { product: 'nodejs', name: 'Node.js', cycle: '24', sources: ['.github/workflows/ci.yml', 'Dockerfile'] },
    { product: 'alpine-linux', name: 'Alpine Linux', cycle: '3.22', sources: ['Dockerfile', 'docker-compose.yml'] },
    { product: 'postgresql', name: 'PostgreSQL', cycle: '16', sources: ['docker-compose.yml'] },
    { product: 'electron', name: 'Electron', cycle: '44', sources: ['packages/desktop'] },
  ]);
});

test('assessRuntime reports ended runtimes and warns ahead of the end date', () => {
  assert.deepEqual(assessRuntime({ isEol: true, eolFrom: '2026-06-01' }, NOW),
    { kind: 'runtime-ended', eolFrom: '2026-06-01' });
  assert.deepEqual(assessRuntime({ isEol: false, eolFrom: '2026-10-20' }, NOW),
    { kind: 'runtime-ending', eolFrom: '2026-10-20', remaining: 14 });
  assert.equal(assessRuntime({ isEol: false, eolFrom: '2028-04-30' }, NOW), null);
  assert.equal(assessRuntime({ isEol: false, eolFrom: null }, NOW), null);
});

test('renderReport lists findings and escapes table cells', () => {
  const report = {
    runtimes: [{ product: 'nodejs', name: 'Node.js', cycle: '22', sources: ['Dockerfile'],
      finding: { kind: 'runtime-ended', eolFrom: '2026-04-30' } }],
    packages: [{ name: 'react', version: '18.3.1', importers: ['packages/client'],
      finding: { kind: 'stale-line', line: '18.x', lastVersion: '18.3.1', lastPublished: '2024-04-26', latest: '19.3.0' } }],
    indirect: [{ name: 'glob', version: '7.2.3', message: 'unsupported | update \\| C:\\path' }],
  };
  const markdown = renderReport(report, NOW);
  assert.match(markdown, new RegExp(`^<!-- end-of-support:${fingerprint(report)} -->`));
  assert.match(markdown, /\| Node\.js \| 22 \| 2026-04-30 にサポート終了 \| Dockerfile \|/);
  assert.match(markdown, /\| react \| 18\.3\.1 \| 18\.x の最終リリースは 2024-04-26（18\.3\.1）。最新は 19\.3\.0 \| packages\/client \|/);
  assert.ok(markdown.includes('| glob@7.2.3 | 非推奨: unsupported \\| update \\\\\\| C:\\\\path |'));
  assert.equal(countFindings(report), 3);
});

test('renderReport says so when nothing is found', () => {
  const empty = { runtimes: [], packages: [], indirect: [] };
  assert.match(renderReport(empty, NOW), /該当する依存関係はありません。/);
  assert.equal(countFindings(empty), 0);
});

test('fingerprint changes only when the set of findings changes', () => {
  const finding = { kind: 'deprecated', message: 'old' };
  const a = { runtimes: [], packages: [{ name: 'x', version: '1.0.0', importers: ['a'], finding }], indirect: [] };
  const b = { runtimes: [], packages: [{ name: 'x', version: '1.0.0', importers: ['b'], finding }], indirect: [] };
  const c = { runtimes: [], packages: [{ name: 'x', version: '1.0.1', importers: ['a'], finding }], indirect: [] };
  assert.equal(fingerprint(a), fingerprint(b));
  assert.notEqual(fingerprint(a), fingerprint(c));
});
