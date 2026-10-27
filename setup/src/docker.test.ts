import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseComposePs, versionAtLeast } from './docker.ts';

test('versions compare numerically, with or without a leading v', () => {
  assert.ok(versionAtLeast('2.20.0', '2.20.0'));
  assert.ok(versionAtLeast('v2.29.1', '2.20.0'));
  assert.ok(versionAtLeast('5.6.1', '2.20.0'));
  assert.ok(!versionAtLeast('2.9.9', '2.20.0'));
  assert.ok(!versionAtLeast('1.29.2', '2.20.0'));
});

test('compose ps output is read in both the line and the array form', () => {
  const line = '{"Service":"app","State":"running","Health":"healthy"}\n{"Service":"proxy","State":"exited","Health":""}\n';
  const expected = [{ service: 'app', state: 'running', health: 'healthy' }, { service: 'proxy', state: 'exited', health: '' }];
  assert.deepEqual(parseComposePs(line), expected);
  assert.deepEqual(parseComposePs(`[${line.trim().split('\n').join(',')}]`), expected);
  assert.deepEqual(parseComposePs(''), []);
});
