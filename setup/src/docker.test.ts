import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Docker, parseComposePs, versionAtLeast } from './docker.ts';
import { systemPaths } from './paths.ts';
import type { Runner } from './run.ts';

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

test('an interruption stops the one-off containers of its own run and no others', async () => {
  const calls: string[][] = [];
  const run: Runner = async (command, args) => {
    calls.push([command, ...args]);
    return { code: 0, stdout: args[0] === 'ps' ? 'c0ffee\n' : '', stderr: '' };
  };
  const ours = new Docker(run, systemPaths('/', '/opt/alparts'));
  const theirs = new Docker(run, systemPaths('/', '/opt/alparts'));
  const labelOf = (call: string[]) => call[call.indexOf('--label') + 1]!;
  await ours.runOnce('backup', ['/opt/alparts/scripts/backup.sh']);
  await theirs.runOnce('backup', ['/opt/alparts/scripts/backup.sh']);
  const label = labelOf(calls[0]!);
  assert.match(label, /^alparts-setup\.run=[0-9a-f]{16}$/);
  assert.notEqual(labelOf(calls[1]!), label);

  calls.length = 0;
  await ours.stopOneOffs();
  assert.deepEqual(calls, [
    ['docker', 'ps', '--all', '--quiet', '--filter', `label=${label}`],
    ['docker', 'stop', '--time', '30', 'c0ffee'],
    ['docker', 'rm', 'c0ffee'],
  ]);
  // Nothing starts after that, such as a migration after a backup.
  await assert.rejects(ours.runOnce('migrator', []), /interrupted/);
  assert.equal(calls.length, 3);
});
