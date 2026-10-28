import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Docker, parseComposePs, versionAtLeast } from './docker.ts';
import { systemPaths } from './paths.ts';
import type { RunResult, Runner } from './run.ts';

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

/** A stand-in for the docker command: `compose run` waits until the test ends it, anything else answers at once. */
function fakeDocker() {
  const calls: string[][] = [];
  const limits: Array<number | undefined> = [];
  const pending: Array<{ resolve: (result: RunResult) => void; reject: (error: Error) => void }> = [];
  const run: Runner = (command, args, options) => {
    calls.push([command, ...args]);
    limits.push(options?.timeoutMs);
    if (args.includes('run')) return new Promise((resolve, reject) => pending.push({ resolve, reject }));
    return Promise.resolve({ code: 0, stdout: '', stderr: '' });
  };
  return { calls, limits, pending, docker: new Docker(run, systemPaths('/', '/opt/alparts')) };
}

const nameOf = (call: string[]) => call[call.indexOf('--name') + 1]!;
const removal = (name: string) => [['docker', 'stop', '--time', '30', name], ['docker', 'rm', '--force', name]];

async function until(check: () => boolean): Promise<void> {
  while (!check()) await new Promise((resolve) => setTimeout(resolve, 5));
}

test('a one-off container whose command fails or runs out of time is stopped and removed', async () => {
  const { calls, limits, pending, docker } = fakeDocker();
  const timedOut = docker.runOnce('backup', ['/opt/alparts/scripts/backup.sh'], { check: false });
  const name = nameOf(calls[0]!);
  assert.match(name, /^alparts-production-backup-run-[0-9a-f]{12}$/);
  // The runner ends the command at its time limit; the container would go on.
  pending[0]!.resolve({ code: 143, stdout: '', stderr: '' });
  assert.equal((await timedOut).code, 143);
  assert.deepEqual(calls.slice(1), removal(name));
  // A Docker that does not answer holds nothing up: stopping and removing have time limits.
  assert.deepEqual(limits.slice(1), [60_000, 30_000]);

  calls.length = 0;
  const failed = docker.runOnce('migrator', []);
  const other = nameOf(calls[0]!);
  pending[1]!.reject(new Error('migrator exited with 1'));
  await assert.rejects(failed, /exited with 1/);
  assert.deepEqual(calls.slice(1), removal(other));
});

test('an interruption stops the one-off containers of its own run, then starts no more', async () => {
  const ours = fakeDocker();
  const theirs = fakeDocker();
  const backup = ours.docker.runOnce('backup', ['/opt/alparts/scripts/backup.sh']).catch((error: unknown) => error);
  void theirs.docker.runOnce('backup', ['/opt/alparts/scripts/backup.sh']);
  const name = nameOf(ours.calls[0]!);
  const stopping = ours.docker.stopOneOffs();
  await until(() => ours.calls.length > 2);
  assert.deepEqual(ours.calls.slice(1, 3), removal(name));
  // With its container gone, the command that started it ends.
  ours.pending[0]!.reject(new Error('backup exited with 143'));
  await stopping;
  assert.ok(await backup instanceof Error);
  assert.ok(!ours.calls.some((call) => call.includes(nameOf(theirs.calls[0]!))));
  // Nothing starts after that, such as a migration after the backup.
  const count = ours.calls.length;
  await assert.rejects(ours.docker.runOnce('migrator', []), /interrupted/);
  assert.equal(ours.calls.length, count);
});
