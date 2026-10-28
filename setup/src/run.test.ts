import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RunLog } from './log.ts';
import { createRunner } from './run.ts';

test('a command past its time limit that ignores the request to stop is killed', async () => {
  const run = createRunner(new RunLog(null, 'test'));
  const started = Date.now();
  // Ignores SIGTERM and would run for about 3 seconds; the kill after the grace period ends it first.
  const script = 'trap "" TERM; i=0; while [ "$i" -lt 60 ]; do sleep 0.05; i=$((i + 1)); done';
  const result = await run('sh', ['-c', script], { timeoutMs: 100, graceMs: 200, check: false });
  assert.notEqual(result.code, 0);
  assert.ok(Date.now() - started < 2000, `ended after ${Date.now() - started} ms`);
});
