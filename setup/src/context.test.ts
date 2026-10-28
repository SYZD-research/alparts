import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { test } from 'node:test';
import { acquireLock, SetupError } from './context.ts';

const lockedBy = (pid: number) => (error: unknown) => error instanceof SetupError && error.key === 'error.locked' && error.values.pid === String(pid);

test('a second run is refused while the first holds the lock, and admitted once it lets go', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'alparts-lock-'));
  try {
    // The directory that holds the lock is made when it is missing.
    const path = join(dir, 'run', 'setup.lock');
    const release = await acquireLock(path);
    await assert.rejects(acquireLock(path), lockedBy(process.pid));
    await release();
    await (await acquireLock(path))();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a run that is killed leaves no lock behind', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'alparts-lock-'));
  try {
    const path = join(dir, 'setup.lock');
    const script = `const { acquireLock } = await import(${JSON.stringify(new URL('./context.ts', import.meta.url).href)});
      await acquireLock(${JSON.stringify(path)}); console.log('held'); setInterval(() => {}, 1000);`;
    const holder = spawn(process.execPath, ['--input-type=module', '-e', script], { stdio: ['ignore', 'pipe', 'inherit'] });
    await once(holder.stdout, 'data');
    await assert.rejects(acquireLock(path), lockedBy(holder.pid!));
    holder.kill('SIGKILL');
    await once(holder, 'exit');
    // The lock's own child sees its input close and exits right after.
    for (let attempt = 0; ; attempt += 1) {
      try {
        await (await acquireLock(path))();
        break;
      } catch (error) {
        if (attempt === 50 || !(error instanceof SetupError)) throw error;
        await sleep(100);
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
