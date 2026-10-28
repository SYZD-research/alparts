import { spawn } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import type { Socket } from 'node:net';
import { dirname } from 'node:path';
import type { Docker } from './docker.ts';
import type { MessageKey, Translate } from './i18n.ts';
import type { RunLog } from './log.ts';
import type { Paths } from './paths.ts';
import type { Runner } from './run.ts';
import type { Language } from './settings.ts';
import type { Ui } from './ui.ts';

export interface Options {
  yes: boolean;
  answersFile: string | null;
  disable: boolean;
  scheduled: boolean;
  /** pins: switch the certificate to the spare key. */
  rotate: boolean;
  /** Use an already built alparts:<tag> instead of building one (operators with their own builds, and tests). */
  imageTag: string | null;
}

export interface Context {
  language: Language;
  t: Translate;
  ui: Ui;
  log: RunLog;
  run: Runner;
  docker: Docker;
  paths: Paths;
  /** How the operator starts the setup, for the commands messages suggest. */
  command: string;
  options: Options;
  /**
   * Undo steps for an interruption (Ctrl+C, or systemd stopping a scheduled
   * backup), run newest first: a stopped app is started again, for example.
   */
  cleanups: Array<() => Promise<void>>;
}

/** Runs `work` with `cleanup` registered for an interruption until `work` ends. */
export async function withCleanup<T>(context: Context, cleanup: () => Promise<void>, work: () => Promise<T>): Promise<T> {
  context.cleanups.push(cleanup);
  try {
    return await work();
  } finally {
    const index = context.cleanups.lastIndexOf(cleanup);
    if (index >= 0) context.cleanups.splice(index, 1);
  }
}

/** A failure explained to the operator: what happened, and what to do next. */
export class SetupError extends Error {
  readonly key: MessageKey;
  readonly values: Record<string, string | number>;
  readonly hint: { key: MessageKey; values?: Record<string, string | number> } | null;

  constructor(key: MessageKey, values: Record<string, string | number> = {}, options: { hint?: SetupError['hint']; cause?: unknown } = {}) {
    super(key, { cause: options.cause });
    this.name = 'SetupError';
    this.key = key;
    this.values = values;
    this.hint = options.hint ?? null;
  }
}

/** The operator chose not to go on; what to say has been said. */
export class Cancelled extends Error {
  constructor() {
    super('Cancelled');
    this.name = 'Cancelled';
  }
}

/**
 * Keeps two runs (an update and the nightly backup, say) from working on the
 * deployment at once. A `flock` child holds a kernel lock on the root-only
 * lock file for as long as this process lives: however this process ends, the
 * child's input closes, it exits, and the kernel releases the lock, so no
 * stale lock is ever left to take over. Release resolves once it is free.
 */
export async function acquireLock(path: string): Promise<() => Promise<void>> {
  mkdirSync(dirname(path), { recursive: true, mode: 0o755 });
  // In its own process group, so a Ctrl+C at the terminal leaves the lock held while this process undoes its steps.
  const holder = spawn('flock', ['--exclusive', '--nonblock', path, 'sh', '-c', 'echo locked; exec cat'], { stdio: ['pipe', 'pipe', 'ignore'], detached: true });
  const outcome = await new Promise<'locked' | 'busy' | Error>((resolve) => {
    holder.stdout.once('data', () => resolve('locked'));
    holder.once('error', resolve);
    // flock exits with 1 when another process holds the lock.
    holder.once('exit', (code) => resolve(code === 1 ? 'busy' : new Error(`flock exited with ${code}`)));
  });
  if (outcome === 'busy') throw new SetupError('error.locked', { pid: lockHolder(path) });
  if (outcome instanceof Error) {
    if ((outcome as NodeJS.ErrnoException).code === 'ENOENT') throw new SetupError('error.lockToolMissing', {}, { cause: outcome });
    throw outcome;
  }
  writeFileSync(path, `${process.pid}\n`);
  holder.stdout.destroy();
  // A run that never releases still exits; the child then sees its input close.
  holder.unref();
  (holder.stdin as Socket).unref();
  return () => new Promise((resolve) => {
    if (holder.exitCode !== null || holder.signalCode !== null) return resolve();
    holder.ref();
    holder.once('exit', () => resolve());
    holder.stdin.end();
  });
}

/** The process ID the holder wrote into the lock file, for the message. */
function lockHolder(path: string): string {
  try {
    const pid = readFileSync(path, 'utf8').trim();
    return /^\d+$/.test(pid) ? pid : '?';
  } catch {
    return '?';
  }
}
