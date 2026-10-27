import { closeSync, openSync, readFileSync, unlinkSync, writeSync } from 'node:fs';
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

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/**
 * Keeps two runs (an update and the nightly backup, say) from working on
 * the deployment at once. A lock left by a process that has gone is taken over.
 */
export function acquireLock(path: string): () => void {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const descriptor = openSync(path, 'wx', 0o600);
      writeSync(descriptor, String(process.pid));
      closeSync(descriptor);
      return () => {
        try {
          if (readFileSync(path, 'utf8') === String(process.pid)) unlinkSync(path);
        } catch {
          // Already gone.
        }
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      let holder = 0;
      try {
        holder = Number(readFileSync(path, 'utf8').trim());
      } catch {
        continue;
      }
      if (Number.isSafeInteger(holder) && holder > 0 && holder !== process.pid && processAlive(holder)) {
        throw new SetupError('error.locked', { pid: holder });
      }
      try {
        unlinkSync(path);
      } catch {
        // Another run removed it first.
      }
    }
  }
  throw new SetupError('error.locked', { pid: '?' });
}
