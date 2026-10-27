import { appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { ensureDirectory } from './files.ts';

/**
 * A private record of one run: the commands, their output and the steps. The
 * screen shows what happened in plain words; diagnostics go here. Secrets
 * never do: commands receive them through files, stdin or the environment,
 * none of which is written.
 */
export class RunLog {
  readonly path: string | null;

  constructor(dir: string | null, command: string) {
    if (!dir) {
      this.path = null;
      return;
    }
    ensureDirectory(dir, 0o700);
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    this.path = join(dir, `${command}-${stamp}.log`);
    appendFileSync(this.path, '', { mode: 0o600 });
  }

  write(text: string): void {
    if (!this.path) return;
    appendFileSync(this.path, text.endsWith('\n') ? text : `${text}\n`);
  }

  event(text: string): void {
    this.write(`[${new Date().toISOString()}] ${text}`);
  }
}
