import { spawn } from 'node:child_process';
import type { RunLog } from './log.ts';

export interface RunOptions {
  /** Written to stdin and never logged (SQL with role verifiers, for example). */
  input?: string;
  /** Added to the environment and never logged. */
  env?: Record<string, string>;
  /** Removed from the inherited environment. */
  clearEnv?: (name: string) => boolean;
  cwd?: string;
  /** Asks the command to stop (SIGTERM) after this long. */
  timeoutMs?: number;
  /** Once asked to stop, how long the command has before it is killed (default 10 seconds). */
  graceMs?: number;
  /** Throw on a non-zero exit (default). */
  check?: boolean;
  /** Let the child use this terminal, for commands the operator watches (logs -f). */
  interactive?: boolean;
  /** Called with each chunk of output, after it is logged. */
  onOutput?: (chunk: string) => void;
}

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

export class CommandError extends Error {
  readonly result: RunResult;

  constructor(command: string, result: RunResult) {
    super(`${command} exited with ${result.code}: ${tail(result.stderr || result.stdout, 2000)}`);
    this.name = 'CommandError';
    this.result = result;
  }
}

/** The end of a long output, which is where errors usually are. */
export function tail(text: string, characters: number): string {
  return text.length > characters ? `…${text.slice(-characters)}` : text;
}

const MAX_CAPTURE = 4 * 1024 * 1024;

export type Runner = (command: string, args: string[], options?: RunOptions) => Promise<RunResult>;

export function createRunner(log: RunLog): Runner {
  return (command, args, options = {}) => new Promise((resolve, reject) => {
    log.event(`$ ${[command, ...args].map(quoteForLog).join(' ')}`);
    const inherited = Object.fromEntries(Object.entries(process.env).filter(([name]) => !options.clearEnv?.(name)));
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: { ...inherited, ...options.env },
      stdio: options.interactive ? 'inherit' : ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const capture = (current: string, chunk: string) => {
      const next = current + chunk;
      return next.length > MAX_CAPTURE ? next.slice(-MAX_CAPTURE) : next;
    };
    child.stdout?.setEncoding('utf8').on('data', (chunk: string) => {
      stdout = capture(stdout, chunk);
      log.write(chunk);
      options.onOutput?.(chunk);
    });
    child.stderr?.setEncoding('utf8').on('data', (chunk: string) => {
      stderr = capture(stderr, chunk);
      log.write(chunk);
      options.onOutput?.(chunk);
    });
    if (child.stdin) {
      child.stdin.on('error', () => undefined);
      child.stdin.end(options.input ?? '');
    }
    let kill: ReturnType<typeof setTimeout> | null = null;
    const timer = options.timeoutMs ? setTimeout(() => {
      child.kill('SIGTERM');
      // A command that ignores the request is killed, so that its caller does not wait for ever.
      kill = setTimeout(() => child.kill('SIGKILL'), options.graceMs ?? 10_000);
    }, options.timeoutMs) : null;
    const clearTimers = () => {
      if (timer) clearTimeout(timer);
      if (kill) clearTimeout(kill);
    };
    child.on('error', (error) => {
      clearTimers();
      reject(error);
    });
    child.on('close', (code, signal) => {
      clearTimers();
      const result = { code: code ?? (signal ? 128 : 1), stdout, stderr };
      log.event(`exit ${result.code}${signal ? ` (${signal})` : ''}`);
      if (result.code !== 0 && options.check !== false) reject(new CommandError(command, result));
      else resolve(result);
    });
  });
}

function quoteForLog(argument: string): string {
  return /^[A-Za-z0-9_./:=@,+-]+$/.test(argument) ? argument : `'${argument.replace(/'/g, `'\\''`)}'`;
}
