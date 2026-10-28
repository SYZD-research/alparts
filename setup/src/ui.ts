import { createInterface, type Interface } from 'node:readline/promises';
import { Writable } from 'node:stream';

/**
 * The terminal side of the setup: headings, progress, and questions. Output
 * stays plain when stdout is not a terminal or NO_COLOR is set, so logs and
 * pipes get readable text.
 */

export interface UiStreams {
  input: NodeJS.ReadableStream & { isTTY?: boolean; setRawMode?: (mode: boolean) => unknown };
  output: NodeJS.WritableStream & { isTTY?: boolean; columns?: number };
}

const SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/** Columns a string takes in a terminal: two for East Asian wide and full-width characters. */
export function displayWidth(text: string): number {
  let width = 0;
  for (const character of text) {
    width += /[\u1100-\u115f\u2e80-\u303e\u3041-\u33ff\u3400-\u4dbf\u4e00-\u9fff\ua000-\ua4cf\uac00-\ud7a3\uf900-\ufaff\ufe30-\ufe4f\uff00-\uff60\uffe0-\uffe6]/u.test(character) ? 2 : 1;
  }
  return width;
}

/** Label/value rows with the values lined up, as a terminal shows them. */
export function alignRows(rows: Array<[string, string]>): string[] {
  const width = Math.max(...rows.map(([label]) => displayWidth(label)));
  return rows.map(([label, value]) => `${label}${' '.repeat(width - displayWidth(label) + 2)}${value}`);
}

export class Interrupted extends Error {
  constructor() {
    super('Interrupted');
    this.name = 'Interrupted';
  }
}

/** Swallows what readline echoes while a secret is typed. */
class MutableOutput extends Writable {
  muted = false;
  readonly target: NodeJS.WritableStream;

  constructor(target: NodeJS.WritableStream) {
    super();
    this.target = target;
  }

  override _write(chunk: Buffer | string, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    if (!this.muted) this.target.write(chunk);
    callback();
  }
}

export interface ChoiceOption<T> {
  value: T;
  label: string;
}

export class Ui {
  readonly interactive: boolean;
  private readonly color: boolean;
  private readonly streams: UiStreams;
  private readline: Interface | null = null;
  private readonly pending: string[] = [];
  private readonly waiters: Array<(line: string | null) => void> = [];
  private readonly mutableOutput: MutableOutput;
  private spinnerLine = false;

  constructor(streams: UiStreams = { input: process.stdin, output: process.stdout }, options: { interactive?: boolean } = {}) {
    this.streams = streams;
    this.interactive = options.interactive ?? Boolean(streams.input.isTTY && streams.output.isTTY);
    this.color = Boolean(streams.output.isTTY) && !process.env.NO_COLOR && process.env.TERM !== 'dumb';
    this.mutableOutput = new MutableOutput(streams.output);
  }

  private paint(code: string, text: string): string {
    return this.color ? `\u001b[${code}m${text}\u001b[0m` : text;
  }

  bold(text: string): string {
    return this.paint('1', text);
  }

  dim(text: string): string {
    return this.paint('2', text);
  }

  private write(text: string): void {
    this.clearSpinner();
    this.streams.output.write(text);
  }

  line(text = ''): void {
    this.write(`${text}\n`);
  }

  title(text: string): void {
    this.line();
    this.line(this.paint('1;36', text));
  }

  section(text: string): void {
    this.line();
    this.line(this.paint('1', `▸ ${text}`));
  }

  /** Indented explanation under a section. */
  note(text: string): void {
    for (const paragraph of text.split('\n')) this.line(`  ${paragraph}`);
  }

  success(text: string): void {
    this.line(`  ${this.paint('32', '✔')} ${text}`);
  }

  warning(text: string): void {
    this.line(`  ${this.paint('33', '⚠')} ${text}`);
  }

  failure(text: string): void {
    this.line(`  ${this.paint('31', '✖')} ${text}`);
  }

  private clearSpinner(): void {
    if (this.spinnerLine) {
      this.streams.output.write('\r\u001b[2K');
      this.spinnerLine = false;
    }
  }

  /**
   * Runs one step with a spinner and the elapsed time on a terminal, or a
   * start line elsewhere, then marks it done or failed. `done` may describe
   * the result, or return a warning for a step that finished short of its goal.
   */
  async task<T>(label: string, work: () => Promise<T>, done: (result: T) => string | { warning: string } = () => label): Promise<T> {
    const started = Date.now();
    let frame = 0;
    let timer: NodeJS.Timeout | null = null;
    if (this.streams.output.isTTY) {
      const render = () => {
        const seconds = Math.floor((Date.now() - started) / 1000);
        const elapsed = seconds >= 5 ? this.dim(` ${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`) : '';
        this.streams.output.write(`\r\u001b[2K  ${this.paint('36', SPINNER[frame++ % SPINNER.length]!)} ${label}${elapsed}`);
        this.spinnerLine = true;
      };
      render();
      timer = setInterval(render, 100);
    } else {
      this.line(`  … ${label}`);
    }
    try {
      const result = await work();
      if (timer) clearInterval(timer);
      const outcome = done(result);
      if (typeof outcome === 'string') this.success(outcome);
      else this.warning(outcome.warning);
      return result;
    } catch (error) {
      if (timer) clearInterval(timer);
      this.failure(label);
      throw error;
    }
  }

  private reader(): Interface {
    if (!this.readline) {
      const readline = createInterface({
        input: this.streams.input,
        output: this.mutableOutput,
        terminal: Boolean(this.streams.input.isTTY && this.streams.output.isTTY),
        // Answers, passwords among them, are not kept for recall with the arrow keys.
        historySize: 0,
      });
      // Lines are queued: input that arrives before its question (pasted, or piped) is kept.
      readline.on('line', (line) => {
        const waiter = this.waiters.shift();
        if (waiter) waiter(line);
        else this.pending.push(line);
      });
      // In raw mode Ctrl+C reaches readline instead of the process; pass it on.
      readline.on('SIGINT', () => {
        this.streams.output.write('\n');
        this.close();
        process.kill(process.pid, 'SIGINT');
      });
      readline.on('close', () => {
        this.readline = null;
        for (const waiter of this.waiters.splice(0)) waiter(null);
      });
      this.readline = readline;
    }
    return this.readline;
  }

  private nextLine(): Promise<string | null> {
    const queued = this.pending.shift();
    if (queued !== undefined) return Promise.resolve(queued);
    if (!this.readline) return Promise.resolve(null);
    return new Promise((resolve) => this.waiters.push(resolve));
  }

  private async read(prompt: string, secret = false): Promise<string> {
    if (!this.interactive) throw new Error(`A question needs an answer and the input is not a terminal: ${prompt}`);
    const reader = this.reader();
    this.clearSpinner();
    reader.setPrompt(`${this.paint('36', '?')} ${prompt} `);
    reader.prompt();
    if (secret) this.mutableOutput.muted = true;
    try {
      const line = await this.nextLine();
      if (line === null) throw new Interrupted();
      return line;
    } finally {
      if (secret) {
        this.mutableOutput.muted = false;
        this.streams.output.write('\n');
      }
    }
  }

  /** Asks until `validate` returns null (meaning valid); it returns the problem to show otherwise. */
  async ask(prompt: string, options: { default?: string; validate?: (answer: string) => string | null; secret?: boolean } = {}): Promise<string> {
    for (;;) {
      const suffix = options.default ? this.dim(` [${options.default}]`) : '';
      const raw = (await this.read(`${prompt}${suffix}`, options.secret)).trim();
      const answer = raw || options.default || '';
      const problem = options.validate?.(answer) ?? null;
      if (problem === null) return answer;
      this.warning(problem);
    }
  }

  async confirm(prompt: string, defaultValue: boolean, invalid: string): Promise<boolean> {
    const hint = this.dim(defaultValue ? ' [Y/n]' : ' [y/N]');
    for (;;) {
      const answer = (await this.read(`${prompt}${hint}`)).trim().toLowerCase();
      if (!answer) return defaultValue;
      if (['y', 'yes', 'はい', 'h'].includes(answer)) return true;
      if (['n', 'no', 'いいえ', 'i'].includes(answer)) return false;
      this.warning(invalid);
    }
  }

  async choose<T>(prompt: string, choices: ChoiceOption<T>[], defaultIndex: number, invalid: string): Promise<T> {
    this.line(`${this.paint('36', '?')} ${prompt}`);
    choices.forEach((choice, index) => this.line(`    ${index + 1}) ${choice.label}`));
    for (;;) {
      const answer = (await this.read(this.dim(`[${defaultIndex + 1}]`))).trim();
      const index = answer ? Number(answer) - 1 : defaultIndex;
      const choice = Number.isInteger(index) ? choices[index] : undefined;
      if (choice) return choice.value;
      this.warning(invalid);
    }
  }

  close(): void {
    this.readline?.close();
    this.readline = null;
  }
}
