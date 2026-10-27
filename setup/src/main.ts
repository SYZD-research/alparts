import { existsSync, readdirSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { acquireLock, Cancelled, SetupError, type Context, type Options } from './context.ts';
import { Docker } from './docker.ts';
import { detectLanguage, translator, type Translate } from './i18n.ts';
import { install } from './install.ts';
import { RunLog } from './log.ts';
import { backup, update } from './maintain.ts';
import { backupSetup, configure, inviteCode, LOG_SERVICES, logs, pins, restart, start, status, stop } from './operate.ts';
import { systemPaths, type Paths } from './paths.ts';
import { createRunner } from './run.ts';
import { loadSettings, type Language } from './settings.ts';
import { Interrupted, Ui } from './ui.ts';

/** Commands that change the deployment take the lock; the others only read it. */
const COMMANDS = {
  install: { lock: true },
  configure: { lock: true },
  status: { lock: false },
  start: { lock: true },
  stop: { lock: true },
  restart: { lock: true },
  update: { lock: true },
  backup: { lock: true },
  'backup-setup': { lock: true },
  pins: { lock: true },
  'invite-code': { lock: false },
  logs: { lock: false },
} as const;

type CommandName = keyof typeof COMMANDS;

const KEEP_LOGS = 60;

/** Keeps the newest run logs. */
function pruneLogs(dir: string): void {
  if (!existsSync(dir)) return;
  const logs = readdirSync(dir).filter((name) => name.endsWith('.log'))
    .map((name) => ({ name, time: statSync(join(dir, name)).mtimeMs }))
    .sort((a, b) => b.time - a.time);
  for (const { name } of logs.slice(KEEP_LOGS)) rmSync(join(dir, name), { force: true });
}

function parse(argv: string[]) {
  return parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      answers: { type: 'string' },
      yes: { type: 'boolean', short: 'y', default: false },
      lang: { type: 'string' },
      help: { type: 'boolean', short: 'h', default: false },
      disable: { type: 'boolean', default: false },
      scheduled: { type: 'boolean', default: false },
      rotate: { type: 'boolean', default: false },
      'use-image': { type: 'string' },
    },
  });
}

function languageFor(requested: string | undefined, paths: Paths): Language {
  if (requested === 'ja' || requested === 'en') return requested;
  try {
    const settings = loadSettings(paths.settingsFile);
    if (settings) return settings.language;
  } catch {
    // Unreadable settings are reported by the command itself.
  }
  return detectLanguage(process.env);
}

function report(t: Translate, ui: Ui, log: RunLog, error: unknown, resumable = false): number {
  if (error instanceof Cancelled) return 1;
  ui.line();
  if (error instanceof Interrupted) {
    ui.failure(t('error.interrupted'));
    if (resumable) ui.note(`  ${t('error.interruptedResume')}`);
    return 130;
  }
  if (error instanceof SetupError) {
    ui.failure(t(error.key, error.values));
    if (error.hint) ui.note(`  ${t(error.hint.key, error.hint.values)}`);
  } else {
    ui.failure(t('error.unexpected'));
  }
  log.event(`error: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`);
  let cause = error instanceof Error ? error.cause : undefined;
  while (cause) {
    log.event(`cause: ${cause instanceof Error ? (cause.stack ?? cause.message) : String(cause)}`);
    cause = cause instanceof Error ? cause.cause : undefined;
  }
  if (log.path) ui.note(`  ${t('error.seeLog', { path: log.path })}`);
  return 1;
}

async function main(argv: string[]): Promise<number> {
  const paths = systemPaths();
  const command = process.env.ALPARTS_SETUP_COMMAND || join(paths.repo, 'setup', 'alparts-setup');
  let parsed: ReturnType<typeof parse>;
  try {
    parsed = parse(argv);
  } catch (error) {
    const t = translator(detectLanguage(process.env));
    process.stderr.write(`${t('error.unknownOption', { detail: (error as Error).message })}\n`);
    return 2;
  }
  const { values, positionals } = parsed;
  const language = languageFor(values.lang, paths);
  const t = translator(language);
  const ui = new Ui();
  const name = (positionals[0] ?? 'install') as CommandName;

  if (values.help || positionals[0] === 'help') {
    ui.line(t('app.usage', { command }));
    return 0;
  }
  if (!Object.hasOwn(COMMANDS, name)) {
    ui.failure(t('error.unknownCommand', { name, command }));
    return 2;
  }
  if (name === 'logs' && positionals[1] !== undefined && !LOG_SERVICES.includes(positionals[1])) {
    ui.failure(t('error.unknownService', { name: positionals[1], services: LOG_SERVICES.join(language === 'ja' ? '、' : ', ') }));
    return 2;
  }
  if (process.getuid?.() !== 0) {
    ui.failure(t('error.notRoot', { command: [command, ...argv].join(' ') }));
    return 1;
  }

  pruneLogs(paths.logDir);
  const log = new RunLog(paths.logDir, name);
  log.event(`alparts-setup ${argv.join(' ')}`);
  const run = createRunner(log);
  const options: Options = {
    yes: values.yes,
    answersFile: values.answers ?? null,
    disable: values.disable,
    scheduled: values.scheduled,
    rotate: values.rotate,
    imageTag: values['use-image'] ?? null,
  };
  const context: Context = { language, t, ui, log, run, docker: new Docker(run, paths), paths, command, options, cleanups: [] };

  let release: (() => void) | null = null;
  // A second signal while the undo steps run ends the process at once (the handlers fire once).
  const interrupt = () => {
    ui.close();
    void (async () => {
      for (const cleanup of context.cleanups.splice(0).reverse()) {
        try {
          await cleanup();
        } catch (error) {
          log.event(`cleanup failed: ${(error as Error).message}`);
        }
      }
      release?.();
      process.exit(report(t, ui, log, new Interrupted(), name === 'install'));
    })();
  };
  process.once('SIGINT', interrupt);
  process.once('SIGTERM', interrupt);
  try {
    if (COMMANDS[name].lock) release = acquireLock(paths.lockFile);
    switch (name) {
      case 'install': await install(context); break;
      case 'configure': await configure(context); break;
      case 'status': await status(context); break;
      case 'start': await start(context); break;
      case 'stop': await stop(context); break;
      case 'restart': await restart(context); break;
      case 'update': await update(context); break;
      case 'backup': await backup(context); break;
      case 'backup-setup': await backupSetup(context); break;
      case 'pins': await pins(context); break;
      case 'invite-code': await inviteCode(context); break;
      case 'logs': await logs(context, positionals[1]); break;
    }
    log.event('done');
    return 0;
  } catch (error) {
    return report(t, ui, log, error);
  } finally {
    ui.close();
    release?.();
  }
}

process.exitCode = await main(process.argv.slice(2));
