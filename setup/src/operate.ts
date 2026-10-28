import { Cancelled, SetupError, type Context } from './context.ts';
import {
  appReady, backupFiles, backupScheduled, ensureBackupToolsImage, hasAccounts, installBackupSchedule, prepareSecrets, probeProxy,
  readInviteCode, removeBackupSchedule, restartRunning, seedProxyKey, startDependencies, startServices, waitForApp, waitForCertificate,
  writeConfiguration, writePinsFile,
} from './deployment.ts';
import { awaitCertificate, checkAnswers, printReview, requireSettings, scheduleBackups, settingsFromAnswers, warnIfKeyDiffers } from './install.ts';
import { voicePortRange } from './render.ts';
import { SecretStore } from './secrets.ts';
import { saveSettings, type Settings } from './settings.ts';
import { answersFromSettings, askBackup, askQuestions, parseAnswersFile } from './wizard.ts';
import { alignRows } from './ui.ts';

function imageTagOf(context: Context, settings: Settings): string {
  if (!settings.image.tag || !settings.state.completed) throw new SetupError('error.notInstalled', { command: context.command });
  return settings.image.tag;
}

/**
 * Writes the configuration the settings describe and brings every service up
 * with it: running services whose mounted files changed are restarted, the
 * rest are created or recreated as Compose sees fit.
 */
export async function applyAndStart(context: Context, settings: Settings, smtpPassword: string | null = null): Promise<void> {
  const tag = imageTagOf(context, settings);
  const restart = prepareSecrets(context, settings, smtpPassword);
  for (const service of await writeConfiguration(context, settings, tag)) restart.add(service);
  await restartRunning(context, restart);
  await startDependencies(context);
  if (await seedProxyKey(context, settings)) await restartRunning(context, new Set(['proxy']));
  await startServices(context, ['app', 'proxy']);
  if (!(await waitForApp(settings, 120_000))) {
    throw new SetupError('error.start', {}, { hint: { key: 'error.startHint', values: { command: context.command } } });
  }
}

export async function start(context: Context): Promise<void> {
  const { t, ui } = context;
  const settings = requireSettings(context);
  await ui.task(t('step.start'), () => applyAndStart(context, settings), () => t('step.startDone'));
  ui.line(t('start.done', { url: `https://${settings.domain}` }));
}

export async function stop(context: Context): Promise<void> {
  const { t, ui } = context;
  requireSettings(context);
  await ui.task(t('step.stopAll'), () => context.docker.stop(), () => t('stop.done'));
}

export async function restart(context: Context): Promise<void> {
  const { t, ui } = context;
  const settings = requireSettings(context);
  await ui.task(t('step.stopAll'), () => context.docker.stop(), () => t('stop.done'));
  await ui.task(t('step.start'), () => applyAndStart(context, settings), () => t('step.startDone'));
  ui.line(t('restart.done', { url: `https://${settings.domain}` }));
}

/** The services whose output `logs` shows. */
export const LOG_SERVICES: readonly string[] = ['app', 'proxy', 'postgres', 'object-storage'];

export async function logs(context: Context, service: string | undefined): Promise<void> {
  requireSettings(context);
  const follow = Boolean(process.stdout.isTTY);
  await context.docker.compose(['logs', '--tail', '200', ...(follow ? ['--follow'] : []), ...(service ? [service] : [])], { interactive: true, check: false });
}

function formatDate(date: Date, language: Context['language']): string {
  return date.toLocaleString(language === 'ja' ? 'ja-JP' : 'en-US', { dateStyle: 'medium', timeStyle: 'short' });
}

export async function status(context: Context): Promise<void> {
  const { t, ui, paths } = context;
  const settings = requireSettings(context);
  const states = new Map((await context.docker.services()).map((entry) => [entry.service, entry]));
  const stateLabel = (service: string) => {
    const entry = states.get(service);
    if (!entry) return t('status.missing');
    if (entry.state !== 'running') return t('status.stopped');
    if (entry.health === 'starting') return t('status.starting');
    if (entry.health === 'unhealthy') return t('status.unhealthy');
    return t('status.running');
  };
  const certificate = (await probeProxy(context, settings))?.certificate;
  const backups = backupFiles(paths.backupDir);
  const email = settings.email;
  const rows: Array<[string, string]> = [
    [t('status.address'), `https://${settings.domain}`],
    [t('status.version'), settings.image.tag ?? '-'],
    [t('status.serviceApp'), stateLabel('app')],
    [t('status.servicePostgres'), stateLabel('postgres')],
    [t('status.serviceStorage'), stateLabel('object-storage')],
    [t('status.serviceProxy'), stateLabel('proxy')],
    [t('status.certificate'), certificate ? t('status.certificateValid', { date: formatDate(new Date(certificate.validTo), context.language) }) : t('status.certificateMissing')],
    [t('status.voice'), settings.voice.relay
      ? t('confirm.voiceRelay', { address: settings.voice.publicAddress ?? '', ports: voicePortRange(settings) })
      : t('confirm.voiceDirect')],
    [t('status.email'), email.mode === 'smtp' ? t('confirm.emailSmtp', { from: email.from, host: email.host, port: email.port }) : t('confirm.emailDisabled')],
    [t('status.backup'), !settings.backup
      ? t('status.backupOff')
      : !backupScheduled(context)
        ? t('status.backupUnscheduled', { command: context.command })
        : backups.length > 0
        ? t('status.backupLatest', { time: settings.backup.time, date: formatDate(backups.at(-1)!.modified, context.language), count: backups.length })
        : t('status.backupNever', { time: settings.backup.time })],
  ];
  ui.title(t('status.title'));
  for (const line of alignRows(rows)) ui.line(`  ${line}`);
  ui.line();
  warnIfKeyDiffers(context, certificate ?? null);
  if (await appReady(settings)) ui.success(t('status.ready'));
  else ui.warning(t('status.notReady'));
}

/** Changes the answers of a finished install, then applies them. */
export async function configure(context: Context): Promise<void> {
  const { t, ui, options } = context;
  const settings = requireSettings(context);
  imageTagOf(context, settings);
  let answers;
  let smtpPassword: string | null = null;
  if (options.answersFile) {
    answers = parseAnswersFile(options.answersFile);
    await checkAnswers(context, answers);
    smtpPassword = answers.smtpPassword;
  } else {
    if (!ui.interactive) throw new SetupError('error.needsTerminal');
    ui.title(t('app.title'));
    const store = new SecretStore(context.paths.secretsDir);
    const saved = store.has('smtp_password') ? store.read('smtp_password') || null : null;
    const result = await askQuestions(context, answersFromSettings(settings), saved);
    answers = result.answers;
    smtpPassword = result.keepSmtpPassword ? null : answers.smtpPassword;
  }
  const updated = settingsFromAnswers(context, answers, settings, settings.network);
  printReview(context, updated);
  if (updated.domain !== settings.domain) ui.warning(t('configure.domainChanged'));
  if (ui.interactive && !options.yes && !options.answersFile && !(await ui.confirm(t('configure.proceed'), true, t('prompt.invalidYesNo')))) {
    ui.note(t('confirm.cancelled'));
    throw new Cancelled();
  }
  saveSettings(context.paths.settingsFile, updated);
  ui.section(t('section.configure'));
  await ui.task(t('step.start'), () => applyAndStart(context, updated, smtpPassword), () => t('step.startDone'));
  await awaitCertificate(context, updated);
  if (updated.backup) await scheduleBackups(context, updated);
  else await removeBackupSchedule(context);
  writePinsFile(context, updated);
  ui.line(t('configure.done'));
}

export async function backupSetup(context: Context): Promise<void> {
  const { t, ui, options, paths } = context;
  const settings = requireSettings(context);
  imageTagOf(context, settings);
  if (options.disable) {
    await removeBackupSchedule(context);
    settings.backup = null;
    saveSettings(paths.settingsFile, settings);
    prepareSecrets(context, settings, null);
    ui.line(t('backupSetup.disabled', { dir: paths.backupDir }));
    return;
  }
  let backup;
  if (options.answersFile) {
    backup = parseAnswersFile(options.answersFile).backup;
    if (!backup) throw new SetupError('error.answer', { field: 'backup' });
  } else {
    if (!ui.interactive) throw new SetupError('error.needsTerminal');
    backup = await askBackup(context, settings.backup, true);
    if (!backup) return;
  }
  settings.backup = { ...backup, retentionDays: settings.backup?.retentionDays ?? 30, minimumCopies: settings.backup?.minimumCopies ?? 7 };
  saveSettings(paths.settingsFile, settings);
  prepareSecrets(context, settings, null);
  await writeConfiguration(context, settings, settings.image.tag!);
  const time = settings.backup.time;
  await ui.task(t('step.schedule'), async () => {
    await ensureBackupToolsImage(context);
    await installBackupSchedule(context, settings);
  }, () => t('step.scheduleDone', { time }));
  ui.line(t('backupSetup.enabled', { time, dir: paths.backupDir }));
}

/**
 * Switches the certificate to the spare key and makes a new spare. Apps
 * built with the current pins file keep connecting: it lists the spare.
 */
async function rotateCertificateKey(context: Context, settings: Settings): Promise<void> {
  const { t, ui, options } = context;
  ui.note(t('pins.rotateExplain'));
  if (!options.yes) {
    if (!ui.interactive) throw new SetupError('error.needsTerminal');
    if (!(await ui.confirm(t('pins.rotateConfirm'), false, t('prompt.invalidYesNo')))) {
      ui.note(t('update.cancelled'));
      throw new Cancelled();
    }
  }
  await ui.task(t('step.rotate'), async () => {
    new SecretStore(context.paths.secretsDir).rotateProxyKey();
    if (await seedProxyKey(context, settings)) await restartRunning(context, new Set(['proxy']));
    return waitForCertificate(context, settings, 180_000);
  }, (served) => (served ? t('step.rotateDone') : { warning: t('warning.certificatePending') }));
}

export async function pins(context: Context): Promise<void> {
  const { t, ui } = context;
  const settings = requireSettings(context);
  if (context.options.rotate) await rotateCertificateKey(context, settings);
  const file = writePinsFile(context, settings);
  const served = (await probeProxy(context, settings))?.certificate;
  if (!served) ui.warning(t('pins.notServing'));
  else warnIfKeyDiffers(context, served);
  ui.success(t('pins.written', { file }));
  ui.line();
  ui.note(t('pins.explain'));
  ui.line();
  ui.note(t('pins.build'));
  ui.line(`    sudo cat ${file} > $HOME/alparts-transport-pins.json`);
  ui.line('    ALPARTS_TRANSPORT_PINS_FILE=$HOME/alparts-transport-pins.json pnpm desktop:dist');
  ui.line('    cd packages/android && ./gradlew -PalpartsTransportPinsFile=$HOME/alparts-transport-pins.json assembleRelease');
  ui.line();
  ui.note(t('pins.compromised'));
}

export async function inviteCode(context: Context): Promise<void> {
  const { t, ui } = context;
  const settings = requireSettings(context);
  if ((await hasAccounts(context)) === true) {
    ui.note(t('invite.used'));
    return;
  }
  ui.line(t('invite.code'));
  ui.line();
  ui.line(`  ${ui.bold(readInviteCode(context))}`);
  ui.line();
  ui.note(t('invite.usage', { url: `https://${settings.domain}` }));
}
