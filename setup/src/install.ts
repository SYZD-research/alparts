import type { X509Certificate } from 'node:crypto';
import { Cancelled, SetupError, type Context } from './context.ts';
import {
  APP_IMAGE, carriesCurrentPin, ensureAppImage, ensureAuditCheckpoint, ensureBackupToolsImage, hasAccounts, installBackupSchedule,
  migrate, prepareSecrets, provisionDatabase, readInviteCode, restartRunning, seedProxyKey, sourceVersion, startDependencies, startServices,
  waitForApp, waitForCertificate, writeConfiguration, writePinsFile,
} from './deployment.ts';
import { busyPorts, chooseEdgeSubnet, edgeNetworkLayout, hostRoutes, resolveDomain } from './network.ts';
import { checkHost, checkPortsFree } from './preflight.ts';
import { voicePortRange } from './render.ts';
import { SecretStore } from './secrets.ts';
import { checkSmtp } from './smtp.ts';
import { DEFAULT_APP_PORT, DEFAULT_VOICE_PORT, loadSettings, newAuditHeadObjectKey, saveSettings, type Settings } from './settings.ts';
import { alignRows } from './ui.ts';
import { answersFromSettings, askQuestions, parseAnswersFile, reviewLines, SMTP_FAILURES, type Answers } from './wizard.ts';

/** The saved settings, or null before the first install. */
export function readSettings(context: Context): Settings | null {
  try {
    return loadSettings(context.paths.settingsFile);
  } catch (error) {
    throw new SetupError('error.settingsInvalid', { detail: (error as Error).message, path: context.paths.settingsFile }, { cause: error });
  }
}

export function requireSettings(context: Context): Settings {
  const settings = readSettings(context);
  if (!settings) throw new SetupError('error.notInstalled', { command: context.command });
  return settings;
}

/** The first loopback port from 3000 that is free, for checks of the app from this host. */
async function freeAppPort(): Promise<number> {
  for (let port = DEFAULT_APP_PORT; port < DEFAULT_APP_PORT + 20; port += 1) {
    if ((await busyPorts([{ port, protocol: 'tcp', host: '127.0.0.1' }])).length === 0) return port;
  }
  return DEFAULT_APP_PORT;
}

async function newNetwork(context: Context): Promise<Settings['network']> {
  const subnet = chooseEdgeSubnet([...hostRoutes(), ...await context.docker.networkRanges()]);
  if (!subnet) throw new SetupError('error.edgeSubnet');
  return { edgeSubnet: subnet, proxyAddress: edgeNetworkLayout(subnet).proxyAddress, appPort: await freeAppPort() };
}

export function settingsFromAnswers(context: Context, answers: Answers, base: Settings | null, network: Settings['network']): Settings {
  return {
    version: 1,
    language: context.language,
    domain: answers.domain,
    acmeEmail: answers.acmeEmail,
    certificates: answers.certificates,
    email: answers.email,
    voice: {
      relay: answers.voice.relay,
      publicAddress: answers.voice.relay ? answers.voice.publicAddress : null,
      basePort: base?.voice.basePort ?? DEFAULT_VOICE_PORT,
      workers: base?.voice.workers ?? 1,
    },
    backup: answers.backup
      ? { ...answers.backup, retentionDays: base?.backup?.retentionDays ?? 30, minimumCopies: base?.backup?.minimumCopies ?? 7 }
      : null,
    network,
    image: base?.image ?? { tag: null, previousTag: null },
    auditHeadObjectKey: base?.auditHeadObjectKey ?? newAuditHeadObjectKey(),
    state: base?.state ?? { audit: 'none', completed: false, createdAt: new Date().toISOString() },
  };
}

/** Unattended answers get the checks the questions make, as warnings or errors. */
export async function checkAnswers(context: Context, answers: Answers): Promise<void> {
  const { t, ui } = context;
  const resolved = await resolveDomain(answers.domain);
  if (answers.certificates === 'public' && resolved.v4.length === 0 && resolved.v6.length === 0) {
    ui.warning(t('domain.notResolved', { domain: answers.domain }));
  }
  if (answers.voice.relay && !answers.voice.publicAddress) {
    answers.voice.publicAddress = resolved.v4[0] ?? null;
    if (!answers.voice.publicAddress) throw new SetupError('error.answer', { field: 'voice.publicAddress' });
  }
  if (answers.email.mode === 'smtp') {
    const { host, port, security, user } = answers.email;
    const result = await checkSmtp({ host, port, security, user, password: answers.smtpPassword });
    if (!result.ok) {
      const message = SMTP_FAILURES[result.reason];
      if (!context.options.yes) throw new SetupError(message);
      ui.warning(t(message));
    }
  }
}

export function printReview(context: Context, settings: Settings): void {
  const { t, ui } = context;
  ui.section(t('section.confirm'));
  for (const line of alignRows(reviewLines(context, settings))) ui.line(`  ${line}`);
}

async function gatherSettings(context: Context, existing: Settings | null): Promise<{ settings: Settings; smtpPassword: string | null }> {
  const { t, ui, options } = context;
  let answers: Answers;
  let smtpPassword: string | null = null;
  if (options.answersFile) {
    answers = parseAnswersFile(options.answersFile);
    await checkAnswers(context, answers);
    smtpPassword = answers.smtpPassword;
  } else if (existing && (!ui.interactive || await ui.confirm(t('install.resumeKeep'), true, t('prompt.invalidYesNo')))) {
    answers = answersFromSettings(existing);
  } else {
    if (!ui.interactive) throw new SetupError('error.needsTerminal');
    const saved = existing ? new SecretStore(context.paths.secretsDir) : null;
    const savedPassword = saved?.has('smtp_password') ? saved.read('smtp_password') || null : null;
    const result = await askQuestions(context, existing ? answersFromSettings(existing) : null, savedPassword);
    answers = result.answers;
    smtpPassword = result.keepSmtpPassword ? null : answers.smtpPassword;
  }
  const network = existing?.network ?? await newNetwork(context);
  const settings = settingsFromAnswers(context, answers, existing, network);
  printReview(context, settings);
  if (ui.interactive && !options.yes && !options.answersFile) {
    if (!(await ui.confirm(t('confirm.proceed'), true, t('prompt.invalidYesNo')))) {
      ui.note(t('confirm.cancelled'));
      throw new Cancelled();
    }
  }
  return { settings, smtpPassword };
}

/** Sets up the daily backup; a failure is reported as a warning, the rest of the work stands. */
export async function scheduleBackups(context: Context, settings: Settings): Promise<void> {
  const { t, ui } = context;
  const time = settings.backup!.time;
  await ui.task(t('step.schedule'), async () => {
    try {
      await ensureBackupToolsImage(context);
      await installBackupSchedule(context, settings);
      return null;
    } catch (error) {
      context.log.event(`backup schedule: ${(error as Error).message}`);
      // The reasons the operator can act on are shown as they are; anything else is in the log.
      if (error instanceof SetupError && (error.key === 'error.noSystemd' || error.key === 'error.scheduleUnsafe')) return t(error.key, error.values);
      return t('warning.backupSchedule', { command: context.command });
    }
  }, (problem) => (problem === null ? t('step.scheduleDone', { time }) : { warning: problem }));
}

/** Apps built with the pins file connect only when the certificate being served carries the key it names. */
export function warnIfKeyDiffers(context: Context, served: X509Certificate | null): void {
  if (served && !carriesCurrentPin(context, served)) context.ui.warning(context.t('pins.mismatch', { command: context.command }));
}

/** Waits for the certificate for the domain, then compares its key with the pins file. */
export async function awaitCertificate(context: Context, settings: Settings): Promise<void> {
  const { t, ui } = context;
  const url = `https://${settings.domain}`;
  const served = await ui.task(t('step.certificate'), () => waitForCertificate(context, settings, 180_000),
    (certificate) => (certificate ? t('step.certificateDone', { url }) : { warning: t('warning.certificatePending') }));
  warnIfKeyDiffers(context, served);
}

export async function install(context: Context): Promise<void> {
  const { t, ui, paths, docker } = context;
  const existing = readSettings(context);
  if (existing?.state.completed) {
    ui.line(t('install.alreadyDone', { url: `https://${existing.domain}` }));
    ui.note(t('install.alreadyDoneHint', { command: context.command }));
    return;
  }
  ui.title(t('app.title'));
  if (!existing && !context.options.answersFile) {
    ui.line();
    ui.note(t('install.intro'));
  }

  ui.section(t('section.preflight'));
  await ui.task(t('preflight.checking'), () => checkHost(context), () => t('preflight.ok'));
  if (!existing && (await docker.projectVolumes()).length > 0) {
    throw new SetupError('error.leftoverData', { path: paths.configDir });
  }
  if (existing) ui.note(t('install.resuming'));

  const { settings, smtpPassword } = await gatherSettings(context, existing);
  await checkPortsFree(context, settings);
  saveSettings(paths.settingsFile, settings);

  ui.section(t('section.install'));
  // A resumed install may find services running with files that change now.
  const restart = await ui.task(t('step.config'), async () => prepareSecrets(context, settings, smtpPassword), () => t('step.configDone'));

  const tag = context.options.imageTag
    ?? (settings.image.tag && await docker.imageExists(APP_IMAGE(settings.image.tag)) ? settings.image.tag : (await sourceVersion(context)).tag);
  await ui.task(t('step.build'), () => ensureAppImage(context, tag), (result) => t(result === 'built' ? 'step.buildDone' : 'step.buildReady'));
  settings.image.tag = tag;
  saveSettings(paths.settingsFile, settings);
  for (const service of await writeConfiguration(context, settings, tag)) restart.add(service);
  await restartRunning(context, restart);

  await ui.task(t('step.dependencies'), () => startDependencies(context), () => t('step.dependenciesDone'));
  await ui.task(t('step.database'), async () => {
    await provisionDatabase(context);
    await migrate(context, tag);
  }, () => t('step.databaseDone'));
  await ui.task(t('step.audit'), () => ensureAuditCheckpoint(context, settings), () => t('step.auditDone'));
  await ui.task(t('step.start'), async () => {
    if (await seedProxyKey(context, settings)) await restartRunning(context, new Set(['proxy']));
    await startServices(context, ['app', 'proxy']);
    if (!(await waitForApp(settings, 120_000))) {
      throw new SetupError('error.start', {}, { hint: { key: 'error.startHint', values: { command: context.command } } });
    }
  }, () => t('step.startDone'));

  await awaitCertificate(context, settings);

  if (settings.backup) await scheduleBackups(context, settings);
  writePinsFile(context, settings);
  settings.state.completed = true;
  saveSettings(paths.settingsFile, settings);
  await printSummary(context, settings);
}

export async function printSummary(context: Context, settings: Settings): Promise<void> {
  const { t, ui, paths } = context;
  const url = `https://${settings.domain}`;
  ui.section(t('section.done'));
  ui.note(t('done.url', { url }));
  if ((await hasAccounts(context)) === false) {
    ui.line();
    ui.note(t('done.firstAccount'));
    ui.note(`  1. ${t('done.firstAccountOpen', { url })}`);
    ui.note(`  2. ${t('done.firstAccountCode')}`);
    ui.line();
    ui.line(`       ${ui.bold(readInviteCode(context))}`);
    ui.line();
    ui.note(`  3. ${t('done.firstAccountNext')}`);
  }
  ui.line();
  ui.note(t('done.ports'));
  ui.note(`  ${t('done.portsWeb', { ports: '80/tcp, 443/tcp, 443/udp' })}`);
  if (settings.voice.relay) {
    const ports = voicePortRange(settings);
    ui.note(`  ${t('done.portsVoice', { ports: `${ports}/udp, ${ports}/tcp` })}`);
  }
  ui.line();
  ui.note(t('done.keep', { dir: paths.configDir }));
  if (settings.backup) ui.note(t('done.backups', { dir: paths.backupDir }));
  ui.line();
  ui.note(t('done.commands'));
  const commands: Array<[string, string]> = [
    [t('done.commandStatus'), `sudo ${context.command} status`],
    [t('done.commandUpdate'), `sudo ${context.command} update`],
    [t('done.commandBackup'), `sudo ${context.command} backup`],
    [t('done.commandPins'), `sudo ${context.command} pins`],
  ];
  for (const line of alignRows(commands)) ui.note(`  ${line}`);
  ui.line();
}
