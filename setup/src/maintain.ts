import { basename, join } from 'node:path';
import { Cancelled, SetupError, withCleanup, type Context } from './context.ts';
import {
  APP_IMAGE, appliedMigrations, ensureAppImage, ensureBackupToolsImage, migrate, prepareSecrets, provisionDatabase,
  restartRunning, seedProxyKey, sourceVersion, startDependencies, startServices, waitForApp, writeConfiguration, writePinsFile,
} from './deployment.ts';
import { requireSettings } from './install.ts';
import { applyAndStart } from './operate.ts';
import { checkHost } from './preflight.ts';
import { saveSettings, type Settings } from './settings.ts';

const BACKUP = '/opt/alparts/scripts/backup.sh';
const PRUNE = '/opt/alparts/scripts/prune-backups.sh';

/** Runs scripts/backup.sh in the tools container while the app is stopped; returns the file it made. */
async function makeBackup(context: Context, reason: string): Promise<string> {
  try {
    const result = await context.docker.runOnce('backup', [BACKUP], {
      profiles: ['operations'],
      environment: { ALPARTS_BACKUP_QUIESCED: 'YES_WRITES_ARE_STOPPED', BACKUP_REASON: reason },
      timeoutMs: 6 * 60 * 60 * 1000,
    });
    const written = result.stdout.trim().split('\n').at(-1) ?? '';
    return join(context.paths.backupDir, basename(written));
  } catch (error) {
    throw new SetupError('error.backup', {}, { cause: error });
  }
}

async function checkBackupTools(context: Context): Promise<void> {
  const { t, ui } = context;
  await ui.task(t('step.backupTools'), () => ensureBackupToolsImage(context), () => t('step.backupToolsDone'));
  // Tools and settings are checked before the app stops, not after.
  await ui.task(t('step.backupCheck'), async () => {
    try {
      await context.docker.runOnce('backup', [BACKUP, '--preflight'], { profiles: ['operations'] });
    } catch (error) {
      throw new SetupError('error.backup', {}, { cause: error });
    }
  }, () => t('step.backupCheckDone'));
}

async function appRunning(context: Context): Promise<boolean> {
  return (await context.docker.services()).some((service) => service.service === 'app' && service.state === 'running');
}

export async function backup(context: Context): Promise<void> {
  const { t, ui } = context;
  const settings = requireSettings(context);
  if (!settings.backup) throw new SetupError('error.backupNotConfigured', { command: context.command });
  ui.section(t('section.backupNow'));
  await checkBackupTools(context);
  await startDependencies(context);

  const running = await appRunning(context);
  const resume = async () => {
    await startServices(context, ['app']);
    if (!(await waitForApp(settings, 120_000))) throw new Error('not ready');
  };
  let failure: unknown = null;
  await withCleanup(context, running ? resume : async () => undefined, async () => {
    if (running) await ui.task(t('step.stopApp'), () => context.docker.stop(['app']), () => t('step.stopAppDone'));
    try {
      await ui.task(t('step.backupRun'), () => makeBackup(context, context.options.scheduled ? 'scheduled' : 'manual'), (file) => t('step.backupRunDone', { file }));
    } catch (error) {
      failure = error;
      context.log.event(`backup failed: ${(error as Error).message}`);
    }
    // The app comes back whether or not the backup worked.
    if (running) {
      await ui.task(t('step.resumeApp'), async () => {
        try {
          await resume();
        } catch (error) {
          throw new SetupError('error.resumeApp', { command: context.command }, { cause: error });
        }
      }, () => t('step.resumeAppDone'));
    } else {
      ui.note(t('backup.appStoppedNote'));
    }
  });
  if (failure) throw failure;

  await ui.task(t('step.prune'), async () => {
    const result = await context.docker.runOnce('backup', [PRUNE, '--apply'], {
      profiles: ['operations'],
      environment: { BACKUP_PRUNE_ACK: 'DELETE_EXPIRED_ENCRYPTED_BACKUPS' },
    });
    return result.stdout.split('\n').filter((line) => line.startsWith('deleted ')).length;
  }, (count) => (count > 0 ? t('step.pruneDone', { count }) : t('step.pruneNothing')));
}

/**
 * Moves the deployment to the checked-out source: build, stop, back up,
 * migrate, start. A new version that does not start is replaced by the
 * previous one when no migration ran; after a migration the database only
 * fits the new version, and the backup is the way back.
 */
export async function update(context: Context): Promise<void> {
  const { t, ui, options, docker } = context;
  const settings = requireSettings(context);
  if (!settings.state.completed || !settings.image.tag) throw new SetupError('error.notInstalled', { command: context.command });
  const current = settings.image.tag;
  ui.section(t('section.update'));
  await ui.task(t('preflight.checking'), () => checkHost(context), () => t('preflight.ok'));

  const version = options.imageTag ? { tag: options.imageTag, dirty: false } : await sourceVersion(context);
  if (version.tag === current) {
    await ui.task(t('step.start'), () => applyAndStart(context, settings), () => t('step.startDone'));
    writePinsFile(context, settings);
    ui.line(t('update.upToDate', { version: current }));
    return;
  }
  if (version.dirty) ui.note(t('update.localChanges'));
  if (!settings.backup) {
    ui.warning(t('update.noBackup'));
    const proceed = options.yes || (ui.interactive && await ui.confirm(t('update.continueWithoutBackup'), false, t('prompt.invalidYesNo')));
    if (!proceed) {
      ui.note(t('update.cancelled'));
      throw new Cancelled();
    }
  } else {
    await checkBackupTools(context);
  }

  await ui.task(t('step.updateBuild'), () => ensureAppImage(context, version.tag), () => t('step.updateBuildDone', { version: version.tag }));
  await startDependencies(context);
  const before = await appliedMigrations(context);
  // Until the new version runs, an interruption brings back the previous one if the database still fits it.
  const restorePrevious = async () => {
    if ((await appliedMigrations(context).catch(() => -1)) !== before) return;
    saveSettings(context.paths.settingsFile, settings);
    await writeConfiguration(context, settings, current);
    await startServices(context, ['app', 'proxy']);
  };
  const older = settings.image.previousTag;
  const next: Settings = { ...settings, image: { tag: version.tag, previousTag: current } };
  await withCleanup(context, restorePrevious, async () => {
    await ui.task(t('step.stopApp'), () => docker.stop(['app']), () => t('step.stopAppDone'));
    let backupFile = '-';
    try {
      if (settings.backup) {
        backupFile = await ui.task(t('step.backupRun'), () => makeBackup(context, `pre-update:${version.tag.slice(0, 60)}`), (file) => t('step.backupRunDone', { file }));
      }
      await ui.task(t('step.migrate'), async () => {
        await provisionDatabase(context);
        await migrate(context, version.tag);
      }, () => t('step.migrateDone'));
    } catch (error) {
      // Nothing has changed for the running version unless a migration did.
      await restorePrevious().catch(() => undefined);
      throw error;
    }
    const migrated = (await appliedMigrations(context)) !== before;
    // From here on the database belongs to the new version.
    saveSettings(context.paths.settingsFile, next);
    try {
      await ui.task(t('step.start'), async () => {
        const restart = prepareSecrets(context, next, null);
        for (const service of await writeConfiguration(context, next, version.tag)) restart.add(service);
        await restartRunning(context, restart);
        if (await seedProxyKey(context, next)) await restartRunning(context, new Set(['proxy']));
        await startServices(context, ['app', 'proxy']);
        if (!(await waitForApp(next, 180_000))) throw new SetupError('error.start', {}, { hint: { key: 'error.startHint', values: { command: context.command } } });
      }, () => t('step.startDone'));
    } catch (error) {
      if (migrated) throw new SetupError('update.cannotRollBack', { file: backupFile }, { cause: error });
      // No migration ran, so the previous version still fits the database: go back to it.
      await restorePrevious().catch(() => undefined);
      if (await waitForApp(settings, 120_000)) throw new SetupError('update.rolledBack', { version: current }, { cause: error });
      throw error;
    }
  });
  writePinsFile(context, next);
  if (older && older !== current && older !== version.tag) await docker.removeImage(APP_IMAGE(older));
  ui.line(t('update.done', { version: version.tag }));
}
