import { createHash, X509Certificate } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { get as httpGet } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { join } from 'node:path';
import { connect as tlsConnect } from 'node:tls';
import { setTimeout as sleep } from 'node:timers/promises';
import { SetupError, type Context } from './context.ts';
import { APPLIED_MIGRATIONS_SQL, grantsSql, HAS_ACCOUNTS_SQL, provisionSql } from './database.ts';
import { BACKUP_USER, ensureDirectory, writeFileIfChanged } from './files.ts';
import { backupToolsImage } from './images.ts';
import type { Paths } from './paths.ts';
import { composeEnvironment, renderBackupUnits, renderCaddyfile, renderComposeOverride, renderEnvFile, renderPgHba, BACKUP_UNIT } from './render.ts';
import { DATABASE, scramSha256Verifier, SecretStore, type SecretName } from './secrets.ts';
import { saveSettings, type Settings } from './settings.ts';
import { spkiPin } from './x509.ts';

// The steps that build and run the deployment. Each converges on the same
// state when run again, so an interrupted install or update resumes by
// running them in order once more.

export const APP_IMAGE = (tag: string) => `alparts:${tag}`;
const AUDIT_CHECKPOINT = '/var/lib/alparts-audit/checkpoint.json';

/**
 * The image tag for the checked-out source: the commit, plus a digest of
 * uncommitted changes when there are any, so the same source reuses its image.
 */
export async function sourceVersion(context: Context): Promise<{ tag: string; dirty: boolean }> {
  // Read-only: as root, git must not rewrite the checkout owner's index (--no-optional-locks).
  const git = (args: string[]) => context.run('git', ['-c', `safe.directory=${context.paths.repo}`, '--no-optional-locks', '-C', context.paths.repo, ...args], { check: false })
    .catch(() => ({ code: 1, stdout: '', stderr: '' }));
  const head = await git(['rev-parse', '--short=12', 'HEAD']);
  if (head.code !== 0) {
    return { tag: `local-${new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14)}`, dirty: true };
  }
  const commit = head.stdout.trim();
  const status = await git(['status', '--porcelain']);
  if (!status.stdout.trim()) return { tag: commit, dirty: false };
  const diff = await git(['diff', 'HEAD', '--binary']);
  const digest = createHash('sha256').update(status.stdout).update(diff.stdout).digest('hex').slice(0, 8);
  return { tag: `${commit}-local-${digest}`, dirty: true };
}

/** Creates what is missing among the generated credentials and rewrites the derived files; returns the services to restart. */
export function prepareSecrets(context: Context, settings: Settings, smtpPassword: string | null): Set<string> {
  const store = new SecretStore(context.paths.secretsDir);
  store.ensureGenerated();
  if (smtpPassword !== null) store.writeSmtpPassword(smtpPassword);
  store.writeDerivedFiles(settings);
  store.enforcePermissions();
  const users: Partial<Record<SecretName, string[]>> = {
    smtp_password: ['app'],
    internal_ca_certificate: ['app'],
    postgres_tls_certificate: ['postgres'],
    postgres_tls_key: ['postgres'],
    storage_identities: ['object-storage'],
    storage_tls_certificate: ['object-storage'],
    storage_tls_key: ['object-storage'],
  };
  return new Set(store.takeChanged().flatMap((name) => users[name] ?? []));
}

export async function ensureAppImage(context: Context, tag: string): Promise<'built' | 'present'> {
  if (await context.docker.imageExists(APP_IMAGE(tag))) return 'present';
  if (context.options.imageTag) throw new SetupError('error.imageMissing', { image: APP_IMAGE(tag) });
  try {
    await context.run('docker', ['build', '--pull', '--progress', 'plain', '--tag', APP_IMAGE(tag), context.paths.repo], { timeoutMs: 2 * 60 * 60 * 1000 });
  } catch (error) {
    throw new SetupError('error.build', {}, { cause: error });
  }
  return 'built';
}

export async function ensureBackupToolsImage(context: Context): Promise<'built' | 'present'> {
  const image = backupToolsImage(context.paths.repo);
  if (await context.docker.imageExists(image)) return 'present';
  try {
    await context.run('docker', ['build', '--pull', '--progress', 'plain', '--tag', image, join(context.paths.repo, 'setup', 'backup-tools')], { timeoutMs: 30 * 60 * 1000 });
  } catch (error) {
    throw new SetupError('error.backup', {}, { cause: error });
  }
  return 'built';
}

/**
 * The backup container runs as the tools image's unprivileged user: its
 * credentials and directories are handed to that user, whatever an older
 * version of the setup left.
 */
export function prepareBackupFiles(paths: Paths): void {
  new SecretStore(paths.secretsDir).enforcePermissions();
  ensureDirectory(paths.backupDir, 0o700, BACKUP_USER);
  ensureDirectory(paths.backupWorkDir, 0o700, BACKUP_USER);
}

/** Writes the generated files; returns the services whose mounted configuration changed. */
export async function writeConfiguration(context: Context, settings: Settings, imageTag: string): Promise<Set<string>> {
  const { paths, docker } = context;
  ensureDirectory(paths.configDir, 0o700);
  ensureDirectory(paths.proxyConfigDir, 0o700);
  ensureDirectory(paths.postgresConfigDir, 0o700);
  ensureDirectory(paths.emptyDir, 0o755);
  ensureDirectory(paths.stateDir, 0o700);
  prepareBackupFiles(paths);
  const appCommand = await docker.imageCommand(APP_IMAGE(imageTag));
  writeFileIfChanged(paths.composeEnvFile, renderEnvFile(composeEnvironment(settings, paths, imageTag)), 0o600);
  writeFileIfChanged(paths.composeOverrideFile, renderComposeOverride(settings, paths, { appCommand, backupImage: backupToolsImage(paths.repo) }), 0o600);
  const changed = new Set<string>();
  if (writeFileIfChanged(paths.caddyfile, renderCaddyfile(settings), 0o444)) changed.add('proxy');
  if (writeFileIfChanged(paths.pgHbaFile, renderPgHba(), 0o444)) changed.add('postgres');
  return changed;
}

export async function startDependencies(context: Context): Promise<void> {
  try {
    await context.docker.up(['postgres', 'object-storage'], { waitSeconds: 300 });
  } catch (error) {
    throw new SetupError('error.dependencies', {}, { cause: error });
  }
}

/** Roles, passwords and the database, through the superuser's local socket. */
export async function provisionDatabase(context: Context): Promise<void> {
  const store = new SecretStore(context.paths.secretsDir);
  const sql = provisionSql({
    [DATABASE.owner]: scramSha256Verifier(store.read('postgres_owner_password')),
    [DATABASE.app]: scramSha256Verifier(store.read('postgres_app_password')),
    [DATABASE.backup]: scramSha256Verifier(store.read('postgres_backup_password')),
  });
  try {
    await context.docker.psql(sql, 'postgres');
  } catch (error) {
    throw new SetupError('error.database', {}, { cause: error });
  }
}

export async function appliedMigrations(context: Context): Promise<number> {
  const result = await context.docker.psql(`${APPLIED_MIGRATIONS_SQL};\n`, DATABASE.name, { tuplesOnly: true });
  return Number.parseInt(result.stdout.trim(), 10) || 0;
}

export async function hasAccounts(context: Context): Promise<boolean | null> {
  try {
    const result = await context.docker.psql(`${HAS_ACCOUNTS_SQL};\n`, DATABASE.name, { tuplesOnly: true });
    return result.stdout.trim() === 't';
  } catch {
    return null;
  }
}

/** Applies the image's migrations as the schema owner (the app must be stopped), then grants on what they created. */
export async function migrate(context: Context, imageTag: string): Promise<void> {
  try {
    await context.docker.runOnce('migrator', [], { profiles: ['operations'], env: { ALPARTS_IMAGE_TAG: imageTag } });
    await context.docker.psql(grantsSql(), DATABASE.name);
  } catch (error) {
    throw new SetupError('error.database', {}, { cause: error });
  }
}

async function checkpointExists(context: Context): Promise<boolean> {
  const result = await context.docker.runOnce('app', ['-c', `test -f ${AUDIT_CHECKPOINT}`], { entrypoint: '/bin/sh', check: false });
  return result.code === 0;
}

/**
 * The audit checkpoint is created once, by the first install. A run that
 * stopped after marking it pending finishes the job; a checkpoint that
 * existed and went missing is never re-created (docs/OPERATIONS.md).
 */
export async function ensureAuditCheckpoint(context: Context, settings: Settings): Promise<void> {
  if (settings.state.audit === 'initialized') {
    if (!(await checkpointExists(context))) throw new SetupError('error.auditMissing');
    return;
  }
  settings.state.audit = 'pending';
  saveSettings(context.paths.settingsFile, settings);
  if (!(await checkpointExists(context))) {
    try {
      await context.docker.runOnce('app', ['node', 'packages/server/dist/scripts/initialize-audit-checkpoint.js']);
    } catch (error) {
      throw new SetupError('error.database', {}, { cause: error });
    }
  }
  settings.state.audit = 'initialized';
  saveSettings(context.paths.settingsFile, settings);
}

/** Where the proxy's certificate storage keeps the key for each certificate authority it may use. */
export function proxyKeyIssuers(settings: Settings): string[] {
  return settings.certificates === 'local'
    ? ['local']
    : ['acme-v02.api.letsencrypt.org-directory', 'acme.zerossl.com-v2-DV90'];
}

const SEED_PROXY_KEY = [
  'set -eu',
  'umask 077',
  'key="$(cat)"',
  'domain="$1"',
  'shift',
  'for issuer in "$@"; do',
  '  dir="/data/caddy/certificates/$issuer/$domain"',
  '  mkdir -p "$dir"',
  '  if [ -f "$dir/$domain.key" ] && [ "$(cat "$dir/$domain.key")" = "$key" ]; then continue; fi',
  // A certificate for another key would be served until renewal; remove it so the next start obtains one for this key.
  '  rm -f "$dir/$domain.crt" "$dir/$domain.json"',
  '  printf "%s\\n" "$key" > "$dir/$domain.key"',
  '  echo changed',
  'done',
].join('\n');

/**
 * Places the certificate key the apps pin into the proxy's storage. With
 * reuse_private_keys the proxy then requests and renews every certificate
 * for this key instead of generating its own. Returns whether it changed.
 */
export async function seedProxyKey(context: Context, settings: Settings): Promise<boolean> {
  const store = new SecretStore(context.paths.secretsDir);
  const input = `${store.read('proxy_tls_current_key')}\n`;
  const args = ['-c', SEED_PROXY_KEY, 'seed', settings.domain, ...proxyKeyIssuers(settings)];
  // A one-off container would take the proxy's fixed address, so a running proxy is entered instead.
  const running = (await context.docker.services()).some((service) => service.service === 'proxy' && service.state === 'running');
  const result = running
    ? await context.docker.exec('proxy', ['/bin/sh', ...args], { input })
    : await context.docker.runOnce('proxy', args, { entrypoint: '/bin/sh', input });
  return result.stdout.includes('changed');
}

export async function startServices(context: Context, services: string[]): Promise<void> {
  try {
    await context.docker.up(services, { waitSeconds: 300 });
  } catch (error) {
    throw new SetupError('error.start', {}, { cause: error, hint: { key: 'error.startHint', values: { command: context.command } } });
  }
}

/** Restarts the running services among `services`; stopped ones pick the change up when they start. */
export async function restartRunning(context: Context, services: Set<string>): Promise<void> {
  if (services.size === 0) return;
  const running = new Set((await context.docker.services()).filter((service) => service.state === 'running').map((service) => service.service));
  const targets = [...services].filter((service) => running.has(service));
  if (targets.length > 0) await context.docker.restart(targets);
}

/** The app's readiness, asked on the loopback port it is published on for this host. */
export function appReady(settings: Settings): Promise<boolean> {
  return new Promise((resolve) => {
    const request = httpGet({ host: '127.0.0.1', port: settings.network.appPort, path: '/health/ready', timeout: 5000 }, (response) => {
      response.resume();
      resolve(response.statusCode === 200);
    });
    request.on('timeout', () => request.destroy());
    request.on('error', () => resolve(false));
  });
}

export async function waitForApp(settings: Settings, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await appReady(settings)) return true;
    await sleep(2000);
  }
  return false;
}

/** The authority behind a `local` certificate, which no browser trusts by default. */
async function localAuthority(context: Context): Promise<string | undefined> {
  const result = await context.docker.exec('proxy', ['cat', '/data/caddy/pki/authorities/local/root.crt'], { check: false });
  return result.code === 0 ? result.stdout : undefined;
}

/** Fetches the web app through the proxy on this host, as a browser would by the domain name. */
function fetchThroughProxy(settings: Settings, ca: string | undefined): Promise<boolean> {
  return new Promise((resolve) => {
    const request = httpsRequest({
      host: '127.0.0.1',
      port: 443,
      path: '/',
      servername: settings.domain,
      headers: { host: settings.domain },
      timeout: 10_000,
      ...(ca ? { ca } : {}),
    }, (response) => {
      response.resume();
      resolve(response.statusCode === 200);
    });
    request.on('timeout', () => request.destroy());
    request.on('error', () => resolve(false));
    request.end();
  });
}

/** Waits until the proxy serves the app with a valid certificate for the domain. */
export async function waitForCertificate(context: Context, settings: Settings, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ca = settings.certificates === 'local' ? await localAuthority(context) : undefined;
    if ((settings.certificates === 'public' || ca) && await fetchThroughProxy(settings, ca)) return true;
    await sleep(3000);
  }
  return false;
}

/** The certificate the proxy serves for the domain, trusted or not. */
export function servedCertificate(settings: Settings): Promise<X509Certificate | null> {
  return new Promise((resolve) => {
    const socket = tlsConnect({ host: '127.0.0.1', port: 443, servername: settings.domain, rejectUnauthorized: false, timeout: 10_000 }, () => {
      const certificate = socket.getPeerX509Certificate() ?? null;
      socket.end();
      resolve(certificate);
    });
    socket.on('timeout', () => socket.destroy());
    socket.on('error', () => resolve(null));
  });
}

export function backupFiles(dir: string): Array<{ name: string; modified: Date }> {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((name) => /^alparts-backup-\d{8}T\d{6}Z-[0-9a-f]{12}\.tar\.age$/.test(name))
    .map((name) => ({ name, modified: statSync(join(dir, name)).mtime }))
    .sort((a, b) => a.modified.getTime() - b.modified.getTime());
}

export async function systemdAvailable(context: Context): Promise<boolean> {
  return existsSync('/run/systemd/system') && (await context.run('systemctl', ['--version'], { check: false }).catch(() => null))?.code === 0;
}

export async function installBackupSchedule(context: Context, settings: Settings): Promise<void> {
  if (!(await systemdAvailable(context))) throw new SetupError('error.noSystemd');
  const units = renderBackupUnits(settings, context.paths, process.execPath);
  ensureDirectory(context.paths.systemdDir, 0o755);
  writeFileIfChanged(join(context.paths.systemdDir, `${BACKUP_UNIT}.service`), units.service, 0o644);
  writeFileIfChanged(join(context.paths.systemdDir, `${BACKUP_UNIT}.timer`), units.timer, 0o644);
  await context.run('systemctl', ['daemon-reload']);
  await context.run('systemctl', ['enable', '--now', `${BACKUP_UNIT}.timer`]);
  // A timer whose schedule changed keeps its old next run until restarted.
  await context.run('systemctl', ['restart', `${BACKUP_UNIT}.timer`]);
}

export async function removeBackupSchedule(context: Context): Promise<void> {
  if (!(await systemdAvailable(context))) return;
  await context.run('systemctl', ['disable', '--now', `${BACKUP_UNIT}.timer`], { check: false });
  for (const suffix of ['service', 'timer']) rmSync(join(context.paths.systemdDir, `${BACKUP_UNIT}.${suffix}`), { force: true });
  await context.run('systemctl', ['daemon-reload'], { check: false });
}

export interface Pins { current: string; spare: string }

export function transportPins(context: Context): Pins {
  const store = new SecretStore(context.paths.secretsDir);
  if (!store.has('proxy_tls_current_key') || !store.has('proxy_tls_spare_key')) {
    throw new SetupError('error.noCertificateKey', { command: context.command });
  }
  return { current: spkiPin(store.read('proxy_tls_current_key')), spare: spkiPin(store.read('proxy_tls_spare_key')) };
}

/** The file the desktop and Android release builds take as ALPARTS_TRANSPORT_PINS_FILE. */
export function writePinsFile(context: Context, settings: Settings): string {
  const pins = transportPins(context);
  const content = `${JSON.stringify({ version: 1, hosts: { [settings.domain]: [pins.current, pins.spare] } }, null, 2)}\n`;
  writeFileIfChanged(context.paths.pinsFile, content, 0o644);
  return context.paths.pinsFile;
}

export function readInviteCode(context: Context): string {
  return readFileSync(join(context.paths.secretsDir, 'registration_invite_secret'), 'utf8').trim();
}
