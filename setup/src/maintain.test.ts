import assert from 'node:assert/strict';
import { once } from 'node:events';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { SetupError, type Context } from './context.ts';
import { prepareSecrets, writeConfiguration } from './deployment.ts';
import { Docker } from './docker.ts';
import { translator } from './i18n.ts';
import { RunLog } from './log.ts';
import { update } from './maintain.ts';
import { repositoryRoot, systemPaths } from './paths.ts';
import type { RunResult } from './run.ts';
import { loadSettings, saveSettings, type Settings } from './settings.ts';
import { Ui } from './ui.ts';

// update() against a stand-in for Docker, from an installed v1 to v2: what it
// backs up and migrates, which version ends up configured and running, and
// whether the settings say so, when v2 starts, and when it does not before
// and after a migration.

interface Scenario {
  /** Whether v2's containers start and pass their health checks. */
  starts: boolean;
  /** Whether v2 brings a migration. */
  migrates: boolean;
}

const ok = (stdout = ''): RunResult => ({ code: 0, stdout, stderr: '' });

async function runUpdate(scenario: Scenario) {
  const root = mkdtempSync(join(tmpdir(), 'alparts-update-'));
  // The app's readiness on its published port.
  const app = createServer((request, response) => response.end('{"status":"ready"}'));
  app.listen(0, '127.0.0.1');
  await once(app, 'listening');
  try {
    const paths = systemPaths(root, repositoryRoot());
    const settings: Settings = {
      version: 1,
      language: 'en',
      domain: 'chat.example.com',
      acmeEmail: null,
      certificates: 'local',
      email: { mode: 'disabled' },
      voice: { relay: false, publicAddress: null, basePort: 40000, workers: 1 },
      backup: { recipient: 'age1pq1qyqszqgp', time: '04:00', retentionDays: 30, minimumCopies: 7 },
      network: { edgeSubnet: '10.199.73.0/28', proxyAddress: '10.199.73.2', appPort: (app.address() as AddressInfo).port },
      image: { tag: 'v1', previousTag: 'v0' },
      auditHeadObjectKey: 'alparts-0123',
      state: { audit: 'initialized', completed: true, createdAt: '2026-10-28T00:00:00.000Z' },
    };
    const configuredTag = () => /^ALPARTS_IMAGE_TAG='([^']*)'$/m.exec(readFileSync(paths.composeEnvFile, 'utf8'))?.[1];
    const calls: string[] = [];
    let migrations = 27;
    const docker = new Docker(async (command, args) => {
      throw new Error(`unexpected: ${command} ${args.join(' ')}`);
    }, paths);
    Object.assign(docker, {
      status: async () => ({ serverVersion: '29.0.0', daemonRunning: true, composeVersion: '2.30.0', rootless: false, userNamespaces: false }),
      rootDirectory: async () => null,
      imageExists: async () => true,
      imageCommand: async () => ['node', 'packages/server/dist/index.js'],
      removeImage: async (reference: string) => void calls.push(`remove ${reference}`),
      services: async () => ['app', 'proxy', 'postgres', 'object-storage'].map((service) => ({ service, state: 'running', health: 'healthy' })),
      up: async (services: string[]) => {
        calls.push(`up ${services.join(',')} ${configuredTag()}`);
        if (services.includes('app') && configuredTag() === 'v2' && !scenario.starts) throw new Error('app is unhealthy');
      },
      stop: async (services: string[] = []) => void calls.push(`stop ${services.join(',')}`),
      restart: async (services: string[]) => void calls.push(`restart ${services.join(',')}`),
      exec: async () => ok(),
      runOnce: async (service: string, command: string[]) => {
        calls.push(`run ${service} ${command.join(' ')}`.trim());
        if (service === 'migrator' && scenario.migrates) migrations += 1;
        // A line after the file's name does not take its place.
        return service === 'backup' && !command.includes('--preflight') ? ok('/backups/alparts-backup-20261028T000000Z-0123456789ab.tar.age\nWARN shutting down\n') : ok();
      },
      psql: async (sql: string) => ok(sql.includes('__drizzle_migrations') ? `${migrations}\n` : ''),
    });
    const output = new PassThrough();
    output.resume();
    const context: Context = {
      language: 'en',
      t: translator('en'),
      ui: new Ui({ input: new PassThrough(), output }, { interactive: false }),
      log: new RunLog(null, 'update'),
      run: async (command) => {
        if (command === 'timedatectl') return { code: 1, stdout: '', stderr: '' };
        throw new Error(`unexpected: ${command}`);
      },
      docker,
      paths,
      command: 'alparts-setup',
      options: { yes: true, answersFile: null, disable: false, scheduled: false, rotate: false, imageTag: 'v2' },
      cleanups: [],
    };

    // Installed at v1.
    saveSettings(paths.settingsFile, settings);
    prepareSecrets(context, settings, null);
    await writeConfiguration(context, settings, 'v1');

    const outcome = await update(context).then(() => null, (error: unknown) => error);
    return { outcome, calls, saved: loadSettings(paths.settingsFile)!, configured: configuredTag(), pins: existsSync(paths.pinsFile), paths };
  } finally {
    app.close();
    rmSync(root, { recursive: true, force: true });
  }
}

const linux = process.platform === 'linux' ? false : 'the setup runs on Linux only';

test('an update backs up before it migrates, then runs the new version and drops the image before last', { skip: linux }, async () => {
  const { outcome, calls, saved, configured, pins } = await runUpdate({ starts: true, migrates: true });
  assert.equal(outcome, null);
  assert.deepEqual(saved.image, { tag: 'v2', previousTag: 'v1' });
  assert.equal(configured, 'v2');
  assert.ok(pins);
  const order = ['stop app', 'run backup /opt/alparts/scripts/backup.sh', 'run migrator', 'up app,proxy v2'].map((call) => calls.indexOf(call));
  assert.ok(order.every((index, position) => index >= 0 && (position === 0 || index > order[position - 1]!)), calls.join('\n'));
  assert.ok(calls.includes('remove alparts:v0'));
});

test('a new version that does not start, with the database unchanged, is replaced by the previous one', { skip: linux }, async () => {
  const { outcome, calls, saved, configured } = await runUpdate({ starts: false, migrates: false });
  assert.ok(outcome instanceof SetupError && outcome.key === 'update.rolledBack', String(outcome));
  assert.equal(outcome.values.version, 'v1');
  assert.deepEqual(saved.image, { tag: 'v1', previousTag: 'v0' });
  assert.equal(configured, 'v1');
  assert.ok(calls.indexOf('up app,proxy v1') > calls.indexOf('up app,proxy v2'), calls.join('\n'));
  assert.ok(!calls.some((call) => call.startsWith('remove ')));
});

test('after a migration the previous version no longer fits, so the update points to the backup instead', { skip: linux }, async () => {
  const { outcome, calls, saved, configured, paths } = await runUpdate({ starts: false, migrates: true });
  assert.ok(outcome instanceof SetupError && outcome.key === 'update.cannotRollBack', String(outcome));
  assert.equal(outcome.values.file, join(paths.backupDir, 'alparts-backup-20261028T000000Z-0123456789ab.tar.age'));
  // The database belongs to the new version now, and so do the settings.
  assert.deepEqual(saved.image, { tag: 'v2', previousTag: 'v1' });
  assert.equal(configured, 'v2');
  assert.ok(!calls.includes('up app,proxy v1'), calls.join('\n'));
});
