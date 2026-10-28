import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { BACKUP_USER } from './files.ts';
import { IMAGES } from './images.ts';
import { repositoryRoot, systemPaths } from './paths.ts';
import { appStartCommand, composeEnvironment, renderBackupUnits, renderCaddyfile, renderComposeOverride, renderEnvFile, renderPgHba } from './render.ts';
import { secretMode, secretOwner, type SecretName } from './secrets.ts';
import type { Settings } from './settings.ts';

const paths = systemPaths('/', '/opt/alparts');
const imageCommand = ['node', '--permission', '--allow-fs-read=/app', 'packages/server/dist/index.js'];

function settings(overrides: Partial<Settings> = {}): Settings {
  return {
    version: 1,
    language: 'ja',
    domain: 'chat.example.com',
    acmeEmail: null,
    certificates: 'public',
    email: { mode: 'smtp', host: 'smtp.example.com', port: 587, security: 'starttls', from: 'no-reply@example.com', user: 'mailer' },
    voice: { relay: true, publicAddress: '203.0.113.10', basePort: 40000, workers: 1 },
    backup: { recipient: 'age1pq1example', time: '04:00', retentionDays: 30, minimumCopies: 7 },
    network: { edgeSubnet: '10.199.73.0/28', proxyAddress: '10.199.73.2', appPort: 3000 },
    image: { tag: 'abc123', previousTag: null },
    auditHeadObjectKey: 'alparts-0123',
    state: { audit: 'initialized', completed: true, createdAt: '2026-10-27T00:00:00.000Z' },
    ...overrides,
  };
}

test('env files quote every value and refuse values that would break out', () => {
  assert.match(renderEnvFile({ A: 'x$y' }), /^A='x\$y'$/m);
  // A single quote cannot be written inside single quotes: Compose reads these escapes in double quotes.
  assert.match(renderEnvFile({ A: "o'brien@example.com" }), /^A="o'brien@example\.com"$/m);
  assert.match(renderEnvFile({ A: `it's $HOME "x" \\` }), /^A="it's \\\$HOME \\"x\\" \\\\"$/m);
  assert.throws(() => renderEnvFile({ A: 'two\nlines' }));
  assert.throws(() => renderEnvFile({ lower: 'x' }));
});

test('the Compose variables point the app at the proxy, TLS dependencies and mail settings', () => {
  const values = composeEnvironment(settings(), paths, 'abc123');
  assert.equal(values.CORS_ORIGINS, 'https://chat.example.com');
  assert.equal(values.TRUSTED_PROXIES, '10.199.73.2');
  assert.equal(values.DB_SSL, 'true');
  assert.equal(values.S3_USE_SSL, 'true');
  assert.equal(values.ALLOW_INSECURE_LOOPBACK_DEPENDENCIES, 'false');
  assert.equal(values.EMAIL_VERIFICATION, 'required');
  assert.equal(values.SMTP_SECURE, 'false');
  assert.equal(values.DATABASE_URL_SECRET_FILE, '/etc/alparts-production/secrets/database_url');
  const disabled = composeEnvironment(settings({ email: { mode: 'disabled' } }), paths, 'abc123');
  assert.equal(disabled.EMAIL_VERIFICATION, 'disabled');
  assert.equal(disabled.SMTP_HOST, '');
});

test('the app starts without the permission model and keeps its other flags', () => {
  assert.deepEqual(
    appStartCommand(['node', '--permission', '--allow-fs-read=/app', '--allow-worker', '--disallow-code-generation-from-strings', 'packages/server/dist/index.js']),
    ['node', '--disallow-code-generation-from-strings', 'packages/server/dist/index.js'],
  );
  const override = JSON.parse(renderComposeOverride(settings(), paths, { appCommand: imageCommand, backupImage: 'tools:1' }));
  assert.deepEqual(override.services.app.command, ['node', 'packages/server/dist/index.js']);
});

test('the voice relay gets its ports and reserved local ports', () => {

  const override = JSON.parse(renderComposeOverride(settings({ voice: { relay: true, publicAddress: '203.0.113.10', basePort: 40000, workers: 2 } }), paths, { appCommand: imageCommand, backupImage: 'tools:1' }));
  const app = override.services.app;
  assert.deepEqual(app.ports, ['40000-40001:40000-40001/udp', '40000-40001:40000-40001/tcp']);
  assert.equal(app.sysctls['net.ipv4.ip_local_reserved_ports'], '40000-40001');
  assert.equal(app.environment.VOICE_SFU_ANNOUNCED_ADDRESS, '203.0.113.10');
  assert.equal(app.environment.VOICE_SFU_WORKERS, '2');

  const direct = JSON.parse(renderComposeOverride(settings({ voice: { relay: false, publicAddress: null, basePort: 40000, workers: 1 } }), paths, { appCommand: imageCommand, backupImage: 'tools:1' }));
  assert.equal(direct.services.app.ports, undefined);
  assert.equal(direct.services.app.sysctls, undefined);
  assert.equal(direct.services.app.environment.VOICE_SFU_ENABLED, 'false');
});

test('the services are split between the public edge and an internal backend', () => {
  const override = JSON.parse(renderComposeOverride(settings(), paths, { appCommand: imageCommand, backupImage: 'tools:1' }));
  assert.equal(override.networks.backend.internal, true);
  assert.deepEqual(override.networks.edge.ipam.config, [{ subnet: '10.199.73.0/28', ip_range: '10.199.73.8/29', gateway: '10.199.73.1' }]);
  assert.deepEqual(override.services.proxy.networks, { edge: { ipv4_address: '10.199.73.2' } });
  assert.deepEqual(Object.keys(override.services.postgres.networks), ['backend']);
  assert.deepEqual(Object.keys(override.services['object-storage'].networks), ['backend']);
  assert.deepEqual(Object.keys(override.services.app.networks).sort(), ['backend', 'edge']);
  assert.equal(override.services.postgres.ports, undefined);
  assert.equal(override.services['object-storage'].ports, undefined);
  assert.equal(override.services.postgres.image, IMAGES.postgres);
  assert.deepEqual(override.services.backup.profiles, ['operations']);

  // Every secret a service added here uses is defined here (compose.production.yml defines its own).
  const base = new Set(['database_url', 's3_access_key', 's3_secret_key', 'jwt_secret', 'password_pepper', 'password_pepper_previous', 'audit_integrity_key', 'metrics_token', 'smtp_password', 'migration_database_url']);
  for (const [name, service] of Object.entries(override.services) as Array<[string, { secrets?: string[] }]>) {
    for (const secret of service.secrets ?? []) {
      assert.ok(override.secrets[secret] || base.has(secret), `${name} uses ${secret}`);
    }
  }
  // Compose interpolates $ in the file; the generated scripts must not contain one.
  assert.doesNotMatch(JSON.stringify(override), /\$/);
});

test('backups run as an unprivileged user that can read their credentials and write their directories', () => {
  const dockerfile = readFileSync(join(repositoryRoot(), 'setup', 'backup-tools', 'Dockerfile'), 'utf8');
  assert.equal([...dockerfile.matchAll(/^USER\s+(\S+)\s*$/gm)].at(-1)?.[1], 'postgres');

  const backup = JSON.parse(renderComposeOverride(settings(), paths, { appCommand: imageCommand, backupImage: 'tools:1' })).services.backup;
  for (const name of backup.secrets as SecretName[]) {
    assert.ok(secretOwner(name) === BACKUP_USER || (secretMode(name) & 0o004) !== 0, name);
  }
  // Host directories the setup hands to that user, not volumes that root would own.
  assert.deepEqual(backup.volumes.slice(1), [`${paths.backupDir}:/backups`, `${paths.backupWorkDir}:/work`]);
  assert.equal(backup.user, undefined);
});

test('the Caddyfile keeps the certificate key, buffers bodies, hides health checks and turns HTTP/2 off', () => {
  const caddyfile = renderCaddyfile(settings());
  assert.match(caddyfile, /^\{\n(?:\t.*\n)*\tservers \{\n\t\tprotocols h1 h3\n\t\}\n\}$/m);
  // Port 80 is a site of its own, so the same options reach it.
  assert.match(caddyfile, /^http:\/\/ \{\n\tredir https:\/\/\{host\}\{uri\} 308\n\}$/m);
  assert.match(caddyfile, /^chat\.example\.com \{$/m);
  assert.match(caddyfile, /^\ttls \{$/m);
  assert.match(caddyfile, /reuse_private_keys/);
  assert.match(caddyfile, /request_buffers 4MiB/);
  assert.match(caddyfile, /@private path \/health \/health\/\* \/metrics \/metrics\/\*/);
  assert.match(renderCaddyfile(settings({ certificates: 'local' })), /^\ttls internal \{$/m);
  // Quoted, so an address such as #ops@example.com is not read as a comment.
  assert.match(renderCaddyfile(settings({ acmeEmail: '#ops@example.com' })), /^\temail "#ops@example\.com"$/m);
});

test('PostgreSQL admits the superuser locally only and the roles over TLS only', () => {
  const rules = renderPgHba().split('\n').filter((line) => line && !line.startsWith('#'));
  assert.deepEqual(rules, [
    'local   all     postgres  peer',
    'hostssl alparts alparts_owner,alparts_app,alparts_backup all scram-sha-256',
  ]);
});

test('the backup timer runs the setup with quoted paths', () => {
  const { service, timer } = renderBackupUnits(settings(), systemPaths('/', '/srv/my alparts'), '/usr/bin/node');
  assert.match(service, /^ExecStart="\/usr\/bin\/node" "\/srv\/my alparts\/setup\/src\/main\.ts" backup --scheduled --lang ja$/m);
  // Stopped, the run stops its backup and starts the app again, which takes longer than systemd's default wait.
  assert.match(service, /^TimeoutStopSec=5min$/m);
  assert.match(timer, /^OnCalendar=\*-\*-\* 04:00:00$/m);
});

test('PostgreSQL and the object store run the images development uses', () => {
  const development = readFileSync(join(repositoryRoot(), 'docker-compose.yml'), 'utf8');
  const images = [...development.matchAll(/^\s+image:\s+(\S+)$/gm)].map((match) => match[1]);
  assert.ok(images.includes(IMAGES.postgres));
  assert.ok(images.includes(IMAGES.objectStorage));
});
