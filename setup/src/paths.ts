import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** The Compose project, and the prefix of every host path this setup owns. */
export const PROJECT_NAME = 'alparts-production';

export interface Paths {
  /** The repository checkout that holds this setup, the Dockerfile and compose.production.yml. */
  repo: string;
  configDir: string;
  secretsDir: string;
  settingsFile: string;
  composeEnvFile: string;
  composeOverrideFile: string;
  /** Mounted as a directory, so a rewritten Caddyfile reaches the running proxy. */
  proxyConfigDir: string;
  caddyfile: string;
  postgresConfigDir: string;
  pgHbaFile: string;
  pinsFile: string;
  emptyDir: string;
  stateDir: string;
  backupDir: string;
  /** Where a backup gathers the data before encrypting it; backup.sh empties it when done. */
  backupWorkDir: string;
  logDir: string;
  lockFile: string;
  systemdDir: string;
}

export function repositoryRoot(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
}

/**
 * Every host path the setup reads or writes. `root` prefixes them all, so a
 * test can work in a temporary directory instead of /etc and /var.
 */
export function systemPaths(root = '/', repo = repositoryRoot()): Paths {
  const configDir = join(root, 'etc', PROJECT_NAME);
  const stateDir = join(root, 'var', 'lib', PROJECT_NAME);
  return {
    repo,
    configDir,
    secretsDir: join(configDir, 'secrets'),
    settingsFile: join(configDir, 'setup.json'),
    composeEnvFile: join(configDir, 'compose.env'),
    composeOverrideFile: join(configDir, 'compose.json'),
    proxyConfigDir: join(configDir, 'proxy'),
    caddyfile: join(configDir, 'proxy', 'Caddyfile'),
    postgresConfigDir: join(configDir, 'postgres'),
    pgHbaFile: join(configDir, 'postgres', 'pg_hba.conf'),
    pinsFile: join(configDir, 'transport-pins.json'),
    emptyDir: join(configDir, 'empty'),
    stateDir,
    backupDir: join(stateDir, 'backups'),
    backupWorkDir: join(stateDir, 'backup-work'),
    logDir: join(root, 'var', 'log', PROJECT_NAME),
    lockFile: join(root, 'run', `${PROJECT_NAME}-setup.lock`),
    systemdDir: join(root, 'etc', 'systemd', 'system'),
  };
}
