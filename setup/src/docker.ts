import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseCidr, type Cidr } from './network.ts';
import { PROJECT_NAME, type Paths } from './paths.ts';
import type { RunOptions, RunResult, Runner } from './run.ts';

export interface ServiceState {
  service: string;
  state: string;
  health: string;
}

export interface DockerStatus {
  /** null when the docker command is missing. */
  serverVersion: string | null;
  daemonRunning: boolean;
  composeVersion: string | null;
  rootless: boolean;
  userNamespaces: boolean;
}

/** Compares dotted versions numerically; missing parts count as 0. */
export function versionAtLeast(version: string, minimum: string): boolean {
  const have = version.replace(/^v/, '').split(/[.+-]/).map((part) => Number.parseInt(part, 10) || 0);
  const want = minimum.split('.').map(Number);
  for (let index = 0; index < want.length; index += 1) {
    const difference = (have[index] ?? 0) - want[index]!;
    if (difference !== 0) return difference > 0;
  }
  return true;
}

/** `docker compose ps --format json` prints one object per line in newer releases and an array in older ones. */
export function parseComposePs(output: string): ServiceState[] {
  const trimmed = output.trim();
  if (!trimmed) return [];
  const entries: unknown[] = trimmed.startsWith('[')
    ? JSON.parse(trimmed) as unknown[]
    : trimmed.split('\n').filter(Boolean).map((line) => JSON.parse(line) as unknown);
  return entries.map((entry) => {
    const record = entry as Record<string, unknown>;
    return {
      service: String(record.Service ?? ''),
      state: String(record.State ?? ''),
      health: String(record.Health ?? ''),
    };
  });
}

/**
 * Docker and Compose for this deployment. Every Compose command names the
 * project, the repository's compose.production.yml with the generated
 * compose.json on top, and the generated variables, so the result does not
 * depend on the directory or the environment the setup runs from.
 */
export class Docker {
  private readonly run: Runner;
  private readonly paths: Paths;

  constructor(run: Runner, paths: Paths) {
    this.run = run;
    this.paths = paths;
  }

  async status(): Promise<DockerStatus> {
    const result: DockerStatus = { serverVersion: null, daemonRunning: false, composeVersion: null, rootless: false, userNamespaces: false };
    try {
      const version = await this.run('docker', ['version', '--format', '{{.Server.Version}}'], { check: false });
      result.daemonRunning = version.code === 0 && version.stdout.trim() !== '';
      result.serverVersion = result.daemonRunning ? version.stdout.trim() : '';
    } catch {
      return result;
    }
    const compose = await this.run('docker', ['compose', 'version', '--short'], { check: false });
    if (compose.code === 0) result.composeVersion = compose.stdout.trim().replace(/^v/, '');
    if (result.daemonRunning) {
      const info = await this.run('docker', ['info', '--format', '{{json .SecurityOptions}}'], { check: false });
      const options = info.code === 0 ? JSON.parse(info.stdout.trim() || '[]') as string[] : [];
      result.rootless = options.some((option) => option.includes('name=rootless'));
      result.userNamespaces = options.some((option) => option.includes('name=userns'));
    }
    return result;
  }

  async rootDirectory(): Promise<string | null> {
    const result = await this.run('docker', ['info', '--format', '{{.DockerRootDir}}'], { check: false });
    return result.code === 0 ? result.stdout.trim() || null : null;
  }

  async imageExists(reference: string): Promise<boolean> {
    return (await this.run('docker', ['image', 'inspect', '--format', '{{.Id}}', reference], { check: false })).code === 0;
  }

  async imageCommand(reference: string): Promise<string[]> {
    const result = await this.run('docker', ['image', 'inspect', '--format', '{{json .Config.Cmd}}', reference]);
    const command = JSON.parse(result.stdout.trim()) as unknown;
    if (!Array.isArray(command) || command.some((part) => typeof part !== 'string')) throw new Error(`Unexpected command in ${reference}`);
    return command as string[];
  }

  async removeImage(reference: string): Promise<void> {
    await this.run('docker', ['image', 'rm', reference], { check: false });
  }

  /** The address ranges of every Docker network on this host. */
  async networkRanges(): Promise<Cidr[]> {
    const ids = (await this.run('docker', ['network', 'ls', '-q'])).stdout.split('\n').filter(Boolean);
    if (ids.length === 0) return [];
    const result = await this.run('docker', ['network', 'inspect', '--format', '{{range .IPAM.Config}}{{.Subnet}} {{end}}', ...ids]);
    return result.stdout.split(/\s+/).map((subnet) => parseCidr(subnet)).filter((cidr): cidr is Cidr => cidr !== null);
  }

  /** Volumes of this project: data that outlives its containers. */
  async projectVolumes(): Promise<string[]> {
    const result = await this.run('docker', ['volume', 'ls', '-q', '--filter', `label=com.docker.compose.project=${PROJECT_NAME}`]);
    return result.stdout.split('\n').filter(Boolean);
  }

  private composeArguments(profiles: string[]): string[] {
    return [
      'compose',
      '--project-name', PROJECT_NAME,
      '--project-directory', this.paths.repo,
      '--env-file', this.paths.composeEnvFile,
      '-f', join(this.paths.repo, 'compose.production.yml'),
      '-f', this.paths.composeOverrideFile,
      ...profiles.flatMap((profile) => ['--profile', profile]),
    ];
  }

  /** Variables compose.env sets, and Compose's own, are dropped from the inherited environment so the file decides. */
  private inheritedFilter(): (name: string) => boolean {
    let keys = new Set<string>();
    try {
      keys = new Set(readFileSync(this.paths.composeEnvFile, 'utf8').split('\n').map((line) => line.split('=')[0]!.trim()).filter(Boolean));
    } catch {
      // Before the file exists there is nothing to protect.
    }
    return (name) => keys.has(name) || name.startsWith('COMPOSE_');
  }

  compose(args: string[], options: RunOptions & { profiles?: string[] } = {}): Promise<RunResult> {
    const { profiles = [], ...runOptions } = options;
    return this.run('docker', [...this.composeArguments(profiles), ...args], { clearEnv: this.inheritedFilter(), ...runOptions });
  }

  async services(): Promise<ServiceState[]> {
    const result = await this.compose(['ps', '--all', '--format', 'json'], { check: false });
    return result.code === 0 ? parseComposePs(result.stdout) : [];
  }

  async up(services: string[], options: { waitSeconds?: number } = {}): Promise<void> {
    const wait = options.waitSeconds ? ['--wait', '--wait-timeout', String(options.waitSeconds)] : [];
    await this.compose(['up', '--detach', '--remove-orphans', ...wait, ...services]);
  }

  async stop(services: string[] = []): Promise<void> {
    await this.compose(['stop', '--timeout', '40', ...services]);
  }

  async restart(services: string[]): Promise<void> {
    await this.compose(['restart', '--timeout', '40', ...services]);
  }

  async build(service: string, profiles: string[] = []): Promise<void> {
    await this.compose(['build', '--pull', service], { profiles, timeoutMs: 2 * 60 * 60 * 1000 });
  }

  /**
   * A one-off container of the service (with its networks, secrets and
   * volumes), removed afterwards. `environment` is for values that are not
   * secret: they appear in the command line.
   */
  runOnce(service: string, command: string[], options: RunOptions & { profiles?: string[]; environment?: Record<string, string>; entrypoint?: string } = {}): Promise<RunResult> {
    const { environment = {}, entrypoint, profiles, ...runOptions } = options;
    const flags = ['run', '--rm', '--no-deps', '-T', ...(entrypoint !== undefined ? ['--entrypoint', entrypoint] : [])];
    for (const [name, value] of Object.entries(environment)) flags.push('-e', `${name}=${value}`);
    return this.compose([...flags, service, ...command], { ...runOptions, profiles });
  }

  exec(service: string, command: string[], options: RunOptions & { user?: string } = {}): Promise<RunResult> {
    const { user, ...runOptions } = options;
    return this.compose(['exec', '-T', ...(user ? ['--user', user] : []), service, ...command], runOptions);
  }

  /** Runs SQL as the database superuser through the local socket. */
  psql(sql: string, database: string, options: { tuplesOnly?: boolean } = {}): Promise<RunResult> {
    const flags = ['-X', '-q', '-v', 'ON_ERROR_STOP=1', ...(options.tuplesOnly ? ['-At'] : []), '-d', database];
    return this.exec('postgres', ['psql', ...flags], { user: 'postgres', input: sql });
  }
}
