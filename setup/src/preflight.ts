import { existsSync, statfsSync } from 'node:fs';
import { totalmem } from 'node:os';
import { join } from 'node:path';
import { SetupError, type Context } from './context.ts';
import { versionAtLeast } from './docker.ts';
import { busyPorts, type PortSpec } from './network.ts';
import type { Settings } from './settings.ts';

export const MINIMUM_COMPOSE = '2.20.0';

function gigabytes(bytes: number): string {
  return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
}

/** Fails on what blocks the setup, warns about what may hurt later. */
export async function checkHost(context: Context): Promise<void> {
  const { t, ui, docker, paths } = context;
  if (process.platform !== 'linux') throw new SetupError('error.notLinux');
  for (const file of ['Dockerfile', 'compose.production.yml', 'scripts/backup.sh']) {
    if (!existsSync(join(paths.repo, file))) throw new SetupError('error.repoIncomplete', { path: join(paths.repo, file) });
  }

  const status = await docker.status();
  if (status.serverVersion === null) throw new SetupError('error.dockerMissing');
  if (!status.daemonRunning) throw new SetupError('error.dockerStopped');
  if (!status.composeVersion || !versionAtLeast(status.composeVersion, MINIMUM_COMPOSE)) {
    throw new SetupError('error.composeMissing', { version: MINIMUM_COMPOSE });
  }
  if (status.rootless || status.userNamespaces) throw new SetupError('error.dockerRootless');

  if (totalmem() < 1.8 * 1024 ** 3) ui.warning(t('warning.lowMemory', { size: gigabytes(totalmem()) }));
  const root = await docker.rootDirectory();
  if (root) {
    try {
      const stats = statfsSync(root);
      const free = stats.bavail * stats.bsize;
      if (free < 10 * 1024 ** 3) ui.warning(t('warning.lowDisk', { size: gigabytes(free) }));
    } catch {
      // The directory is not visible from here (a remote daemon); skip the hint.
    }
  }
  const clock = await context.run('timedatectl', ['show', '--property=NTPSynchronized', '--value'], { check: false }).catch(() => null);
  if (clock && clock.code === 0 && clock.stdout.trim() === 'no') ui.warning(t('warning.clock'));
}

/** The host ports the deployment publishes, with the service that holds each. */
export function publishedPorts(settings: Pick<Settings, 'voice' | 'network'>): Array<PortSpec & { service: string }> {
  const ports: Array<PortSpec & { service: string }> = [
    { port: 80, protocol: 'tcp', service: 'proxy' },
    { port: 443, protocol: 'tcp', service: 'proxy' },
    { port: 443, protocol: 'udp', service: 'proxy' },
    { port: settings.network.appPort, protocol: 'tcp', host: '127.0.0.1', service: 'app' },
  ];
  if (settings.voice.relay) {
    for (let port = settings.voice.basePort; port < settings.voice.basePort + settings.voice.workers; port += 1) {
      ports.push({ port, protocol: 'udp', service: 'app' }, { port, protocol: 'tcp', service: 'app' });
    }
  }
  return ports;
}

/** Ports another program holds; those of the deployment's own running services are left out. */
export async function checkPortsFree(context: Context, settings: Pick<Settings, 'voice' | 'network'>): Promise<void> {
  const running = new Set((await context.docker.services()).filter((service) => service.state === 'running').map((service) => service.service));
  const busy = await busyPorts(publishedPorts(settings).filter((spec) => !running.has(spec.service)));
  if (busy.length > 0) {
    throw new SetupError('error.portsBusy', { ports: busy.map((spec) => `${spec.port}/${spec.protocol}`).join(', ') });
  }
}
