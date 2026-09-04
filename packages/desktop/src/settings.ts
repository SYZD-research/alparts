import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import {
  DEFAULT_IDLE_LOCK_MINUTES,
  deploymentNamespace,
  normalizeIdleLockMinutes,
  normalizeServerUrl,
} from './security-policy.js';

export interface DesktopSettings {
  version: 1;
  serverUrl: string | null;
  idleLockMinutes: number;
}

export class SettingsStore {
  readonly #directory: string;
  readonly #filename: string;

  constructor(userDataDirectory: string) {
    this.#directory = userDataDirectory;
    this.#filename = path.join(userDataDirectory, 'settings.json');
  }

  async load(): Promise<DesktopSettings> {
    try {
      const parsed = JSON.parse(await readFile(this.#filename, 'utf8')) as Partial<DesktopSettings>;
      return {
        version: 1,
        serverUrl: parsed.serverUrl === null || parsed.serverUrl === undefined
          ? null
          : normalizeServerUrl(parsed.serverUrl),
        idleLockMinutes: parsed.idleLockMinutes === undefined
          ? DEFAULT_IDLE_LOCK_MINUTES
          : normalizeIdleLockMinutes(parsed.idleLockMinutes),
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return defaultSettings();
      // Invalid settings must not silently select an unintended server.
      return defaultSettings();
    }
  }

  async save(settings: DesktopSettings): Promise<void> {
    const normalized: DesktopSettings = {
      version: 1,
      serverUrl: settings.serverUrl === null ? null : normalizeServerUrl(settings.serverUrl),
      idleLockMinutes: normalizeIdleLockMinutes(settings.idleLockMinutes),
    };
    await mkdir(this.#directory, { recursive: true, mode: 0o700 });
    const temporary = path.join(this.#directory, `.settings-${randomUUID()}.tmp`);
    try {
      await writeFile(temporary, `${JSON.stringify(normalized)}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
      await rename(temporary, this.#filename);
    } finally {
      await rm(temporary, { force: true }).catch(() => undefined);
    }
  }

  namespace(settings: DesktopSettings): string | null {
    return settings.serverUrl ? deploymentNamespace(settings.serverUrl) : null;
  }
}

export function defaultSettings(): DesktopSettings {
  return {
    version: 1,
    serverUrl: null,
    idleLockMinutes: DEFAULT_IDLE_LOCK_MINUTES,
  };
}
