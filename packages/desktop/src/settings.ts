import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
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

/**
 * Whether the app is locked. The main process answers for the renderer and also keeps a marker
 * file next to settings.json, so closing and reopening the app does not skip the password. The
 * file's existence is the state: only an unlock removes it, and a file that is damaged or cannot
 * be read still counts as locked.
 */
export class AppLock {
  readonly #directory: string;
  readonly #filename: string;
  #locked = false;
  // Marker changes run one after another, so the file ends up matching the last request.
  #writes: Promise<void> = Promise.resolve();

  constructor(userDataDirectory: string) {
    this.#directory = userDataDirectory;
    this.#filename = path.join(userDataDirectory, 'app-lock.json');
  }

  get locked(): boolean {
    return this.#locked;
  }

  /** Picks up the lock an earlier run left behind. */
  async load(): Promise<void> {
    try {
      await stat(this.#filename);
      this.#locked = true;
    } catch (error) {
      // Only a missing file means unlocked; any other failure must not open the app.
      this.#locked = (error as NodeJS.ErrnoException).code !== 'ENOENT';
    }
  }

  /** Locks at once and resolves when the marker is saved. */
  async lock(): Promise<void> {
    this.#locked = true;
    await this.#enqueue(() => this.#save());
  }

  /** Unlocks at once; if the marker cannot be removed the app stays locked and this rejects. */
  async unlock(): Promise<void> {
    this.#locked = false;
    try {
      await this.#enqueue(() => rm(this.#filename, { force: true }));
    } catch (error) {
      this.#locked = true;
      throw error;
    }
  }

  /** Resolves when every marker change requested so far has finished, whether or not it worked. */
  async settled(): Promise<void> {
    await this.#writes;
  }

  #enqueue(change: () => Promise<void>): Promise<void> {
    const result = this.#writes.then(change);
    this.#writes = result.catch(() => undefined);
    return result;
  }

  async #save(): Promise<void> {
    await mkdir(this.#directory, { recursive: true, mode: 0o700 });
    const temporary = path.join(this.#directory, `.app-lock-${randomUUID()}.tmp`);
    try {
      await writeFile(temporary, `${JSON.stringify({ version: 1, locked: true })}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
      await rename(temporary, this.#filename);
    } finally {
      await rm(temporary, { force: true }).catch(() => undefined);
    }
  }
}

export function defaultSettings(): DesktopSettings {
  return {
    version: 1,
    serverUrl: null,
    idleLockMinutes: DEFAULT_IDLE_LOCK_MINUTES,
  };
}
