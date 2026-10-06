import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { chmod, open, rename, rm, writeFile, type FileHandle } from 'node:fs/promises';
import path from 'node:path';

export const MAX_NATIVE_SAVE_BYTES = 100 * 1024 * 1024;
export const MAX_NATIVE_SAVE_CHUNK_BYTES = 5 * 1024 * 1024;

export type SaveTargetSelector = (suggestedName: string) => Promise<string | null>;
export type SavedFileProtector = (filename: string) => Promise<void>;

interface ActiveSave {
  handle: FileHandle;
  temporaryPath: string;
  targetPath: string;
  expectedBytes: number;
  writtenBytes: number;
  writing: boolean;
}

/**
 * Owns every plaintext file descriptor used by the renderer. The renderer gets
 * only an opaque, short-lived token and can never choose or inspect a path.
 */
export class NativeFileSaveManager {
  readonly #active = new Map<string, ActiveSave>();
  #pendingSelections = 0;

  constructor(
    private readonly selectTarget: SaveTargetSelector,
    private readonly protectSavedFile: SavedFileProtector = protectSavedFileForPlatform,
  ) {}

  async begin(suggestedNameValue: unknown, expectedBytesValue: unknown, dangerousValue: unknown): Promise<string | null> {
    if (this.#active.size + this.#pendingSelections >= 2) throw new Error('TOO_MANY_ACTIVE_SAVES');
    const suggestedName = normalizeSuggestedFilename(suggestedNameValue);
    const expectedBytes = normalizeExpectedBytes(expectedBytesValue);
    // The flag only decides the renderer's own confirmation. Every saved file
    // is marked as downloaded, whatever its type, as browsers do.
    if (typeof dangerousValue !== 'boolean') throw new Error('INVALID_DANGER_FLAG');

    this.#pendingSelections += 1;
    let selectedPath: string | null;
    try {
      selectedPath = await this.selectTarget(suggestedName);
    } finally {
      this.#pendingSelections -= 1;
    }
    if (!selectedPath) return null;
    const targetPath = assertSafeSelectedPath(selectedPath);
    const temporaryPath = path.join(
      path.dirname(targetPath),
      `.${path.basename(targetPath)}.${randomUUID()}.alparts-partial`,
    );
    const handle = await open(temporaryPath, 'wx', 0o600);
    const token = randomUUID();
    this.#active.set(token, {
      handle,
      temporaryPath,
      targetPath,
      expectedBytes,
      writtenBytes: 0,
      writing: false,
    });
    return token;
  }

  async write(tokenValue: unknown, chunkValue: unknown): Promise<number> {
    const { token, save } = this.#requiredSave(tokenValue);
    if (save.writing) throw new Error('SAVE_ALREADY_WRITING');
    if (!(chunkValue instanceof ArrayBuffer) || chunkValue.byteLength > MAX_NATIVE_SAVE_CHUNK_BYTES) {
      await this.#discard(token, save);
      throw new Error(chunkValue instanceof ArrayBuffer ? 'SAVE_CHUNK_TOO_LARGE' : 'INVALID_SAVE_CHUNK');
    }
    if (save.writtenBytes + chunkValue.byteLength > save.expectedBytes) {
      await this.#discard(token, save);
      throw new Error('SAVE_SIZE_MISMATCH');
    }

    save.writing = true;
    try {
      const bytes = Buffer.from(chunkValue);
      let offset = 0;
      while (offset < bytes.byteLength) {
        const result = await save.handle.write(bytes, offset, bytes.byteLength - offset);
        if (result.bytesWritten < 1) throw new Error('SAVE_WRITE_FAILED');
        offset += result.bytesWritten;
      }
      save.writtenBytes += bytes.byteLength;
      return save.writtenBytes;
    } catch (error) {
      await this.#discard(token, save);
      throw error;
    } finally {
      save.writing = false;
    }
  }

  async finish(tokenValue: unknown): Promise<boolean> {
    const { token, save } = this.#requiredSave(tokenValue);
    if (save.writing) throw new Error('SAVE_ALREADY_WRITING');
    if (save.writtenBytes !== save.expectedBytes) {
      await this.#discard(token, save);
      throw new Error('SAVE_SIZE_MISMATCH');
    }

    this.#active.delete(token);
    try {
      await save.handle.sync();
      await save.handle.close();
      await this.protectSavedFile(save.temporaryPath);
      await rename(save.temporaryPath, save.targetPath);
      return true;
    } catch (error) {
      await save.handle.close().catch(() => undefined);
      await rm(save.temporaryPath, { force: true }).catch(() => undefined);
      throw error;
    }
  }

  async cancel(tokenValue: unknown): Promise<boolean> {
    const token = requiredToken(tokenValue);
    const save = this.#active.get(token);
    if (!save) return false;
    if (save.writing) throw new Error('SAVE_ALREADY_WRITING');
    await this.#discard(token, save);
    return true;
  }

  async abortAll(): Promise<void> {
    await Promise.all([...this.#active.entries()].map(([token, save]) => this.#discard(token, save)));
  }

  #requiredSave(tokenValue: unknown): { token: string; save: ActiveSave } {
    const token = requiredToken(tokenValue);
    const save = this.#active.get(token);
    if (!save) throw new Error('UNKNOWN_SAVE');
    return { token, save };
  }

  async #discard(token: string, save: ActiveSave): Promise<void> {
    this.#active.delete(token);
    await save.handle.close().catch(() => undefined);
    await rm(save.temporaryPath, { force: true }).catch(() => undefined);
  }
}

export function normalizeSuggestedFilename(value: unknown): string {
  if (typeof value !== 'string') throw new Error('INVALID_FILENAME');
  let filename = value
    .normalize('NFKC')
    .replace(/[\\/:*?"<>|\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, '_')
    .replace(/[. ]+$/g, '')
    .trim()
    .slice(0, 180);
  if (!filename || /^\.+$/.test(filename)) filename = 'attachment';
  const stem = filename.split('.')[0] || '';
  if (/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])$/i.test(stem)) filename = `_${filename}`;
  return filename;
}

export function assertSafeSelectedPath(value: unknown, platform = process.platform): string {
  const pathApi = platform === 'win32' ? path.win32 : path;
  if (
    typeof value !== 'string'
    || value.length < 1
    || value.length > 4096
    || !pathApi.isAbsolute(value)
    || /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/.test(value)
  ) throw new Error('INVALID_SAVE_PATH');
  const basename = pathApi.basename(value);
  if (!basename || basename === '.' || basename === '..') throw new Error('INVALID_SAVE_PATH');
  if (platform === 'win32') {
    const stem = basename.split('.')[0] || '';
    if (
      /[<>:"/\\|?*]/.test(basename)
      || /[. ]$/.test(basename)
      || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])$/i.test(stem)
    ) throw new Error('INVALID_SAVE_PATH');
  }
  return value;
}

async function protectSavedFileForPlatform(filename: string): Promise<void> {
  await chmod(filename, 0o600);
  if (process.platform === 'win32') {
    await writeFile(`${filename}:Zone.Identifier`, '[ZoneTransfer]\r\nZoneId=3\r\n', {
      encoding: 'utf8',
      flag: 'wx',
    });
    return;
  }
  if (process.platform === 'darwin') {
    const timestamp = Math.floor(Date.now() / 1000).toString(16);
    await runFixedProgram('/usr/bin/xattr', [
      '-w',
      'com.apple.quarantine',
      `0081;${timestamp};alparts;${randomUUID()}`,
      filename,
    ]);
  }
  // On Linux, mode 0600 deliberately removes execute permission. Together
  // with the confirmation the UI asks for risky types, this is the guard.
}

async function runFixedProgram(program: string, args: string[]): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    execFile(program, args, { timeout: 5_000, windowsHide: true }, (error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

function normalizeExpectedBytes(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > MAX_NATIVE_SAVE_BYTES) {
    throw new Error('INVALID_SAVE_SIZE');
  }
  return value as number;
}

function requiredToken(value: unknown): string {
  if (typeof value !== 'string' || !/^[0-9a-f-]{36}$/i.test(value)) throw new Error('INVALID_SAVE_TOKEN');
  return value;
}
