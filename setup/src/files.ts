import { randomBytes } from 'node:crypto';
import { chmodSync, chownSync, closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

/** The owner a file is handed to: root, or the user an image runs as. */
export interface Owner { uid: number; gid: number }

export const ROOT: Owner = { uid: 0, gid: 0 };
/** The `node` user of the app image (the CI image test checks uid 1000). */
export const APP_USER: Owner = { uid: 1000, gid: 1000 };
/** The `postgres` user of the PostgreSQL image, which the backup tools image (setup/backup-tools) runs as. */
export const BACKUP_USER: Owner = { uid: 70, gid: 70 };

function canChown(): boolean {
  return process.getuid?.() === 0;
}

/** Sets the mode, and as root the owner, of an existing file or directory. */
export function setPermissions(path: string, mode: number, owner: Owner): void {
  if (canChown()) chownSync(path, owner.uid, owner.gid);
  chmodSync(path, mode);
}

/** Creates the directory (and parents) and enforces its mode and the owner given, refusing a symbolic link. */
export function ensureDirectory(path: string, mode: number, owner?: Owner): void {
  mkdirSync(path, { recursive: true, mode });
  if (lstatSync(path).isSymbolicLink()) throw new Error(`${path} must not be a symbolic link`);
  if (owner) setPermissions(path, mode, owner);
  else chmodSync(path, mode);
}

/**
 * Writes through a temporary file in the same directory and renames it into
 * place, so a reader never sees half a file and an interrupted run leaves the
 * old one. The mode and owner are set before the rename.
 */
export function writeFileAtomic(path: string, content: string | Buffer, mode: number, owner: Owner = ROOT): void {
  const temporary = join(dirname(path), `.${basename(path)}.${randomBytes(6).toString('hex')}.tmp`);
  const descriptor = openSync(temporary, 'wx', 0o600);
  try {
    writeSync(descriptor, typeof content === 'string' ? Buffer.from(content, 'utf8') : content);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  try {
    if (canChown()) chownSync(temporary, owner.uid, owner.gid);
    chmodSync(temporary, mode);
    renameSync(temporary, path);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
}

/** Writes only when the content differs, and reports whether it did. */
export function writeFileIfChanged(path: string, content: string, mode: number, owner: Owner = ROOT): boolean {
  if (existsSync(path) && readFileSync(path, 'utf8') === content) {
    setPermissions(path, mode, owner);
    return false;
  }
  writeFileAtomic(path, content, mode, owner);
  return true;
}

export function readText(path: string): string {
  return readFileSync(path, 'utf8');
}
