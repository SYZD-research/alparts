import { closeSync, fstatSync, openSync, readFileSync } from 'node:fs';

/** Read one bounded direct or file-backed value without logging its contents. */
export function readConfiguredValue(
  name: string,
  environment: NodeJS.ProcessEnv,
  isProduction: boolean,
): string | undefined {
  const direct = environment[name]?.trim();
  const file = environment[`${name}_FILE`]?.trim();
  if (direct && file) throw new Error(`Configure only one of ${name} or ${name}_FILE`);
  if (!file) {
    if (direct && Buffer.byteLength(direct, 'utf8') > 64 * 1024) throw new Error(`${name} is too large`);
    return direct || undefined;
  }
  if (Buffer.byteLength(file, 'utf8') > 4_096) throw new Error(`${name}_FILE path is too long`);
  // Check and read the same open file, so it cannot be swapped in between.
  const descriptor = openSync(file, 'r');
  let loaded: string;
  try {
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.size > 64 * 1024) {
      throw new Error(`${name}_FILE must be a regular file no larger than 64 KiB`);
    }
    if (isProduction && (metadata.mode & 0o022) !== 0) {
      throw new Error(`${name}_FILE must not be writable by group or other in production`);
    }
    loaded = readFileSync(descriptor, { encoding: 'utf8' }).trim();
  } finally {
    closeSync(descriptor);
  }
  if (Buffer.byteLength(loaded, 'utf8') > 64 * 1024) throw new Error(`${name}_FILE is too large`);
  return loaded || undefined;
}
