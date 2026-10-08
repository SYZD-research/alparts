const KEY_WRITE_CODES = new Set(['KEY_VERSION_STALE', 'KEY_ROTATION_REQUIRED', 'INVALID_KEY_VERSION']);

/**
 * Encrypted writes keep HTTP 400, but the body names a key-state reason a
 * client can act on: catch up and reseal (KEY_VERSION_STALE, with the
 * current version), wait for a group update (KEY_ROTATION_REQUIRED), or stop
 * (INVALID_KEY_VERSION).
 */
export function keyWriteErrorDetails(error: unknown): { code?: string; currentVersion?: number } {
  if (!(error instanceof Error) || !KEY_WRITE_CODES.has(error.message)) return {};
  const currentVersion = (error as { currentVersion?: unknown }).currentVersion;
  return {
    code: error.message,
    ...(typeof currentVersion === 'number' ? { currentVersion } : {}),
  };
}
