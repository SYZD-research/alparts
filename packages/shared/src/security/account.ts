export const DIRECTORY_GENESIS = '0'.repeat(64);
export interface DirectoryHead {
  userId: string;
  sequence: number;
  hash: string;
}
export interface DirectoryEvent {
  kind:
    | 'legacy'
    | 'bootstrap'
    | 'register'
    | 'approve'
    | 'revoke'
    | 'recovery'
    | 'recovery-config'
    | 'recovery-disable';
  deviceId: string;
  identityKey: string;
  actorDeviceId: string;
  signature: string;
  challenge?: string;
  recoveryKey?: string;
}
export interface DirectoryEntry extends DirectoryHead {
  previousHash: string;
  event: DirectoryEvent;
}
export function serializeDeviceDecision(
  head: DirectoryHead,
  event: Pick<DirectoryEvent, 'kind' | 'deviceId' | 'identityKey' | 'actorDeviceId'>,
): string {
  return JSON.stringify([
    'alparts-device-decision',
    1,
    head.userId,
    head.sequence,
    head.hash,
    event.kind,
    event.deviceId,
    event.identityKey,
    event.actorDeviceId,
  ]);
}
export function serializeDirectoryEntry(entry: Omit<DirectoryEntry, 'hash'>): string {
  const e = entry.event;
  return JSON.stringify([
    'alparts-directory',
    1,
    entry.userId,
    entry.sequence,
    entry.previousHash,
    e.kind,
    e.deviceId,
    e.identityKey,
    e.actorDeviceId,
    e.signature,
    e.challenge ?? null,
    e.recoveryKey ?? null,
  ]);
}
export function canonicalActionBody(value: unknown): string {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalActionBody).join(',')}]`;
  return `{${Object.keys(value)
    .sort()
    .map(
      (key) =>
        `${JSON.stringify(key)}:${canonicalActionBody((value as Record<string, unknown>)[key])}`,
    )
    .join(',')}}`;
}
/** Drops trailing slashes. A loop, unlike /\/+$/, stays linear on any input. */
function withoutTrailingSlashes(path: string): string {
  let end = path.length;
  while (end > 0 && path[end - 1] === '/') end -= 1;
  return path.slice(0, end);
}

export function isSensitiveAction(method: string, path: string): boolean {
  // Express routes accept case variations and a trailing slash. Classify the
  // same route here; the grant still binds the exact original request path.
  method = method.toUpperCase();
  path = withoutTrailingSlashes(path.toLowerCase());
  if (['GET', 'HEAD', 'OPTIONS'].includes(method)) return false;
  return (
    (path.startsWith('/api/devices/') && (method === 'DELETE' || path.endsWith('/approve'))) ||
    (path.startsWith('/api/auth/sessions') && method === 'DELETE') ||
    ((path === '/api/auth/password' || path === '/api/auth/password-login') && method === 'PUT') ||
    path === '/api/auth/passkeys/register/options' ||
    (path.startsWith('/api/auth/passkeys/') && method === 'DELETE') ||
    (path === '/api/recovery/configure' || path === '/api/recovery/access') ||
    (path === '/api/recovery' && method === 'DELETE') ||
    path.endsWith('/mls/epochs/fresh-start') ||
    path.endsWith('/mls/group/fresh-start') ||
    (/^\/api\/(workspaces|channels|categories)\//.test(path) &&
      (method === 'DELETE' ||
        /\/(roles|members|invitations|permission-overrides)(\/|$)/.test(path)) &&
      !path.endsWith('/preview'))
  );
}

/**
 * Like isSensitiveAction, but also for requests that are sensitive because of
 * what they change. Making a private channel public (or moving a channel to
 * a category with different permissions) lets new members read what follows,
 * so it needs the same proof as adding members. The field's presence decides,
 * so a client sends it only when it changes.
 */
export function isSensitiveRequest(method: string, path: string, body: unknown): boolean {
  if (isSensitiveAction(method, path)) return true;
  const normalizedPath = withoutTrailingSlashes(path.toLowerCase());
  if (method.toUpperCase() !== 'PUT' || !/^\/api\/channels\/[^/]+$/.test(normalizedPath)) return false;
  return body !== null && typeof body === 'object' && !Array.isArray(body)
    && ['isPrivate', 'categoryId'].some((field) => Object.prototype.hasOwnProperty.call(body, field));
}
