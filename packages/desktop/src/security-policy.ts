import { createHash } from 'node:crypto';
import path from 'node:path';

export const APP_SCHEME = 'alparts-app';
export const APP_HOST = 'bundle';
export const APP_URL = `${APP_SCHEME}://${APP_HOST}/`;
export const DEFAULT_IDLE_LOCK_MINUTES = 5;
export const IDLE_LOCK_MINUTES = [1, 5, 15, 30, 60] as const;

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const SECRET_NAME = new RegExp(`^(?:device|local|channel):${UUID}(?::${UUID}){0,2}(?::[1-9]\\d{0,6})?$`, 'i');

export function normalizeServerUrl(value: unknown): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > 2048) {
    throw new Error('INVALID_SERVER_URL');
  }
  let parsed: URL;
  try {
    parsed = new URL(value.trim());
  } catch {
    throw new Error('INVALID_SERVER_URL');
  }
  if (
    !['http:', 'https:'].includes(parsed.protocol)
    || parsed.username
    || parsed.password
    || parsed.search
    || parsed.hash
    || (parsed.pathname !== '/' && parsed.pathname !== '')
  ) {
    throw new Error('INVALID_SERVER_URL');
  }
  if (parsed.protocol !== 'https:' && !LOOPBACK_HOSTS.has(parsed.hostname)) {
    throw new Error('INSECURE_SERVER_URL');
  }
  return parsed.origin;
}

export function normalizeIdleLockMinutes(value: unknown): number {
  if (typeof value !== 'number' || !IDLE_LOCK_MINUTES.includes(value as typeof IDLE_LOCK_MINUTES[number])) {
    throw new Error('INVALID_IDLE_LOCK');
  }
  return value;
}

export function isAllowedExternalUrl(value: unknown): value is string {
  if (typeof value !== 'string' || value.length < 1 || value.length > 2048 || /[\u0000-\u001f\u007f]/.test(value)) {
    return false;
  }
  try {
    const parsed = new URL(value);
    return ['http:', 'https:'].includes(parsed.protocol) && !parsed.username && !parsed.password;
  } catch {
    return false;
  }
}

export function isTrustedRendererUrl(value: string, serverUrl: string | null, developmentUrl?: string): boolean {
  try {
    const parsed = new URL(value);
    if (parsed.username || parsed.password) return false;
    if (parsed.protocol === `${APP_SCHEME}:` && parsed.hostname === APP_HOST) return true;
    if (developmentUrl && parsed.origin === new URL(developmentUrl).origin) return true;
    return Boolean(
      serverUrl
      && parsed.origin === new URL(serverUrl).origin
      && !isBackendPath(parsed.pathname),
    );
  } catch {
    return false;
  }
}

export function isBackendPath(pathname: string): boolean {
  return pathname === '/api'
    || pathname.startsWith('/api/')
    || pathname === '/socket.io'
    || pathname.startsWith('/socket.io/')
    || pathname === '/health'
    || pathname.startsWith('/health/');
}

/** Backend routes are data transports, never executable or top-level resources. */
export function isAllowedBackendRequestDestination(
  destination: unknown,
  fetchDestinationHeader: unknown,
): boolean {
  const requestDestination = typeof destination === 'string' ? destination : '';
  const headerDestination = typeof fetchDestinationHeader === 'string' ? fetchDestinationHeader : '';
  return requestDestination === '' && (headerDestination === '' || headerDestination === 'empty');
}

/**
 * Electron's protocol forwarding does not preserve Chromium's generated
 * Origin header. Re-attach the exact configured origin after the destination
 * and request type have passed the desktop boundary checks.
 */
export function withBackendRequestOrigin(request: Request, serverUrl: string): Request {
  const headers = new Headers(request.headers);
  headers.set('Origin', normalizeServerUrl(serverUrl));
  return new Request(request, { headers });
}

export function assertSecretName(value: unknown): string {
  if (typeof value !== 'string' || value.length > 180 || !SECRET_NAME.test(value)) {
    throw new Error('INVALID_SECRET_NAME');
  }
  const parts = value.split(':');
  if (parts[0] === 'device' && parts.length === 2) return value;
  if (parts[0] === 'local' && parts.length === 3) return value;
  if (parts[0] === 'channel' && parts.length === 5) return value;
  throw new Error('INVALID_SECRET_NAME');
}

export function assertSecretValue(value: unknown): string {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > 64 * 1024) {
    throw new Error('INVALID_SECRET_VALUE');
  }
  return value;
}

export function resolveBundledPath(root: string, pathname: string): string | null {
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null;
  }
  if (!decoded.startsWith('/') || decoded.includes('\\') || /[\u0000-\u001f\u007f]/.test(decoded)) return null;
  const candidate = path.resolve(root, `.${decoded}`);
  const relative = path.relative(root, candidate);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) return null;
  return candidate;
}

export function deploymentNamespace(serverUrl: string): string {
  return createHash('sha256').update(normalizeServerUrl(serverUrl), 'utf8').digest('base64url');
}
