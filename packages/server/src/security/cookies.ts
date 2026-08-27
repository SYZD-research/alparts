import { timingSafeEqual } from 'node:crypto';
import { config } from '../config/index.js';

export function readCookie(header: string | undefined, name: string): string | null {
  if (!header || header.length > 8192) return null;
  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0 || part.slice(0, separator).trim() !== name) continue;
    const value = part.slice(separator + 1).trim();
    return value.length <= 4096 ? value : null;
  }
  return null;
}

export function sessionCookie(token: string, maxAgeSeconds: number): string {
  const parts = [
    `${config.auth.cookieName}=${token}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (config.auth.secureCookie) parts.push('Secure');
  return parts.join('; ');
}

export function expiredSessionCookie(): string {
  const parts = [
    `${config.auth.cookieName}=`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    'Max-Age=0',
  ];
  if (config.auth.secureCookie) parts.push('Secure');
  return parts.join('; ');
}

export function matchesSecret(candidate: string | undefined, expected: string | null): boolean {
  if (!candidate || !expected) return false;
  const left = Buffer.from(candidate, 'utf8');
  const right = Buffer.from(expected, 'utf8');
  return left.length === right.length && timingSafeEqual(left, right);
}
