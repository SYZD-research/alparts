import { createHmac, timingSafeEqual } from 'node:crypto';
import { readConfiguredValue } from '../config/source.js';

export function passwordPepper(): string {
  const value = readConfiguredValue(
    'PASSWORD_PEPPER',
    process.env,
    process.env.NODE_ENV === 'production',
  );
  if (!value || Buffer.byteLength(value) < 32) throw new Error('PASSWORD_PEPPER_REQUIRED');
  return value;
}

function digest(hash: string): string {
  return createHmac('sha256', passwordPepper())
    .update('alparts.password.pepper.v1\0')
    .update(hash)
    .digest('base64url');
}

/** Post-hash pepper permits protecting existing bcrypt credentials without passwords. */
export function protectPasswordHash(hash: string): string {
  if (!/^\$2[aby]\$(12|13|14|15)\$[./A-Za-z0-9]{53}$/.test(hash))
    throw new Error('UNSUPPORTED_PASSWORD_HASH');
  return `p1:${Buffer.from(hash.slice(0, 29)).toString('base64url')}:${digest(hash)}`;
}

export function passwordSalt(stored: string): string {
  if (!/^p1:[A-Za-z0-9_-]{39}:[A-Za-z0-9_-]{43}$/.test(stored))
    throw new Error('UNSUPPORTED_PASSWORD_HASH');
  const salt = Buffer.from(stored.split(':')[1], 'base64url').toString();
  if (!/^\$2[aby]\$(12|13|14|15)\$[./A-Za-z0-9]{22}$/.test(salt))
    throw new Error('UNSUPPORTED_PASSWORD_HASH');
  return salt;
}

export function matchesPasswordHash(stored: string, bcryptHash: string): boolean {
  const candidate = protectPasswordHash(bcryptHash);
  return (
    stored.length === candidate.length &&
    timingSafeEqual(Buffer.from(stored), Buffer.from(candidate))
  );
}
