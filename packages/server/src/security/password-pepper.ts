import { createHmac, timingSafeEqual } from 'node:crypto';
import { readConfiguredValue } from '../config/source.js';

const BCRYPT_HASH = /^\$2[aby]\$(12|13|14|15)\$[./A-Za-z0-9]{53}$/;
const BCRYPT_SALT = /^\$2[aby]\$(12|13|14|15)\$[./A-Za-z0-9]{22}$/;
const V1_STORED = /^p1:([A-Za-z0-9_-]{39}):([A-Za-z0-9_-]{43})$/;
const V2_STORED = /^p2:([A-Za-z0-9_-]{11}):([A-Za-z0-9_-]{39}):([A-Za-z0-9_-]{43})$/;

function readPepper(name: string, required: boolean): string | undefined {
  const value = readConfiguredValue(name, process.env, process.env.NODE_ENV === 'production');
  if (!value) {
    if (required) throw new Error('PASSWORD_PEPPER_REQUIRED');
    return undefined;
  }
  if (Buffer.byteLength(value) < 32) {
    throw new Error(required ? 'PASSWORD_PEPPER_REQUIRED' : 'PASSWORD_PEPPER_PREVIOUS_INVALID');
  }
  return value;
}

export function passwordPepper(): string {
  return readPepper('PASSWORD_PEPPER', true)!;
}

/**
 * The pepper being retired. It is only used to recognise hashes written before
 * a rotation; every successful login rewraps them under PASSWORD_PEPPER.
 */
export function previousPasswordPepper(): string | undefined {
  const previous = readPepper('PASSWORD_PEPPER_PREVIOUS', false);
  if (previous && previous === passwordPepper()) throw new Error('PASSWORD_PEPPER_PREVIOUS_INVALID');
  return previous;
}

/** Non-secret identifier that selects the pepper for a stored p2 hash. */
function pepperId(pepper: string): string {
  return createHmac('sha256', pepper).update('alparts.password.pepper.id\0').digest('base64url').slice(0, 11);
}

function digestV1(pepper: string, hash: string): string {
  return createHmac('sha256', pepper)
    .update('alparts.password.pepper.v1\0')
    .update(hash)
    .digest('base64url');
}

function digestV2(pepper: string, id: string, hash: string): string {
  return createHmac('sha256', pepper)
    .update('alparts.password.pepper.v2\0')
    .update(id)
    .update('\0')
    .update(hash)
    .digest('base64url');
}

function encodedSalt(hash: string): string {
  return Buffer.from(hash.slice(0, 29)).toString('base64url');
}

/** Post-hash pepper permits protecting existing bcrypt credentials without passwords. */
export function protectPasswordHash(hash: string): string {
  if (!BCRYPT_HASH.test(hash)) throw new Error('UNSUPPORTED_PASSWORD_HASH');
  const pepper = passwordPepper();
  const id = pepperId(pepper);
  return `p2:${id}:${encodedSalt(hash)}:${digestV2(pepper, id, hash)}`;
}

/** True for stored values this runtime can verify (either pepper version). */
export function isProtectedPasswordHash(stored: string): boolean {
  return V1_STORED.test(stored) || V2_STORED.test(stored);
}

export function passwordSalt(stored: string): string {
  const match = V2_STORED.exec(stored) ?? V1_STORED.exec(stored);
  if (!match) throw new Error('UNSUPPORTED_PASSWORD_HASH');
  const salt = Buffer.from(match[match.length - 2], 'base64url').toString();
  if (!BCRYPT_SALT.test(salt)) throw new Error('UNSUPPORTED_PASSWORD_HASH');
  return salt;
}

function equalText(left: string, right: string): boolean {
  return left.length === right.length && timingSafeEqual(Buffer.from(left), Buffer.from(right));
}

export interface PasswordHashMatch {
  valid: boolean;
  /** Set when the credential is valid but not stored under the current pepper. */
  upgradedHash?: string;
}

export function comparePasswordHash(stored: string, bcryptHash: string): PasswordHashMatch {
  if (!BCRYPT_HASH.test(bcryptHash)) throw new Error('UNSUPPORTED_PASSWORD_HASH');
  const current = passwordPepper();
  const previous = previousPasswordPepper();
  const salt = encodedSalt(bcryptHash);
  const v2 = V2_STORED.exec(stored);
  if (v2) {
    const [, id, storedSalt, digest] = v2;
    const pepper = id === pepperId(current) ? current : previous && id === pepperId(previous) ? previous : undefined;
    // Always compute one HMAC so an unknown pepper id costs the same as a miss.
    const candidate = digestV2(pepper ?? current, id, bcryptHash);
    const valid = pepper !== undefined && equalText(storedSalt, salt) && equalText(digest, candidate);
    return valid && pepper !== current ? { valid, upgradedHash: protectPasswordHash(bcryptHash) } : { valid };
  }
  const v1 = V1_STORED.exec(stored);
  if (!v1) throw new Error('UNSUPPORTED_PASSWORD_HASH');
  const [, storedSalt, digest] = v1;
  const saltMatches = equalText(storedSalt, salt);
  const currentMatch = equalText(digest, digestV1(current, bcryptHash));
  const previousMatch = previous !== undefined && equalText(digest, digestV1(previous, bcryptHash));
  const valid = saltMatches && (currentMatch || previousMatch);
  return valid ? { valid, upgradedHash: protectPasswordHash(bcryptHash) } : { valid };
}

export function matchesPasswordHash(stored: string, bcryptHash: string): boolean {
  return comparePasswordHash(stored, bcryptHash).valid;
}
