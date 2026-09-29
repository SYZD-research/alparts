import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync, randomUUID } from 'node:crypto';
import { describe, it } from 'node:test';
import jwt from 'jsonwebtoken';

process.env.NODE_ENV = 'test';
process.env.DATABASE_URL ||= 'postgresql://alparts:test@127.0.0.1:1/alparts';
process.env.MINIO_ACCESS_KEY ||= 'test-access-key';
process.env.MINIO_SECRET_KEY ||= 'test-secret-key';
process.env.JWT_SECRET = 'session-test-only-jwt-secret-at-least-32-bytes';
process.env.PASSWORD_PEPPER ||= 'test-only-password-pepper-at-least-32-bytes';
process.env.AUDIT_INTEGRITY_KEY ||= 'test-audit-integrity-key-at-least-32-bytes';

const { verifySessionToken } = await import('./session.js');
const { config } = await import('../config/index.js');

const claims = () => ({ sid: randomUUID() });
const options = (extra: jwt.SignOptions = {}): jwt.SignOptions => ({
  subject: randomUUID(),
  issuer: config.jwt.issuer,
  audience: config.jwt.audience,
  expiresIn: 300,
  ...extra,
});
const base64url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

describe('session token verification', () => {
  // Every case is rejected by signature/claim checks before any database lookup.
  it('rejects algorithm confusion and unsigned tokens', async () => {
    const now = Math.floor(Date.now() / 1000);
    const payload = { sid: randomUUID(), sub: randomUUID(), iss: config.jwt.issuer, aud: config.jwt.audience, iat: now, exp: now + 300 };
    const unsigned = `${base64url({ alg: 'none', typ: 'JWT' })}.${base64url(payload)}.`;
    const hs512 = jwt.sign(claims(), config.jwt.secret, { ...options(), algorithm: 'HS512' });
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rs256 = jwt.sign(claims(), privateKey, { ...options(), algorithm: 'RS256' });
    // RS256 header signed with the public key as an HMAC secret (classic confusion).
    const header = base64url({ alg: 'RS256', typ: 'JWT' });
    const body = base64url(payload);
    const confused = `${header}.${body}.${createHmac('sha256', publicKey.export({ type: 'spki', format: 'pem' })).update(`${header}.${body}`).digest('base64url')}`;
    for (const token of [unsigned, hs512, rs256, confused]) {
      assert.equal(await verifySessionToken(token), null);
    }
  });

  it('rejects wrong issuer, audience, secret, expiry and oversize tokens', async () => {
    const tokens = [
      jwt.sign(claims(), config.jwt.secret, { ...options({ issuer: 'someone-else' }), algorithm: 'HS256' }),
      jwt.sign(claims(), config.jwt.secret, { ...options({ audience: 'another-client' }), algorithm: 'HS256' }),
      jwt.sign(claims(), 'a-different-secret-that-is-at-least-32-bytes', { ...options(), algorithm: 'HS256' }),
      jwt.sign({ ...claims(), exp: Math.floor(Date.now() / 1000) - 10 }, config.jwt.secret, {
        subject: randomUUID(), issuer: config.jwt.issuer, audience: config.jwt.audience, algorithm: 'HS256',
      }),
      jwt.sign({}, config.jwt.secret, { ...options(), algorithm: 'HS256' }),
      'x'.repeat(4097),
    ];
    for (const token of tokens) assert.equal(await verifySessionToken(token), null);
  });
});
