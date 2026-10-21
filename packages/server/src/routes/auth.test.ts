import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it, mock } from 'node:test';
import type { NextFunction, Request, Response } from 'express';

// Never a real database: an attempt let through every limit fails at the
// account lookup, which the error handler below reports.
process.env.DATABASE_URL = 'postgres://test:test@127.0.0.1:1/alparts_test';
process.env.S3_ACCESS_KEY ||= 'test-access-key';
process.env.S3_SECRET_KEY ||= 'test-secret-key';
process.env.AUDIT_INTEGRITY_KEY ||= 'test-audit-integrity-key-at-least-32-bytes';
process.env.JWT_SECRET ||= 'test-jwt-secret-key-at-least-32-bytes';
// Challenges are minted with this pepper at this time, so their work could be
// solved once ahead: each number is the first nonce that solves its challenge.
process.env.PASSWORD_PEPPER = 'login-limit-test-only-password-pepper';
const now = Date.UTC(2026, 9, 1);
const ownerWork = 95445;
const guessWork = [
  360441, 1583907, 7526184, 9180014, 1233593, 3994136, 3440687, 2244571, 19092615, 2740567,
  4067606, 1770027, 1321858, 3307784, 952802, 3024361, 1138600, 806343, 9875235, 1663976,
  5536280, 1008037, 1651854, 2200923, 2101310, 14452938, 1285670, 1447678, 1927331, 503420,
  5400666, 28941338, 8078872, 1131130, 2070705, 3301140, 3181914, 7244736, 4141616, 1371789,
  4195319, 483821, 821088, 2613393, 12242205, 4631572, 815143, 10862947, 2144439,
];
const password = 'correct horse battery staple';

let server: Server;
let url: string;
let credentialRateLimitKey: (req: Request) => string;

before(async () => {
  mock.method(Date, 'now', () => now);
  const { default: express } = await import('express');
  const { default: authRoutes } = await import('./auth.js');
  ({ credentialRateLimitKey } = await import('../middleware/rate-limit.js'));
  const app = express();
  // The forwarded address names the source, as behind a trusted proxy.
  app.set('trust proxy', true);
  app.use(express.json());
  app.use('/api/auth', authRoutes);
  app.use((_error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    res.status(503).json({ error: 'PASSED_LIMITS' });
  });
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/auth/login`;
});

after(() => {
  server.closeAllConnections();
  server.close();
  mock.restoreAll();
});

/** A challenge the server could have issued to this source for this account, with its solution. */
function solved(source: string, email: string, id: string, work: number): string {
  const binding = credentialRateLimitKey({ ip: source, socket: {}, body: { email } } as any);
  const payload = Buffer.from(JSON.stringify({ binding, expires: now + 120_000, nonce: id })).toString('base64url');
  const signature = createHmac('sha256', process.env.PASSWORD_PEPPER!)
    .update('alparts.login.challenge.v1\0')
    .update(payload)
    .digest('base64url');
  return `${payload}.${signature}.${work}`;
}

async function login(source: string, body: object, proof?: string) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Forwarded-For': source,
      ...(proof ? { 'X-Alparts-Login-Proof': proof } : {}),
    },
    body: JSON.stringify(body),
  });
  const { error } = await response.json() as { error?: string };
  return { status: response.status, error };
}

describe('password login limits (GHSA-8c53-h6x7-82gm)', () => {
  it('never lets requests without solved work lock the owner out', async () => {
    const email = 'owner-a@example.test';
    const owner = '203.0.113.9';
    // The address alone, from one source, far past both account limits. Once
    // the account's free attempts are used, each request is asked for work.
    const statuses: number[] = [];
    for (let index = 0; index < 90; index += 1) statuses.push((await login('198.51.100.7', { email })).status);
    assert.deepEqual(statuses.slice(12), Array.from({ length: 78 }, () => 428));
    // Being asked for work does not use up the owner's own attempts either.
    for (let index = 0; index < 10; index += 1) {
      assert.equal((await login(owner, { email, password })).error, 'LOGIN_CHALLENGE_REQUIRED');
    }
    const admitted = await login(owner, { email, password }, solved(owner, email, 'owner', ownerWork));
    assert.equal(admitted.error, 'PASSED_LIMITS');
  });

  it('caps guesses backed by solved work across sources', async () => {
    const email = 'owner-b@example.test';
    // No password is checked here, so each guess is malformed instead: like a
    // wrong password, it is refused as a client error after every limit.
    for (let index = 0; index < 60; index += 1) {
      const source = `198.51.100.${20 + (index % 10)}`;
      const proof = index < 12 ? undefined : solved(source, email, `guess-${index}`, guessWork[index - 12]!);
      assert.equal((await login(source, { email }, proof)).status, 400);
    }
    // The next guess is refused, even from a new source with solved work.
    const source = '192.0.2.60';
    const refused = await login(source, { email, password }, solved(source, email, 'guess-60', guessWork[48]!));
    assert.deepEqual(refused, { status: 429, error: 'RATE_LIMITED' });
  });
});
