import assert from 'node:assert/strict';
import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';
import type { NextFunction, Request, Response } from 'express';

// Never a real database: every session lookup fails as it would during an outage.
process.env.DATABASE_URL = 'postgres://test:test@127.0.0.1:1/alparts_test';
process.env.S3_ACCESS_KEY ||= 'test-access-key';
process.env.S3_SECRET_KEY ||= 'test-secret-key';
process.env.AUDIT_INTEGRITY_KEY ||= 'test-audit-integrity-key-at-least-32-bytes';
process.env.JWT_SECRET ||= 'test-jwt-secret-key-at-least-32-bytes';
process.env.PASSWORD_PEPPER ||= 'auth-middleware-test-only-password-pepper';

let server: Server;
let url: string;
let validToken: string;

before(async () => {
  const { default: express } = await import('express');
  const { default: jwt } = await import('jsonwebtoken');
  const { config } = await import('../config/index.js');
  const { authMiddleware } = await import('./auth.js');
  validToken = jwt.sign({ sub: 'user-id', sid: 'session-id' }, config.jwt.secret, {
    algorithm: 'HS256', issuer: config.jwt.issuer, audience: config.jwt.audience, expiresIn: 60,
  });
  const app = express();
  app.get('/private', authMiddleware, (_req, res) => {
    res.json({ reached: true });
  });
  app.use((_error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    res.status(500).json({ error: 'LOOKUP_FAILED' });
  });
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/private`;
});

after(() => {
  server.closeAllConnections();
  server.close();
});

async function call(token?: string) {
  const response = await fetch(url, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
  return { status: response.status, body: await response.json() as { error?: string } };
}

describe('authentication middleware', () => {
  it('answers 401 when no valid token is presented', async () => {
    assert.deepEqual((await call()).status, 401);
    assert.deepEqual((await call('not-a-token')).status, 401);
  });

  it('reports a failed session lookup as an error, not as a missing session', async () => {
    assert.deepEqual(await call(validToken), { status: 500, body: { error: 'LOOKUP_FAILED' } });
  });
});
