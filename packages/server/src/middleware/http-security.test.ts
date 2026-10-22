import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { EventEmitter, once } from 'node:events';
import type { Server } from 'node:http';
import { connect, type AddressInfo } from 'node:net';
import { after, afterEach, before, describe, it } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import type { RequestHandler } from 'express';
import jwt from 'jsonwebtoken';

process.env.DATABASE_URL ||= 'postgres://test:test@127.0.0.1:5432/alparts_test';
process.env.S3_ACCESS_KEY ||= 'test-access-key';
process.env.S3_SECRET_KEY ||= 'test-secret-key';
process.env.AUDIT_INTEGRITY_KEY ||= 'test-audit-integrity-key-at-least-32-bytes';
process.env.PASSWORD_PEPPER ||= 'test-only-password-pepper-at-least-32-bytes';
process.env.JWT_SECRET ||= 'test-jwt-secret-key-at-least-32-bytes';

interface MockResponse {
  statusCode: number;
  body: unknown;
  headers: Record<string, string>;
  status(code: number): MockResponse;
  json(value: unknown): MockResponse;
  setHeader(name: string, value: string): void;
}

function response(): MockResponse {
  return {
    statusCode: 200,
    body: undefined,
    headers: {},
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(value) {
      this.body = value;
      return this;
    },
    setHeader(name, value) {
      this.headers[name.toLowerCase()] = String(value);
    },
  };
}

describe('HTTP browser boundary', () => {
  it('requires an allowed Origin for cookie-authenticated mutations', async () => {
    const { config } = await import('../config/index.js');
    const { enforceBrowserOrigin } = await import('./origin.js');
    const cookie = `${config.auth.cookieName}=session-token`;

    for (const headers of [
      { cookie },
      { cookie, origin: 'https://attacker.example' },
    ]) {
      const res = response();
      let passed = false;
      enforceBrowserOrigin({ method: 'POST', headers } as any, res as any, () => { passed = true; });
      assert.equal(passed, false);
      assert.equal(res.statusCode, 403);
    }

    const allowed = response();
    let allowedPassed = false;
    enforceBrowserOrigin({
      method: 'POST',
      headers: { cookie, origin: config.cors.origins[0], 'sec-fetch-site': 'same-site' },
    } as any, allowed as any, () => { allowedPassed = true; });
    assert.equal(allowedPassed, true);
    assert.equal(allowed.statusCode, 200);
  });

  it('allows non-browser clients without cookies but rejects cross-site browser signals', async () => {
    const { enforceBrowserOrigin } = await import('./origin.js');
    const apiResponse = response();
    let apiPassed = false;
    enforceBrowserOrigin({ method: 'POST', headers: {} } as any, apiResponse as any, () => { apiPassed = true; });
    assert.equal(apiPassed, true);

    const crossSiteResponse = response();
    let crossSitePassed = false;
    enforceBrowserOrigin({
      method: 'POST',
      headers: { origin: 'http://localhost:5173', 'sec-fetch-site': 'cross-site' },
    } as any, crossSiteResponse as any, () => { crossSitePassed = true; });
    assert.equal(crossSitePassed, false);
    assert.equal(crossSiteResponse.statusCode, 403);
  });
});

describe('in-process rate limiting', () => {
  it('returns standard limit headers and rejects only after the configured count', async () => {
    const { rateLimit } = await import('./rate-limit.js');
    const middleware = rateLimit({ windowMs: 60_000, max: 2 });
    const request = { ip: '192.0.2.1', socket: { remoteAddress: '192.0.2.1' } } as any;

    for (const expectedStatus of [200, 200, 429]) {
      const res = response();
      let passed = false;
      middleware(request, res as any, () => { passed = true; });
      assert.equal(res.statusCode, expectedStatus);
      assert.equal(passed, expectedStatus === 200);
      assert.equal(res.headers['ratelimit-limit'], '2');
    }
  });

  it('can spend a budget only on refused requests', async () => {
    const { EventEmitter } = await import('node:events');
    const { rateLimit } = await import('./rate-limit.js');
    const middleware = rateLimit({ windowMs: 60_000, max: 2, key: () => 'user-a', failuresOnly: true });
    const attempt = (finalStatus: number) => {
      const res = Object.assign(new EventEmitter(), response());
      let passed = false;
      middleware({} as any, res as any, () => { passed = true; });
      if (passed) {
        res.statusCode = finalStatus;
        res.emit('finish');
      }
      return { passed, status: res.statusCode };
    };

    for (let index = 0; index < 5; index += 1) assert.equal(attempt(200).passed, true);
    assert.equal(attempt(403).passed, true);
    assert.equal(attempt(200).passed, true);
    assert.equal(attempt(403).passed, true);
    assert.deepEqual(attempt(200), { passed: false, status: 429 });
  });

  it('normalizes and hashes credential identifiers instead of retaining email text', async () => {
    const { credentialAccountRateLimitKey, credentialRateLimitKey } = await import('./rate-limit.js');
    const first = credentialRateLimitKey({
      ip: '192.0.2.1',
      socket: { remoteAddress: '192.0.2.1' },
      body: { email: ' Alice@Example.TEST ' },
    } as any);
    const second = credentialRateLimitKey({
      ip: '192.0.2.1',
      socket: { remoteAddress: '192.0.2.1' },
      body: { email: 'alice@example.test' },
    } as any);
    assert.equal(first, second);
    assert.equal(first.includes('alice'), false);
    assert.match(first, /^192\.0\.2\.1:[a-f0-9]{24}$/);
    const accountOnly = credentialAccountRateLimitKey({ body: { email: ' Alice@Example.TEST ' } } as any);
    assert.equal(accountOnly, first.split(':')[1]);
    assert.match(accountOnly, /^[a-f0-9]{24}$/);
  });
});

const MiB = 1024 * 1024;

interface JsonRequestOptions {
  bytes: number;
  ip?: string;
  cookie?: string;
  headers?: Record<string, string>;
  method?: string;
}

/** A request as body admission sees it: the headers are in, no body has arrived. */
function jsonRequest(options: JsonRequestOptions) {
  const ip = options.ip ?? '198.51.100.1';
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'content-length': String(options.bytes),
    ...(options.cookie ? { cookie: options.cookie } : {}),
    ...options.headers,
  };
  const req = Object.assign(new EventEmitter(), {
    method: options.method ?? 'POST',
    headers,
    ip,
    socket: { remoteAddress: ip },
    complete: false,
    is: (type: string) => headers['content-type'] === type,
  });
  const res = Object.assign(new EventEmitter(), response(), { headersSent: false });
  return { req, res };
}

describe('request body admission', () => {
  const open: Array<() => void> = [];
  afterEach(() => {
    for (const end of open.splice(0)) end();
  });

  async function fixture() {
    const { config } = await import('../config/index.js');
    const admission = await import('./body-admission.js');
    const { MLS_EPOCH_BODY_BYTES } = await import('../routes/mls-schema.js');
    const token = (userId = randomUUID(), options: jwt.SignOptions = {}) => jwt.sign({ sid: randomUUID() }, config.jwt.secret, {
      algorithm: 'HS256',
      subject: userId,
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
      expiresIn: 300,
      ...options,
    });
    const cookie = (value: string) => `${config.auth.cookieName}=${value}`;
    /** Run a request through a handler. An admitted request keeps its share until it ends. */
    const admit = (handler: RequestHandler, options: JsonRequestOptions) => {
      const { req, res } = jsonRequest(options);
      let admitted = false;
      handler(req as any, res as any, () => { admitted = true; });
      const end = () => res.emit('close');
      if (admitted) open.push(end);
      return { admitted, req, res, end };
    };
    return { config, ...admission, groupBytes: MLS_EPOCH_BODY_BYTES, token, cookie, admit };
  }

  it('reserves bounded bytes per user and globally with idempotent release', async () => {
    const { InFlightBodyBudget } = await import('./body-admission.js');
    const budget = new InFlightBodyBudget({
      maxBytesTotal: 10,
      maxBytesPerUser: 6,
      maxRequestsTotal: 2,
      maxRequestsPerUser: 1,
    });
    const first = budget.acquire('user-a', 6);
    assert.equal(typeof first, 'function');
    assert.equal(budget.acquire('user-a', 1), null);
    const second = budget.acquire('user-b', 4);
    assert.equal(typeof second, 'function');
    assert.equal(budget.acquire('user-c', 1), null);
    first?.();
    first?.();
    const replacement = budget.acquire('user-c', 5);
    assert.equal(typeof replacement, 'function');
    second?.();
    replacement?.();
  });

  it('lets a body take a short start plus the time its size needs at a modest rate', async () => {
    const { bodyDeadlineMs } = await fixture();
    assert.equal(bodyDeadlineMs(0), 10_000);
    assert.equal(bodyDeadlineMs(32 * 1024), 11_000);
    assert.equal(bodyDeadlineMs(512 * 1024), 26_000);
    assert.equal(bodyDeadlineMs(2 * MiB), 74_000);
  });

  it('answers a body that stalls with 408 and gives its reservation back at once', async (t) => {
    const { reserveJsonBody, bodyDeadlineMs, groupBytes, token, cookie, admit } = await fixture();
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const group = reserveJsonBody(groupBytes);
    const signedIn = cookie(token());
    const stalled = admit(group, { bytes: groupBytes, cookie: signedIn });
    assert.equal(stalled.admitted, true);
    // It holds the user's whole allowance, so no second body of that size fits meanwhile.
    assert.equal(admit(group, { bytes: groupBytes, cookie: signedIn }).res.statusCode, 503);

    t.mock.timers.tick(bodyDeadlineMs(groupBytes) - 1);
    assert.equal(stalled.res.body, undefined);
    t.mock.timers.tick(1);
    assert.equal(stalled.res.statusCode, 408);
    assert.deepEqual(stalled.res.body, {
      error: 'REQUEST_TIMEOUT',
      message: 'Request body was not received in time',
      statusCode: 408,
    });
    assert.equal(stalled.res.headers.connection, 'close');
    // The connection has not even closed yet, and the share is already free.
    assert.equal(admit(group, { bytes: groupBytes, cookie: signedIn }).admitted, true);
  });

  it('stops waiting for a body that has arrived, however long the request then takes', async (t) => {
    const { reserveJsonBody, bodyDeadlineMs, groupBytes, token, cookie, admit } = await fixture();
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const group = reserveJsonBody(groupBytes);
    const signedIn = cookie(token());
    const arrived = admit(group, { bytes: groupBytes, cookie: signedIn });
    arrived.req.emit('end');
    // Received completely, though the end event has not fired yet.
    const complete = admit(group, { bytes: 1024, cookie: cookie(token()) });
    complete.req.complete = true;

    t.mock.timers.tick(10 * bodyDeadlineMs(groupBytes));
    assert.equal(arrived.res.body, undefined);
    assert.equal(complete.res.body, undefined);
    // The reservation stays until the request ends.
    assert.equal(admit(group, { bytes: groupBytes, cookie: signedIn }).res.statusCode, 503);
    arrived.res.emit('finish');
    assert.equal(admit(group, { bytes: groupBytes, cookie: signedIn }).admitted, true);
  });

  it('does not let unauthenticated slow uploads use up the capacity signed-in users need', async () => {
    const { reserveJsonBody, DEFAULT_JSON_BODY_BYTES, groupBytes, token, cookie, admit } = await fixture();
    const group = reserveJsonBody(groupBytes);
    const normal = reserveJsonBody(DEFAULT_JSON_BODY_BYTES);
    const attackers = ['198.51.100.1', '198.51.100.2', '198.51.100.3', '198.51.100.4'];

    // The reported attack: headers for a 2 MiB group commit from four addresses, then nothing.
    // Without a session the group allowance is not on offer, so nothing is held.
    for (const ip of attackers) {
      const attack = admit(group, { bytes: groupBytes, ip });
      assert.deepEqual([attack.admitted, attack.res.statusCode], [false, 413]);
    }
    const login = admit(normal, { bytes: 300, ip: '203.0.113.7' });
    assert.equal(login.admitted, true);
    login.end();

    // The most an unauthenticated request may send, held by four addresses, fills their own share.
    const held = attackers.map((ip) => admit(normal, { bytes: DEFAULT_JSON_BODY_BYTES, ip }));
    assert.deepEqual(held.map((request) => request.admitted), [true, true, true, true]);
    assert.equal(admit(normal, { bytes: 300, ip: '203.0.113.7' }).res.statusCode, 503);
    // Signed-in requests still pass, up to the group allowance.
    assert.equal(admit(group, { bytes: groupBytes, cookie: cookie(token()) }).admitted, true);
    assert.equal(admit(normal, { bytes: 300, cookie: cookie(token()) }).admitted, true);
  });

  it('gives the group allowance only to a request whose session token passes the checks that need no database', async () => {
    const { config, reserveJsonBody, groupBytes, token, cookie, admit } = await fixture();
    const group = reserveJsonBody(groupBytes);
    const claims = () => ({ subject: randomUUID(), issuer: config.jwt.issuer, audience: config.jwt.audience });
    const unusable = [
      jwt.sign({ sid: randomUUID() }, 'a-different-secret-that-is-at-least-32-bytes', { ...claims(), expiresIn: 300 }),
      token(randomUUID(), { issuer: 'someone-else' }),
      token(randomUUID(), { audience: 'another-client' }),
      jwt.sign({ sid: randomUUID(), exp: Math.floor(Date.now() / 1000) - 10 }, config.jwt.secret, claims()),
      jwt.sign({}, config.jwt.secret, { ...claims(), expiresIn: 300 }),
      jwt.sign({ sid: randomUUID() }, config.jwt.secret, { ...claims(), expiresIn: 300, algorithm: 'HS512' }),
      'not-a-token',
      'x'.repeat(4097),
    ];
    for (const value of unusable) {
      const attempt = admit(group, { bytes: groupBytes, cookie: cookie(value) });
      assert.deepEqual([attempt.admitted, attempt.res.statusCode], [false, 413], value.slice(0, 24));
    }
    // A cookie of another name, a bearer header with a bad token, and nothing at all are no session either.
    for (const options of [
      { cookie: `other_session=${token()}` },
      { headers: { authorization: 'Bearer not-a-token' } },
      {},
    ]) assert.equal(admit(group, { bytes: groupBytes, ...options }).res.statusCode, 413);
    // A usable token, from the cookie or from a bearer header, is.
    assert.equal(admit(group, { bytes: groupBytes, cookie: cookie(token()) }).admitted, true);
    assert.equal(admit(group, { bytes: groupBytes, headers: { authorization: `Bearer ${token()}` } }).admitted, true);
  });

  it('counts a signed-in user once, wherever the requests come from', async () => {
    const { reserveJsonBody, groupBytes, token, cookie, admit } = await fixture();
    const group = reserveJsonBody(groupBytes);
    const alice = randomUUID();
    const first = admit(group, { bytes: groupBytes, cookie: cookie(token(alice)), ip: '198.51.100.1' });
    assert.equal(first.admitted, true);
    // Another address and another token of the same user draw on the same allowance ...
    assert.equal(admit(group, { bytes: 1, cookie: cookie(token(alice)), ip: '198.51.100.2' }).res.statusCode, 503);
    // ... while another user at the first address has an allowance of their own.
    assert.equal(admit(group, { bytes: groupBytes, cookie: cookie(token()), ip: '198.51.100.1' }).admitted, true);
  });

  it('keeps ordinary requests working', async () => {
    const { reserveJsonBody, DEFAULT_JSON_BODY_BYTES, token, cookie, admit } = await fixture();
    const normal = reserveJsonBody(DEFAULT_JSON_BODY_BYTES);
    const signedIn = cookie(token());
    // Reads and bodies that are not JSON are not counted.
    for (const options of [
      { method: 'GET', bytes: 0 },
      { method: 'HEAD', bytes: 0 },
      { bytes: 5 * MiB, headers: { 'content-type': 'text/plain' } },
    ]) assert.equal(admit(normal, options).admitted, true);
    // Sign-in and an ordinary signed-in request side by side.
    const login = admit(normal, { bytes: 300, ip: '203.0.113.7' });
    const message = admit(normal, { bytes: 4096, cookie: signedIn });
    assert.deepEqual([login.admitted, message.admitted], [true, true]);
    // The ordinary limit is the same with and without a session.
    for (const options of [{ cookie: cookie(token()) }, { ip: '203.0.113.8' }]) {
      assert.equal(admit(normal, { ...options, bytes: DEFAULT_JSON_BODY_BYTES }).admitted, true);
      assert.equal(admit(normal, { ...options, bytes: DEFAULT_JSON_BODY_BYTES + 1 }).res.statusCode, 413);
    }
    // A body without a usable length is refused as before.
    assert.equal(admit(normal, { bytes: 10, headers: { 'transfer-encoding': 'chunked' } }).res.statusCode, 400);
    assert.equal(admit(normal, { bytes: 10, headers: { 'content-length': 'many' } }).res.statusCode, 411);
    // A finished request returns its share.
    message.res.emit('finish');
    for (let index = 0; index < 8; index += 1) assert.equal(admit(normal, { bytes: 4096, cookie: signedIn }).admitted, true);
  });
});

async function eventually(check: () => Promise<boolean>, timeoutMs = 3_000): Promise<void> {
  const until = Date.now() + timeoutMs;
  while (!await check()) {
    if (Date.now() > until) assert.fail('The expected state was not reached in time');
    await delay(10);
  }
}

describe('request bodies on a real connection', () => {
  const deadlineMs = 500;
  let server: Server;
  let url = '';
  let port = 0;

  before(async () => {
    const { default: express } = await import('express');
    const { DEFAULT_JSON_BODY_BYTES, reserveJsonBody } = await import('./body-admission.js');
    const app = express();
    // The forwarded address names the source, as behind a trusted proxy.
    app.set('trust proxy', true);
    app.use(reserveJsonBody(DEFAULT_JSON_BODY_BYTES, () => deadlineMs));
    app.use(express.json({ limit: DEFAULT_JSON_BODY_BYTES, type: 'application/json' }));
    app.post('/echo', (req, res) => { res.json({ received: req.body }); });
    app.post('/slow', async (_req, res) => {
      await delay(deadlineMs * 2);
      res.json({ done: true });
    });
    server = app.listen(0, '127.0.0.1');
    await once(server, 'listening');
    port = (server.address() as AddressInfo).port;
    url = `http://127.0.0.1:${port}`;
  });

  after(() => {
    server.closeAllConnections();
    server.close();
  });

  const post = (path: string, source: string, body: unknown) => fetch(`${url}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-forwarded-for': source },
    body: JSON.stringify(body),
  });

  /** Send the headers of a JSON request that declares `declared` bytes, then only `sent` of them. */
  function openRequest(source: string, declared: number, sent: string) {
    const socket = connect(port, '127.0.0.1');
    let received = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => { received += chunk; });
    socket.on('error', () => undefined);
    socket.write([
      'POST /echo HTTP/1.1',
      'Host: localhost',
      'Content-Type: application/json',
      `Content-Length: ${declared}`,
      `X-Forwarded-For: ${source}`,
      '',
      sent,
    ].join('\r\n'));
    const closed = new Promise<void>((resolve) => { socket.once('close', () => resolve()); });
    return { socket, closed, received: () => received };
  }

  it('answers a stalled body with 408, closes the connection and frees its share', async () => {
    const source = '198.51.100.10';
    const pad = (bytes: number) => ({ pad: 'x'.repeat(bytes) });
    const stalled = openRequest(source, 400 * 1024, '{"pad":');
    // While it waits it holds most of its source's share ...
    await eventually(async () => (await post('/echo', source, pad(200 * 1024))).status === 503);
    // ... and no one else's.
    assert.equal((await post('/echo', '198.51.100.11', pad(200 * 1024))).status, 200);

    await stalled.closed;
    assert.match(stalled.received(), /^HTTP\/1\.1 408 /);
    assert.match(stalled.received(), /"error":"REQUEST_TIMEOUT"/);
    assert.equal((await post('/echo', source, pad(200 * 1024))).status, 200);
  });

  it('lets a body that keeps arriving finish, even if it is slow', async () => {
    const body = JSON.stringify({ slow: true });
    const request = openRequest('198.51.100.12', body.length, '');
    for (const character of body) {
      request.socket.write(character);
      await delay(10);
    }
    await eventually(async () => request.received().includes('"received"'));
    assert.match(request.received(), /^HTTP\/1\.1 200 /);
    request.socket.end();
    await request.closed;
  });

  it('does not cut off a request whose body arrived but whose handler is still working', async () => {
    const response = await post('/slow', '198.51.100.13', { small: true });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { done: true });
  });
});
