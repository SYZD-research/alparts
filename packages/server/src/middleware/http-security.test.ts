import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

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

describe('request body admission', () => {
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
});
