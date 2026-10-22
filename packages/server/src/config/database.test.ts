import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import pg from 'pg';
import { databaseConnectionOptions, loadDatabaseRuntimeConfig } from './database.js';

/** A synthetic connection string, assembled so that it is not taken for a leaked one. */
function databaseUrl(host: string, query = ''): string {
  return ['postgresql', '://', 'test', ':', 'synthetic', '@', host, '/alparts', query].join('');
}

function production(url: string, overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return { NODE_ENV: 'production', DATABASE_URL: url, ...overrides };
}

const plaintext = { DB_SSL: 'false', ALLOW_INSECURE_LOOPBACK_DEPENDENCIES: 'true' };
const refused = /DATABASE_URL must not carry the "[^"]*" query parameter/;

describe('database configuration', () => {
  it('takes TLS from DB_SSL alone', () => {
    const url = databaseUrl('db.example.test:5432');
    assert.equal(loadDatabaseRuntimeConfig(production(url)).ssl, true);
    assert.equal(loadDatabaseRuntimeConfig(production(url, { DB_SSL: 'true' })).ssl, true);
    assert.throws(() => loadDatabaseRuntimeConfig(production(url, { DB_SSL: 'false' })), /database TLS may be disabled only/);
    assert.equal(loadDatabaseRuntimeConfig({ NODE_ENV: 'development', DATABASE_URL: url }).ssl, false);
    assert.equal(loadDatabaseRuntimeConfig({ NODE_ENV: 'test', DATABASE_URL: url, DB_SSL: 'true' }).ssl, true);
    // NODE_ENV unset means development.
    assert.equal(loadDatabaseRuntimeConfig({ DATABASE_URL: url }).ssl, false);
  });

  it('does not take an unrecognised NODE_ENV for development', () => {
    for (const NODE_ENV of ['prod', 'staging', 'Production', '']) {
      assert.throws(
        () => loadDatabaseRuntimeConfig({ NODE_ENV, DATABASE_URL: databaseUrl('db.example.test') }),
        /NODE_ENV must be production, development or test/,
        JSON.stringify(NODE_ENV),
      );
    }
  });

  it('refuses the URLs that undid the production TLS rule', () => {
    for (const [query, url, overrides] of [
      ['sslmode=no-verify', databaseUrl('db.example.test:5432', '?sslmode=no-verify'), {}],
      ['sslmode=disable', databaseUrl('db.example.test:5432', '?sslmode=disable'), {}],
      ['ssl=false', databaseUrl('db.example.test:5432', '?ssl=false'), {}],
      // The host check saw loopback while the client connected to the host parameter.
      ['host=db.example.test', databaseUrl('127.0.0.1:5432', '?host=db.example.test'), plaintext],
    ] as const) {
      assert.throws(() => loadDatabaseRuntimeConfig(production(url, overrides)), refused, query);
    }
    // The same URL without the parameter is fine, and verified TLS is the default.
    assert.deepEqual(
      loadDatabaseRuntimeConfig(production(databaseUrl('db.example.test:5432'))),
      {
        url: databaseUrl('db.example.test:5432'),
        ssl: true,
        poolMax: 10,
        connectTimeoutMs: 5_000,
        statementTimeoutMs: 15_000,
      },
    );
  });

  it('refuses every query parameter that sets TLS or the server, in any environment', () => {
    for (const parameter of [
      'ssl=false',
      'ssl=true',
      'sslmode=disable',
      'sslmode=require',
      'sslmode=verify-full',
      'sslcert=/etc/client.crt',
      'sslkey=/etc/client.key',
      'sslrootcert=/etc/ca.pem',
      'sslpassword=x',
      'sslnegotiation=direct',
      'uselibpqcompat=true',
      'host=db.example.test',
      'hostaddr=192.0.2.10',
      'port=5433',
      // Other spellings of the same names.
      'SSLMODE=disable',
      'Host=db.example.test',
      'ss%6Cmode=disable',
      // Among harmless ones.
      'application_name=alparts&sslmode=disable',
    ]) {
      const url = databaseUrl('db.example.test:5432', `?${parameter}`);
      for (const environment of [
        production(url),
        { NODE_ENV: 'development', DATABASE_URL: url },
        { NODE_ENV: 'test', DATABASE_URL: url },
        { DATABASE_URL: url },
      ]) {
        assert.throws(() => loadDatabaseRuntimeConfig(environment), refused, parameter);
      }
    }
  });

  it('accepts a URL with harmless parameters', () => {
    for (const url of [
      databaseUrl('db.example.test:5432'),
      databaseUrl('db.example.test'),
      databaseUrl('[2001:db8::1]:5432'),
      databaseUrl('db.example.test:5432', '?application_name=alparts&connect_timeout=5'),
    ]) {
      assert.equal(loadDatabaseRuntimeConfig(production(url)).url, url);
    }
  });

  it('lets host and port name only the directory of a Unix socket', () => {
    for (const url of [
      'postgresql:///alparts?host=/var/run/postgresql',
      'postgresql:///alparts?host=/var/run/postgresql&port=5433',
      // Credentials in front of an empty host, which the client reads too.
      databaseUrl('', '?host=/var/run/postgresql'),
      databaseUrl('', '?host=/var/run/postgresql&port=5433'),
    ]) {
      assert.equal(loadDatabaseRuntimeConfig(production(url, plaintext)).ssl, false, url);
    }
    for (const url of [
      // Not the directory of a socket.
      databaseUrl('', '?host=db.example.test'),
      databaseUrl('', '?host='),
      // Next to a network host, so it is not the only way the host is named.
      databaseUrl('db.example.test:5432', '?host=/var/run/postgresql'),
      // The client takes the last of a repeated parameter, whatever its case.
      'postgresql:///alparts?host=/var/run/postgresql&host=db.example.test',
      'postgresql:///alparts?host=/var/run/postgresql&HOST=db.example.test',
      'postgresql:///alparts?host=/var/run/postgresql&port=5433&port=5432',
      'postgresql:///alparts?host=/var/run/postgresql&PORT=5432',
    ]) {
      assert.throws(() => loadDatabaseRuntimeConfig(production(url, plaintext)), refused, url);
    }
  });

  it('allows plaintext in production only for an acknowledged loopback endpoint', () => {
    for (const host of ['127.0.0.1:5432', 'localhost', '[::1]:5432']) {
      assert.equal(loadDatabaseRuntimeConfig(production(databaseUrl(host), plaintext)).ssl, false, host);
    }
    for (const [url, overrides] of [
      [databaseUrl('db.example.test:5432'), plaintext],
      [databaseUrl('127.0.0.1:5432'), { DB_SSL: 'false' }],
      // An empty host is not loopback unless a socket directory says so.
      ['postgresql:///alparts', plaintext],
    ] as const) {
      assert.throws(() => loadDatabaseRuntimeConfig(production(url, overrides)), /database TLS may be disabled only/, url);
    }
  });

  it('refuses a URL the client could read differently from the checks', () => {
    for (const url of [
      'not a url',
      'alparts',
      '/var/run/postgresql alparts',
      // Without a scheme the client reads it relative to its own base and honours the parameter.
      `//${databaseUrl('db.example.test:5432', '?sslmode=disable').split('://')[1]}`,
    ]) {
      assert.throws(() => loadDatabaseRuntimeConfig(production(url)), /DATABASE_URL must be a valid URL/);
    }
  });
});

describe('database connection options', () => {
  it('always apply the configured TLS setting', () => {
    const url = databaseUrl('db.example.test:5432');
    assert.deepEqual(databaseConnectionOptions({ url, ssl: true }), { connectionString: url, ssl: { rejectUnauthorized: true } });
    assert.deepEqual(databaseConnectionOptions({ url, ssl: false }), { connectionString: url, ssl: false });
  });

  it('give the client the configured TLS setting and the host that was checked', () => {
    for (const [url, overrides, expected] of [
      [databaseUrl('db.example.test:5433'), {}, { ssl: { rejectUnauthorized: true }, host: 'db.example.test', port: 5433 }],
      [databaseUrl('[2001:db8::1]'), {}, { ssl: { rejectUnauthorized: true }, host: '2001:db8::1', port: 5432 }],
      [databaseUrl('db.example.test', '?application_name=alparts'), {}, { ssl: { rejectUnauthorized: true }, host: 'db.example.test', port: 5432 }],
      [databaseUrl('127.0.0.1:5432'), plaintext, { ssl: false, host: '127.0.0.1', port: 5432 }],
      ['postgresql:///alparts?host=/var/run/postgresql&port=5433', plaintext, { ssl: false, host: '/var/run/postgresql', port: 5433 }],
      [databaseUrl('', '?host=/var/run/postgresql'), plaintext, { ssl: false, host: '/var/run/postgresql', port: 5432 }],
    ] as const) {
      const client = new pg.Client(databaseConnectionOptions(loadDatabaseRuntimeConfig(production(url, overrides))));
      assert.deepEqual({ ssl: client.ssl, host: client.host, port: client.port }, expected, url);
    }
  });

  it('are not changed by the PostgreSQL environment variables', () => {
    const previous = process.env.PGSSLMODE;
    try {
      const url = databaseUrl('db.example.test:5432');
      process.env.PGSSLMODE = 'disable';
      assert.deepEqual(new pg.Client(databaseConnectionOptions({ url, ssl: true })).ssl, { rejectUnauthorized: true });
      process.env.PGSSLMODE = 'require';
      assert.equal(new pg.Client(databaseConnectionOptions({ url, ssl: false })).ssl, false);
    } finally {
      if (previous === undefined) delete process.env.PGSSLMODE;
      else process.env.PGSSLMODE = previous;
    }
  });

  it('would be undone by these parameters, which is why the URL may not carry them', () => {
    // The client merges the URL over the options it is given. If a later
    // version stops doing that, this fails and the refusal can be revisited.
    const disabled = new pg.Client(databaseConnectionOptions({ url: databaseUrl('db.example.test:5432', '?sslmode=disable'), ssl: true }));
    assert.equal(disabled.ssl, false);
    const moved = new pg.Client(databaseConnectionOptions({ url: databaseUrl('127.0.0.1:5432', '?host=db.example.test'), ssl: false }));
    assert.equal(moved.host, 'db.example.test');
  });
});
