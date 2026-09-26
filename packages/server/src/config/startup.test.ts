import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, it } from 'node:test';

const strong = 'synthetic-test-secret-at-least-32-bytes';

function syntheticDatabaseUrl(host: string): string {
  return ['postgresql', '://', 'test', ':', 'synthetic', '@', host, '/alparts'].join('');
}

function productionEnvironment(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH,
    NODE_ENV: 'production',
    DATABASE_URL: syntheticDatabaseUrl('db.example.test'),
    DB_SSL: 'true',
    MINIO_ENDPOINT: 'objects.example.test',
    MINIO_USE_SSL: 'true',
    MINIO_ACCESS_KEY: 'synthetic-access-key',
    MINIO_SECRET_KEY: strong,
    JWT_SECRET: strong,
    AUDIT_INTEGRITY_KEY: strong,
    PASSWORD_PEPPER: strong,
    AUDIT_CHECKPOINT_PATH: '/tmp/alparts-synthetic-checkpoint.json',
    AUDIT_CHECKPOINT_REQUIRED: 'true',
    CORS_ORIGINS: 'https://chat.example.test',
    ...overrides,
  };
}

function loadConfiguration(environment: NodeJS.ProcessEnv) {
  return spawnSync(process.execPath, [
    '--import',
    'tsx',
    '--input-type=module',
    '--eval',
    "await import('./src/config/index.ts'); (await import('node:fs')).writeSync(1, 'loaded')",
  ], {
    cwd: process.cwd(),
    env: environment,
    encoding: 'utf8',
    timeout: 5_000,
  });
}

describe('production startup configuration', () => {
  it('accepts a complete TLS-protected production configuration', () => {
    const result = loadConfiguration(productionEnvironment());
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, 'loaded');
  });

  it('requires both the audit checkpoint path and fail-closed mode', () => {
    const withoutPath = productionEnvironment({ AUDIT_CHECKPOINT_PATH: '' });
    const result = loadConfiguration(withoutPath);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Production requires AUDIT_CHECKPOINT_PATH/);
  });

  it('rejects insecure remote dependencies even with the loopback acknowledgement', () => {
    const result = loadConfiguration(productionEnvironment({
      DB_SSL: 'false',
      ALLOW_INSECURE_LOOPBACK_DEPENDENCIES: 'true',
    }));
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /database TLS may be disabled only/);
  });

  it('allows explicitly acknowledged plaintext only for loopback dependencies', () => {
    const result = loadConfiguration(productionEnvironment({
      DATABASE_URL: syntheticDatabaseUrl('127.0.0.1:5432'),
      DB_SSL: 'false',
      MINIO_ENDPOINT: '127.0.0.1',
      MINIO_USE_SSL: 'false',
      ALLOW_INSECURE_LOOPBACK_DEPENDENCIES: 'true',
    }));
    assert.equal(result.status, 0, result.stderr);
  });

  it('requires a strong metrics token when metrics are enabled', () => {
    const missing = loadConfiguration(productionEnvironment({ METRICS_ENABLED: 'true' }));
    assert.notEqual(missing.status, 0);
    assert.match(missing.stderr, /METRICS_TOKEN is required/);

    const short = loadConfiguration(productionEnvironment({ METRICS_ENABLED: 'true', METRICS_TOKEN: 'short' }));
    assert.notEqual(short.status, 0);
    assert.match(short.stderr, /METRICS_TOKEN must contain at least 32 bytes/);
  });

  it('rejects weak object-storage secrets in production', () => {
    const result = loadConfiguration(productionEnvironment({ MINIO_SECRET_KEY: 'short' }));
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /MINIO_SECRET_KEY must contain at least 32 bytes/);
  });

  it('rejects group-writable secret files and ambiguous direct/file values', () => {
    const directory = mkdtempSync(join(tmpdir(), 'alparts-config-test-'));
    const secretFile = join(directory, 'jwt-secret');
    try {
      writeFileSync(secretFile, strong, { mode: 0o660 });
      chmodSync(secretFile, 0o660);
      const fileEnvironment = productionEnvironment({ JWT_SECRET: '', JWT_SECRET_FILE: secretFile });
      const unsafeFile = loadConfiguration(fileEnvironment);
      assert.notEqual(unsafeFile.status, 0);
      assert.match(unsafeFile.stderr, /must not be writable by group or other/);

      chmodSync(secretFile, 0o600);
      const ambiguous = loadConfiguration(productionEnvironment({ JWT_SECRET_FILE: secretFile }));
      assert.notEqual(ambiguous.status, 0);
      assert.match(ambiguous.stderr, /Configure only one of JWT_SECRET or JWT_SECRET_FILE/);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
