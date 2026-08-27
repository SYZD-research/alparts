import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parseBindHost, parseBoundedInteger, parseCorsOrigins, parseVoiceIceServers } from './validation.js';

const env = process.env;
const nodeEnv = env.NODE_ENV || 'development';
const isProduction = nodeEnv === 'production';

function value(name: string): string | undefined {
  const direct = env[name]?.trim();
  const file = env[`${name}_FILE`]?.trim();
  if (direct && file) throw new Error(`Configure only one of ${name} or ${name}_FILE`);
  if (!file) return direct || undefined;
  const loaded = readFileSync(file, { encoding: 'utf8' }).trim();
  if (Buffer.byteLength(loaded, 'utf8') > 64 * 1024) throw new Error(`${name}_FILE is too large`);
  return loaded || undefined;
}

function required(name: string): string {
  const configured = value(name);
  if (!configured) throw new Error(`Missing required configuration: ${name} or ${name}_FILE`);
  return configured;
}

function secret(name: string, minimumBytes = 32): string {
  const configured = value(name);
  if (!configured) {
    if (isProduction) throw new Error(`Missing required production secret: ${name}`);
    // Development-only ephemeral secrets avoid shipping a reusable credential.
    return randomBytes(minimumBytes).toString('base64url');
  }
  if (Buffer.byteLength(configured, 'utf8') < minimumBytes) {
    throw new Error(`${name} must contain at least ${minimumBytes} bytes`);
  }
  return configured;
}

function optionalSecret(name: string, minimumBytes = 32): string | null {
  const configured = value(name);
  if (!configured) return null;
  if (Buffer.byteLength(configured, 'utf8') < minimumBytes) {
    throw new Error(`${name} must contain at least ${minimumBytes} bytes when configured`);
  }
  return configured;
}

function mandatorySecret(name: string, minimumBytes = 32): string {
  const value = required(name);
  if (Buffer.byteLength(value, 'utf8') < minimumBytes) {
    throw new Error(`${name} must contain at least ${minimumBytes} bytes`);
  }
  return value;
}

const configuredCorsOrigins = env.CORS_ORIGINS || env.CORS_ORIGIN;
if (isProduction && !configuredCorsOrigins) {
  throw new Error('CORS_ORIGINS must be explicitly configured in production');
}

const corsOrigins = parseCorsOrigins(configuredCorsOrigins || 'http://localhost:5173', isProduction);

export const config = {
  bindHost: parseBindHost(env.BIND_HOST),
  port: parseBoundedInteger('PORT', env.PORT, 3000, 1, 65535),
  nodeEnv,
  isProduction,

  db: {
    url: required('DATABASE_URL'),
    ssl: env.DB_SSL === 'true' || (isProduction && env.DB_SSL !== 'false'),
    poolMax: parseBoundedInteger('DB_POOL_MAX', env.DB_POOL_MAX, 10, 1, 100),
    connectTimeoutMs: parseBoundedInteger('DB_CONNECT_TIMEOUT_MS', env.DB_CONNECT_TIMEOUT_MS, 5_000, 100, 60_000),
    statementTimeoutMs: parseBoundedInteger('DB_STATEMENT_TIMEOUT_MS', env.DB_STATEMENT_TIMEOUT_MS, 15_000, 1_000, 120_000),
  },

  jwt: {
    secret: secret('JWT_SECRET'),
    issuer: env.JWT_ISSUER || 'alparts',
    audience: env.JWT_AUDIENCE || 'alparts-client',
    expiresInSeconds: parseBoundedInteger('JWT_EXPIRES_IN_SECONDS', env.JWT_EXPIRES_IN_SECONDS, 7 * 24 * 60 * 60, 300, 30 * 24 * 60 * 60),
  },

  auth: {
    registrationInviteSecret: optionalSecret('REGISTRATION_INVITE_SECRET'),
    cookieName: isProduction ? '__Host-alparts_session' : 'alparts_session',
    secureCookie: isProduction || env.COOKIE_SECURE === 'true',
  },

  audit: {
    integrityKey: mandatorySecret('AUDIT_INTEGRITY_KEY'),
    checkpointPath: env.AUDIT_CHECKPOINT_PATH?.trim() || null,
    checkpointRequired: env.AUDIT_CHECKPOINT_REQUIRED === 'true',
  },

  minio: {
    endPoint: env.MINIO_ENDPOINT || 'localhost',
    port: parseBoundedInteger('MINIO_PORT', env.MINIO_PORT, 9000, 1, 65535),
    accessKey: required('MINIO_ACCESS_KEY'),
    secretKey: required('MINIO_SECRET_KEY'),
    bucket: env.MINIO_BUCKET || 'alparts',
    useSSL: env.MINIO_USE_SSL === 'true' || (isProduction && env.MINIO_USE_SSL !== 'false'),
    requestTimeoutMs: parseBoundedInteger(
      'MINIO_REQUEST_TIMEOUT_MS',
      env.MINIO_REQUEST_TIMEOUT_MS,
      10_000,
      1_000,
      60_000,
    ),
  },

  storage: {
    perUserQuotaBytes: parseBoundedInteger('STORAGE_QUOTA_BYTES_PER_USER', env.STORAGE_QUOTA_BYTES_PER_USER, 5 * 1024 * 1024 * 1024, 1024 * 1024, 1024 * 1024 * 1024 * 1024),
    perChannelQuotaBytes: parseBoundedInteger('STORAGE_QUOTA_BYTES_PER_CHANNEL', env.STORAGE_QUOTA_BYTES_PER_CHANNEL, 20 * 1024 * 1024 * 1024, 1024 * 1024, 4 * 1024 * 1024 * 1024 * 1024),
    perWorkspaceQuotaBytes: parseBoundedInteger('STORAGE_QUOTA_BYTES_PER_WORKSPACE', env.STORAGE_QUOTA_BYTES_PER_WORKSPACE, 100 * 1024 * 1024 * 1024, 1024 * 1024, 8 * 1024 * 1024 * 1024 * 1024),
  },

  cors: {
    origins: corsOrigins,
  },

  network: {
    trustedProxies: (env.TRUSTED_PROXIES || '').split(',').map((entry) => entry.trim()).filter(Boolean),
  },

  voice: {
    iceServers: parseVoiceIceServers(value('VOICE_ICE_SERVERS_JSON')),
  },
} as const;
