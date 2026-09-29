import { randomBytes } from 'node:crypto';
import { parseBindHost, parseBoundedInteger, parseCorsOrigins, parseTrustedProxies, parseVoiceIceServers } from './validation.js';
import { loadDatabaseRuntimeConfig } from './database.js';
import { readConfiguredValue } from './source.js';

const env = process.env;
const nodeEnv = env.NODE_ENV || 'development';
const isProduction = nodeEnv === 'production';

function value(name: string): string | undefined {
  return readConfiguredValue(name, env, isProduction);
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

function productionSecret(name: string, minimumBytes = 32): string {
  const configured = required(name);
  if (isProduction && Buffer.byteLength(configured, 'utf8') < minimumBytes) {
    throw new Error(`${name} must contain at least ${minimumBytes} bytes in production`);
  }
  return configured;
}

const configuredCorsOrigins = env.CORS_ORIGINS || env.CORS_ORIGIN;
if (isProduction && !configuredCorsOrigins) {
  throw new Error('CORS_ORIGINS must be explicitly configured in production');
}

const corsOrigins = parseCorsOrigins(
  configuredCorsOrigins || 'http://localhost:5173,http://localhost:3000,http://127.0.0.1:3000',
  isProduction,
);
const databaseRuntimeConfig = loadDatabaseRuntimeConfig(env, nodeEnv);

export const config = {
  bindHost: parseBindHost(env.BIND_HOST),
  port: parseBoundedInteger('PORT', env.PORT, 3000, 1, 65535),
  nodeEnv,
  isProduction,

  db: databaseRuntimeConfig,

  jwt: {
    secret: secret('JWT_SECRET'),
    issuer: env.JWT_ISSUER || 'alparts',
    audience: env.JWT_AUDIENCE || 'alparts-client',
    expiresInSeconds: parseBoundedInteger('JWT_EXPIRES_IN_SECONDS', env.JWT_EXPIRES_IN_SECONDS, 7 * 24 * 60 * 60, 300, 30 * 24 * 60 * 60),
  },

  auth: {
    passwordPepper: mandatorySecret('PASSWORD_PEPPER'),
    // Only set while rotating away from a leaked/retired pepper.
    previousPasswordPepper: optionalSecret('PASSWORD_PEPPER_PREVIOUS'),
    registrationInviteSecret: optionalSecret('REGISTRATION_INVITE_SECRET'),
    cookieName: isProduction ? '__Host-alparts_session' : 'alparts_session',
    secureCookie: isProduction || env.COOKIE_SECURE === 'true',
  },

  webauthn: {
    rpId: env.WEBAUTHN_RP_ID || new URL(corsOrigins[0]).hostname,
    origins: env.WEBAUTHN_ORIGINS ? parseCorsOrigins(env.WEBAUTHN_ORIGINS, isProduction) : corsOrigins,
  },

  audit: {
    integrityKey: mandatorySecret('AUDIT_INTEGRITY_KEY'),
    checkpointPath: env.AUDIT_CHECKPOINT_PATH?.trim() || null,
    checkpointRequired: env.AUDIT_CHECKPOINT_REQUIRED === 'true',
    witnessPublicKeyPath: env.AUDIT_WITNESS_PUBLIC_KEY_FILE?.trim() || null,
    witnessPath: env.AUDIT_WITNESS_PATH?.trim() || null,
    witnessDeploymentId: env.AUDIT_WITNESS_DEPLOYMENT_ID?.trim() || null,
    witnessRequired: env.AUDIT_WITNESS_REQUIRED === 'true',
  },

  minio: {
    endPoint: env.MINIO_ENDPOINT || 'localhost',
    port: parseBoundedInteger('MINIO_PORT', env.MINIO_PORT, 9000, 1, 65535),
    accessKey: required('MINIO_ACCESS_KEY'),
    secretKey: productionSecret('MINIO_SECRET_KEY'),
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
    trustedProxies: parseTrustedProxies(env.TRUSTED_PROXIES, isProduction),
  },

  observability: {
    metricsEnabled: env.METRICS_ENABLED === 'true',
    metricsToken: optionalSecret('METRICS_TOKEN'),
  },

  voice: {
    iceServers: parseVoiceIceServers(value('VOICE_ICE_SERVERS_JSON')),
  },
} as const;

if (config.observability.metricsEnabled && !config.observability.metricsToken) {
  throw new Error('METRICS_TOKEN is required when METRICS_ENABLED=true');
}
if (config.isProduction && (!config.audit.checkpointPath || !config.audit.checkpointRequired)) {
  throw new Error('Production requires AUDIT_CHECKPOINT_PATH and AUDIT_CHECKPOINT_REQUIRED=true');
}
if ((config.audit.witnessRequired || config.audit.witnessPath || config.audit.witnessPublicKeyPath || config.audit.witnessDeploymentId)
  && (!config.audit.witnessPath || !config.audit.witnessPublicKeyPath
    || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(config.audit.witnessDeploymentId ?? ''))) {
  throw new Error('Audit witness requires its public key, signed witness file and deployment UUID');
}
if (config.isProduction && !config.minio.useSSL && (
  env.ALLOW_INSECURE_LOOPBACK_DEPENDENCIES !== 'true'
  || !isLoopbackHost(config.minio.endPoint)
)) {
  throw new Error('Production object-storage TLS may be disabled only for an explicitly acknowledged loopback endpoint');
}

function isLoopbackHost(host: string): boolean {
  const normalized = host.toLowerCase();
  return normalized === 'localhost'
    || normalized === '127.0.0.1'
    || normalized === '[::1]'
    || normalized === '::1'
    || normalized === 'unix-socket';
}

for (const origin of config.webauthn.origins) {
  const host = new URL(origin).hostname;
  if (host !== config.webauthn.rpId && !host.endsWith(`.${config.webauthn.rpId}`)) {
    // Default development origins may include both localhost and loopback.
    if (!env.WEBAUTHN_ORIGINS && !env.WEBAUTHN_RP_ID && !isProduction) continue;
    throw new Error('WEBAUTHN_RP_ID must match the configured WebAuthn origins');
  }
}
