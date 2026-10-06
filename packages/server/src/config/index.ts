import { randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
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

// Object storage settings were renamed from MINIO_* to S3_*; the old names
// are not read, so refuse to start rather than silently use defaults.
const legacyStorageSettings = Object.keys(env).filter((name) => name.startsWith('MINIO_')).sort();
if (legacyStorageSettings.length > 0) {
  throw new Error(`Object storage settings are now named S3_* (for example MINIO_ENDPOINT is S3_ENDPOINT). Rename: ${legacyStorageSettings.join(', ')}`);
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

  email: {
    // Registration proves the address with a mailed code unless the operator
    // explicitly turns that off.
    verification: env.EMAIL_VERIFICATION?.trim() === 'disabled' ? 'disabled' as const : 'required' as const,
    smtp: env.SMTP_HOST?.trim()
      ? {
          host: env.SMTP_HOST.trim(),
          port: parseBoundedInteger('SMTP_PORT', env.SMTP_PORT, 587, 1, 65535),
          // true: TLS from the first byte (usually port 465). Otherwise the
          // connection upgrades with STARTTLS, which production requires.
          secure: env.SMTP_SECURE === 'true',
          user: env.SMTP_USER?.trim() || null,
          password: value('SMTP_PASSWORD') || null,
          from: env.SMTP_FROM?.trim() || '',
          timeoutMs: parseBoundedInteger('SMTP_TIMEOUT_MS', env.SMTP_TIMEOUT_MS, 10_000, 1_000, 60_000),
        }
      : null,
  },

  webauthn: {
    rpId: env.WEBAUTHN_RP_ID || new URL(corsOrigins[0]).hostname,
    origins: env.WEBAUTHN_ORIGINS ? parseCorsOrigins(env.WEBAUTHN_ORIGINS, isProduction) : corsOrigins,
  },

  audit: {
    integrityKey: mandatorySecret('AUDIT_INTEGRITY_KEY'),
    checkpointPath: env.AUDIT_CHECKPOINT_PATH?.trim() || null,
    checkpointRequired: env.AUDIT_CHECKPOINT_REQUIRED === 'true',
    // A separate object-store bucket is outside the checkpoint-file writer's
    // authority. Keep its identity stable across restarts and restores.
    headBucket: env.AUDIT_HEAD_BUCKET?.trim() || `${env.S3_BUCKET || 'alparts'}-audit`,
    headObjectKey: env.AUDIT_HEAD_OBJECT_KEY?.trim() || null,
    witnessPublicKeyPath: env.AUDIT_WITNESS_PUBLIC_KEY_FILE?.trim() || null,
    witnessPath: env.AUDIT_WITNESS_PATH?.trim() || null,
    witnessDeploymentId: env.AUDIT_WITNESS_DEPLOYMENT_ID?.trim() || null,
    witnessRequired: env.AUDIT_WITNESS_REQUIRED === 'true',
  },

  s3: {
    endpoint: env.S3_ENDPOINT || 'localhost',
    port: parseBoundedInteger('S3_PORT', env.S3_PORT, 9000, 1, 65535),
    region: env.S3_REGION?.trim() || 'us-east-1',
    accessKey: required('S3_ACCESS_KEY'),
    secretKey: productionSecret('S3_SECRET_KEY'),
    bucket: env.S3_BUCKET || 'alparts',
    useSSL: env.S3_USE_SSL === 'true' || (isProduction && env.S3_USE_SSL !== 'false'),
    requestTimeoutMs: parseBoundedInteger(
      'S3_REQUEST_TIMEOUT_MS',
      env.S3_REQUEST_TIMEOUT_MS,
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

if (env.EMAIL_VERIFICATION?.trim() && !['required', 'disabled'].includes(env.EMAIL_VERIFICATION.trim())) {
  throw new Error('EMAIL_VERIFICATION must be required or disabled');
}
if (config.email.smtp) {
  if (!/^[^\s@<>"(),;:]+@[^\s@<>"(),;:]+$/.test(config.email.smtp.from)) throw new Error('SMTP_FROM must be an email address');
  if (Boolean(config.email.smtp.user) !== Boolean(config.email.smtp.password)) {
    throw new Error('SMTP_USER and SMTP_PASSWORD must be set together');
  }
}
if (config.observability.metricsEnabled && !config.observability.metricsToken) {
  throw new Error('METRICS_TOKEN is required when METRICS_ENABLED=true');
}
if (config.isProduction && (!config.audit.checkpointPath || !config.audit.checkpointRequired)) {
  throw new Error('Production requires AUDIT_CHECKPOINT_PATH and AUDIT_CHECKPOINT_REQUIRED=true');
}
if (config.audit.headObjectKey && !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(config.audit.headObjectKey)) {
  throw new Error('AUDIT_HEAD_OBJECT_KEY must be a stable identifier of at most 128 characters');
}
if (config.audit.headBucket === config.s3.bucket) throw new Error('AUDIT_HEAD_BUCKET must be separate from S3_BUCKET');
if (config.isProduction && !config.audit.headObjectKey) throw new Error('Production requires AUDIT_HEAD_OBJECT_KEY');
if ((config.audit.witnessRequired || config.audit.witnessPath || config.audit.witnessPublicKeyPath || config.audit.witnessDeploymentId)
  && (!config.audit.witnessPath || !config.audit.witnessPublicKeyPath
    || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(config.audit.witnessDeploymentId ?? ''))) {
  throw new Error('Audit witness requires its public key, signed witness file and deployment UUID');
}
// A scheme, port or path in S3_ENDPOINT would only fail later, obscurely.
const s3Host = config.s3.endpoint.startsWith('[') && config.s3.endpoint.endsWith(']')
  ? config.s3.endpoint.slice(1, -1)
  : config.s3.endpoint;
if (!isIP(s3Host) && !/^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/.test(config.s3.endpoint)) {
  throw new Error('S3_ENDPOINT must be a host name or IP address, without a scheme, port or path');
}
if (!/^[a-z0-9][a-z0-9-]{0,31}$/.test(config.s3.region)) throw new Error('S3_REGION must be a region name such as us-east-1');
for (const [name, bucket] of [['S3_BUCKET', config.s3.bucket], ['AUDIT_HEAD_BUCKET', config.audit.headBucket]] as const) {
  if (
    !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucket)
    || /\.\.|\.-|-\./.test(bucket)
    || isIP(bucket)
  ) throw new Error(`${name} must be a DNS-safe bucket name of 3 to 63 lower-case characters`);
}
if (config.isProduction && !config.s3.useSSL && (
  env.ALLOW_INSECURE_LOOPBACK_DEPENDENCIES !== 'true'
  || !isLoopbackHost(config.s3.endpoint)
)) {
  throw new Error('Production object-storage TLS may be disabled only for an explicitly acknowledged loopback endpoint');
}

// The S3 client resolves any name through DNS, so only literal loopback
// names count; unlike PostgreSQL there is no Unix-socket form.
function isLoopbackHost(host: string): boolean {
  const normalized = host.toLowerCase();
  return normalized === 'localhost'
    || normalized === '127.0.0.1'
    || normalized === '[::1]'
    || normalized === '::1';
}

for (const origin of config.webauthn.origins) {
  const host = new URL(origin).hostname;
  if (host !== config.webauthn.rpId && !host.endsWith(`.${config.webauthn.rpId}`)) {
    // Default development origins may include both localhost and loopback.
    if (!env.WEBAUTHN_ORIGINS && !env.WEBAUTHN_RP_ID && !isProduction) continue;
    throw new Error('WEBAUTHN_RP_ID must match the configured WebAuthn origins');
  }
}
