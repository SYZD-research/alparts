import { parseBoundedInteger } from './validation.js';
import { readConfiguredValue } from './source.js';

export interface DatabaseRuntimeConfig {
  url: string;
  ssl: boolean;
  poolMax: number;
  connectTimeoutMs: number;
  statementTimeoutMs: number;
}

/**
 * Database-only configuration for both the server and the least-privilege
 * migrator. It deliberately does not load JWT, audit, or object-store secrets.
 */
export function loadDatabaseRuntimeConfig(
  environment: NodeJS.ProcessEnv = process.env,
  nodeEnvironment = environment.NODE_ENV || 'development',
): DatabaseRuntimeConfig {
  const isProduction = nodeEnvironment === 'production';
  const url = readConfiguredValue('DATABASE_URL', environment, isProduction);
  if (!url) throw new Error('Missing required configuration: DATABASE_URL or DATABASE_URL_FILE');
  const ssl = environment.DB_SSL === 'true' || (isProduction && environment.DB_SSL !== 'false');
  if (isProduction && !ssl && (
    environment.ALLOW_INSECURE_LOOPBACK_DEPENDENCIES !== 'true'
    || !isLoopbackHost(databaseHost(url))
  )) {
    throw new Error('Production database TLS may be disabled only for an explicitly acknowledged loopback endpoint');
  }
  return {
    url,
    ssl,
    poolMax: parseBoundedInteger('DB_POOL_MAX', environment.DB_POOL_MAX, 10, 1, 100),
    connectTimeoutMs: parseBoundedInteger('DB_CONNECT_TIMEOUT_MS', environment.DB_CONNECT_TIMEOUT_MS, 5_000, 100, 60_000),
    statementTimeoutMs: parseBoundedInteger('DB_STATEMENT_TIMEOUT_MS', environment.DB_STATEMENT_TIMEOUT_MS, 15_000, 1_000, 120_000),
  };
}

function databaseHost(connectionString: string): string {
  try {
    const parsed = new URL(connectionString);
    if (!parsed.hostname && parsed.searchParams.get('host')?.startsWith('/')) return 'unix-socket';
    return parsed.hostname;
  } catch {
    throw new Error('DATABASE_URL must be a valid URL');
  }
}

function isLoopbackHost(host: string): boolean {
  const normalized = host.toLowerCase();
  return normalized === 'localhost'
    || normalized === '127.0.0.1'
    || normalized === '[::1]'
    || normalized === '::1'
    || normalized === 'unix-socket';
}
