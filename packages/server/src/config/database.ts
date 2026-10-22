import { parseBoundedInteger, parseNodeEnvironment, type NodeEnvironment } from './validation.js';
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
  nodeEnvironment: NodeEnvironment = parseNodeEnvironment(environment.NODE_ENV),
): DatabaseRuntimeConfig {
  const isProduction = nodeEnvironment === 'production';
  const url = readConfiguredValue('DATABASE_URL', environment, isProduction);
  if (!url) throw new Error('Missing required configuration: DATABASE_URL or DATABASE_URL_FILE');
  const host = validatedDatabaseHost(url);
  const ssl = environment.DB_SSL === 'true' || (isProduction && environment.DB_SSL !== 'false');
  if (isProduction && !ssl && (
    environment.ALLOW_INSECURE_LOOPBACK_DEPENDENCIES !== 'true'
    || !isLoopbackHost(host)
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

/**
 * The options every PostgreSQL client of the server is built from. TLS is the
 * validated setting alone. The client lets the query parameters of the URL
 * override the options it is given, so loadDatabaseRuntimeConfig refuses a URL
 * that carries any that matter.
 */
export function databaseConnectionOptions(
  database: Pick<DatabaseRuntimeConfig, 'url' | 'ssl'>,
): { connectionString: string; ssl: { rejectUnauthorized: true } | false } {
  return {
    connectionString: database.url,
    ssl: database.ssl ? { rejectUnauthorized: true } : false,
  };
}

/**
 * The host a DATABASE_URL names, read as the PostgreSQL client reads it. A
 * parameter that sets TLS or the server would undo what was validated, so it
 * is refused: DB_SSL decides TLS, and the host and port belong in the URL
 * itself. The directory of a Unix socket is the one thing `host` and `port`
 * may name, because it cannot lead off the machine.
 */
function validatedDatabaseHost(connectionString: string): string {
  const { hostname, parameters } = parseDatabaseUrl(connectionString);
  const named = (name: string) => parameters.filter(([key]) => key.toLowerCase() === name);
  const hosts = named('host');
  const ports = named('port');
  // The client takes the last of a repeated parameter, so only a single one can be trusted.
  const unixSocket = hostname === ''
    && hosts.length === 1 && hosts[0]![0] === 'host' && hosts[0]![1].startsWith('/')
    && ports.length <= 1 && ports.every(([key]) => key === 'port');
  for (const [name] of parameters) {
    const key = name.toLowerCase();
    if (
      key.startsWith('ssl')
      || key === 'uselibpqcompat'
      || key === 'hostaddr'
      || ((key === 'host' || key === 'port') && !unixSocket)
    ) {
      throw new Error(
        `DATABASE_URL must not carry the ${JSON.stringify(name.slice(0, 40))} query parameter: DB_SSL decides TLS, and the host and port belong in the URL itself`,
      );
    }
  }
  return unixSocket ? 'unix-socket' : hostname;
}

function parseDatabaseUrl(connectionString: string): { hostname: string; parameters: Array<[string, string]> } {
  try {
    const parsed = new URL(connectionString);
    return { hostname: parsed.hostname, parameters: [...parsed.searchParams] };
  } catch {
    // The client also reads credentials in front of an empty host ("user:password@/name").
    try {
      const parsed = new URL(connectionString.replace('@/', '@___DUMMY___/'));
      return { hostname: '', parameters: [...parsed.searchParams] };
    } catch {
      throw new Error('DATABASE_URL must be a valid URL');
    }
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
