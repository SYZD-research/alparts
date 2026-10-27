import { DATABASE } from './secrets.ts';

// PostgreSQL roles: the owner applies migrations and owns the schema, the app
// reads and writes rows, and the backup role only reads. The superuser has no
// password login (pg_hba.conf) and is used here, through the local socket,
// for these statements only.

const ROLES = [DATABASE.owner, DATABASE.app, DATABASE.backup] as const;

function literal(value: string): string {
  if (!/^[A-Za-z0-9$:+/=._-]+$/.test(value)) throw new Error('Unexpected characters in a SQL literal');
  return `'${value}'`;
}

/** Creates or updates the roles and the database. Safe to run again: it converges on the same state. */
export function provisionSql(verifiers: Record<(typeof ROLES)[number], string>): string {
  const roles = ROLES.map((role) => `'${role}'`).join(', ');
  return [
    '\\set ON_ERROR_STOP on',
    `SELECT format('CREATE ROLE %I LOGIN', name) FROM unnest(ARRAY[${roles}]) AS name`,
    '  WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = name)\\gexec',
    ...ROLES.map((role) => `ALTER ROLE ${role} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD ${literal(verifiers[role])};`),
    `SELECT 'CREATE DATABASE ${DATABASE.name} OWNER ${DATABASE.owner} ENCODING ''UTF8'' TEMPLATE template0'`,
    `  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${DATABASE.name}')\\gexec`,
    `\\connect ${DATABASE.name}`,
    `REVOKE ALL ON DATABASE ${DATABASE.name} FROM PUBLIC;`,
    `GRANT CONNECT ON DATABASE ${DATABASE.name} TO ${DATABASE.app}, ${DATABASE.backup};`,
    'REVOKE ALL ON SCHEMA public FROM PUBLIC;',
    `GRANT USAGE ON SCHEMA public TO ${DATABASE.app}, ${DATABASE.backup};`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${DATABASE.owner} IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${DATABASE.app};`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${DATABASE.owner} IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO ${DATABASE.app};`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${DATABASE.owner} IN SCHEMA public GRANT SELECT ON TABLES TO ${DATABASE.backup};`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${DATABASE.owner} IN SCHEMA public GRANT SELECT ON SEQUENCES TO ${DATABASE.backup};`,
    '',
  ].join('\n');
}

/**
 * Grants on what the migrations created, run after each of them. The app
 * reads the migration records at startup to check the schema it runs on.
 */
export function grantsSql(): string {
  return [
    '\\set ON_ERROR_STOP on',
    `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${DATABASE.app};`,
    `GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${DATABASE.app};`,
    `GRANT SELECT ON ALL TABLES IN SCHEMA public TO ${DATABASE.backup};`,
    `GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO ${DATABASE.backup};`,
    `GRANT USAGE ON SCHEMA drizzle TO ${DATABASE.app}, ${DATABASE.backup};`,
    `GRANT SELECT ON ALL TABLES IN SCHEMA drizzle TO ${DATABASE.app}, ${DATABASE.backup};`,
    `GRANT SELECT ON ALL SEQUENCES IN SCHEMA drizzle TO ${DATABASE.backup};`,
    '',
  ].join('\n');
}

/** The number of applied migrations, 0 before the first. */
export const APPLIED_MIGRATIONS_SQL = "SELECT CASE WHEN to_regclass('drizzle.__drizzle_migrations') IS NULL THEN 0"
  + " ELSE (xpath('/row/c/text()', query_to_xml('SELECT count(*) AS c FROM drizzle.__drizzle_migrations', false, true, '')))[1]::text::int END";

/** Whether any account exists yet: the first one is created with the setup's invitation code. */
export const HAS_ACCOUNTS_SQL = "SELECT CASE WHEN to_regclass('public.users') IS NULL THEN false"
  + " ELSE (xpath('/row/e/text()', query_to_xml('SELECT EXISTS (SELECT FROM public.users) AS e', false, true, '')))[1]::text::boolean END";
