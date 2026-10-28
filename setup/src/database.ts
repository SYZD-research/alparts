import { DATABASE } from './secrets.ts';

// PostgreSQL roles: the owner applies migrations and owns the schema, the app
// reads and writes rows, and the backup role only reads. The superuser has no
// password login (pg_hba.conf) and is used here, through the local socket,
// for these statements only.

/** The database and its three roles: the setup's own names, or unique ones for the integration test. */
export interface DatabaseNames { name: string; owner: string; app: string; backup: string }

export type Role = 'owner' | 'app' | 'backup';

const ROLES: Role[] = ['owner', 'app', 'backup'];

function literal(value: string): string {
  if (!/^[A-Za-z0-9$:+/=._-]+$/.test(value)) throw new Error('Unexpected characters in a SQL literal');
  return `'${value}'`;
}

function identifiers(names: DatabaseNames): DatabaseNames {
  for (const value of [names.name, names.owner, names.app, names.backup]) {
    if (!/^[a-z_][a-z0-9_]{0,62}$/.test(value)) throw new Error('Unexpected characters in a SQL identifier');
  }
  return names;
}

/** Creates or updates the roles and the database. Safe to run again: it converges on the same state. */
export function provisionSql(verifiers: Record<Role, string>, names: DatabaseNames = DATABASE): string {
  const { name, owner, app, backup } = identifiers(names);
  const roles = ROLES.map((role) => `'${names[role]}'`).join(', ');
  return [
    '\\set ON_ERROR_STOP on',
    `SELECT format('CREATE ROLE %I LOGIN', name) FROM unnest(ARRAY[${roles}]) AS name`,
    '  WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = name)\\gexec',
    ...ROLES.map((role) => `ALTER ROLE ${names[role]} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD ${literal(verifiers[role])};`),
    `SELECT 'CREATE DATABASE ${name} OWNER ${owner} ENCODING ''UTF8'' TEMPLATE template0'`,
    `  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${name}')\\gexec`,
    `\\connect ${name}`,
    `REVOKE ALL ON DATABASE ${name} FROM PUBLIC;`,
    `GRANT CONNECT ON DATABASE ${name} TO ${app}, ${backup};`,
    'REVOKE ALL ON SCHEMA public FROM PUBLIC;',
    `GRANT USAGE ON SCHEMA public TO ${app}, ${backup};`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${app};`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO ${app};`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA public GRANT SELECT ON TABLES TO ${backup};`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA public GRANT SELECT ON SEQUENCES TO ${backup};`,
    '',
  ].join('\n');
}

/**
 * Grants on what the migrations created, run after each of them. The app
 * reads the migration records at startup to check the schema it runs on.
 */
export function grantsSql(names: DatabaseNames = DATABASE): string {
  const { app, backup } = identifiers(names);
  return [
    '\\set ON_ERROR_STOP on',
    `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${app};`,
    `GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${app};`,
    `GRANT SELECT ON ALL TABLES IN SCHEMA public TO ${backup};`,
    `GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO ${backup};`,
    `GRANT USAGE ON SCHEMA drizzle TO ${app}, ${backup};`,
    `GRANT SELECT ON ALL TABLES IN SCHEMA drizzle TO ${app}, ${backup};`,
    `GRANT SELECT ON ALL SEQUENCES IN SCHEMA drizzle TO ${backup};`,
    '',
  ].join('\n');
}

/** The number of applied migrations, 0 before the first. */
export const APPLIED_MIGRATIONS_SQL = "SELECT CASE WHEN to_regclass('drizzle.__drizzle_migrations') IS NULL THEN 0"
  + " ELSE (xpath('/row/c/text()', query_to_xml('SELECT count(*) AS c FROM drizzle.__drizzle_migrations', false, true, '')))[1]::text::int END";

/** Whether any account exists yet: the first one is created with the setup's invitation code. */
export const HAS_ACCOUNTS_SQL = "SELECT CASE WHEN to_regclass('public.users') IS NULL THEN false"
  + " ELSE (xpath('/row/e/text()', query_to_xml('SELECT EXISTS (SELECT FROM public.users) AS e', false, true, '')))[1]::text::boolean END";
