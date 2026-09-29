import { createHash } from 'node:crypto';
import type pg from 'pg';

const MAX_SCHEMA_CATALOG_ENTRIES = 4_096;
const SCHEMA_CATALOG_FORMAT = 1;

/** Generated from a fresh PostgreSQL 16 database after migrations 0000-0019. */
export const expectedSchemaCatalog = Object.freeze({
  entryCount: 567,
  sha256: 'b70ac8ed5be344908d9f3220649969d1d8081da017e67c0a5a0ce6daaa9feb2a',
});

export interface SchemaCatalogSnapshot {
  entryCount: number;
  sha256: string;
}

interface CatalogClient {
  query<T extends pg.QueryResultRow = pg.QueryResultRow>(
    queryText: string,
    values?: readonly unknown[],
  ): Promise<pg.QueryResult<T>>;
}

interface CountRow extends pg.QueryResultRow { entryCount: string }
interface DescriptorRow extends pg.QueryResultRow { descriptor: string }

/**
 * Fingerprint security-relevant public-schema catalog state. The caller must
 * hold a repeatable-read transaction with search_path fixed to pg_catalog so
 * pg_get_* output is deterministic and the count/snapshot is one view.
 */
export async function loadSchemaCatalogSnapshot(client: CatalogClient): Promise<SchemaCatalogSnapshot> {
  const countResult = await client.query<CountRow>(SCHEMA_CATALOG_COUNT_SQL);
  const entryCount = Number(countResult.rows[0]?.entryCount);
  if (
    countResult.rows.length !== 1
    || !Number.isSafeInteger(entryCount)
    || entryCount < 1
    || entryCount > MAX_SCHEMA_CATALOG_ENTRIES
  ) throw new Error('DATABASE_SCHEMA_CATALOG_LIMIT');

  const result = await client.query<DescriptorRow>(SCHEMA_CATALOG_DESCRIPTOR_SQL, [entryCount + 1]);
  if (result.rows.length !== entryCount) throw new Error('DATABASE_SCHEMA_CATALOG_UNSTABLE');
  const descriptors = result.rows.map((row) => row.descriptor);
  if (descriptors.some((value) => typeof value !== 'string' || value.length > 1_048_576)) {
    throw new Error('DATABASE_SCHEMA_CATALOG_INVALID');
  }
  return {
    entryCount,
    sha256: fingerprintSchemaCatalogDescriptors(descriptors),
  };
}

export function fingerprintSchemaCatalogDescriptors(descriptors: readonly string[]): string {
  const hash = createHash('sha256');
  let previous: string | null = null;
  for (const descriptor of descriptors) {
    if (previous !== null && descriptor <= previous) {
      throw new Error('DATABASE_SCHEMA_CATALOG_INVALID');
    }
    hash.update(descriptor);
    hash.update('\n');
    previous = descriptor;
  }
  return hash.digest('hex');
}

export function assertSchemaCatalogMatches(
  actual: SchemaCatalogSnapshot,
  expected: SchemaCatalogSnapshot = expectedSchemaCatalog,
): void {
  if (
    actual.entryCount !== expected.entryCount
    || actual.sha256 !== expected.sha256
  ) throw new Error('DATABASE_SCHEMA_CATALOG_MISMATCH');
}

const SCHEMA_CATALOG_COUNT_SQL = `
  with descriptors as (
    select 1 from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public' and c.relkind in ('r', 'p', 'S', 'v', 'm')
    union all
    select 1 from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
      join pg_attribute a on a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
      where n.nspname = 'public' and c.relkind in ('r', 'p', 'v', 'm')
    union all
    select 1 from pg_constraint con
      join pg_class c on c.oid = con.conrelid
      join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public'
    union all
    select 1 from pg_index idx
      join pg_class c on c.oid = idx.indrelid
      join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public'
    union all
    select 1 from pg_trigger tr
      join pg_class c on c.oid = tr.tgrelid
      join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public' and not tr.tgisinternal
    union all
    select 1 from pg_trigger tr
      join pg_class c on c.oid = tr.tgrelid
      join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public' and tr.tgisinternal
      group by tr.tgenabled
    union all
    select 1 from pg_policy pol
      join pg_class c on c.oid = pol.polrelid
      join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public'
    union all
    select 1 from pg_proc proc
      join pg_namespace n on n.oid = proc.pronamespace
      where n.nspname = 'public'
    union all
    select 1 from pg_type typ
      join pg_namespace n on n.oid = typ.typnamespace
      where n.nspname = 'public'
        and typ.typtype in ('d', 'e', 'm', 'r')
        and typ.typrelid = 0
    union all
    select 1 from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public' and c.relkind in ('v', 'm')
    union all
    select 1
  )
  select count(*)::text as "entryCount" from descriptors
`;

const SCHEMA_CATALOG_DESCRIPTOR_SQL = `
  with descriptors as (
    select jsonb_build_array(
      'relation', n.nspname, c.relname, c.relkind, c.relpersistence,
      c.relispartition, c.relrowsecurity, c.relforcerowsecurity, c.relreplident,
      coalesce(c.reloptions::text, ''), coalesce(pg_get_expr(c.relpartbound, c.oid, false), ''),
      coalesce(pg_get_partkeydef(c.oid), '')
    )::text as descriptor
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind in ('r', 'p', 'S', 'v', 'm')

    union all
    select jsonb_build_array(
      'column', n.nspname, c.relname, a.attnum, a.attname,
      format_type(a.atttypid, a.atttypmod), a.attnotnull, a.attidentity,
      a.attgenerated, a.attstorage, a.attcompression,
      case when a.attcollation = 0 or a.attcollation = typ.typcollation then ''
        else coll_namespace.nspname || '.' || coll.collname end,
      coalesce(pg_get_expr(attr_default.adbin, attr_default.adrelid, false), '')
    )::text
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    join pg_attribute a on a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
    join pg_type typ on typ.oid = a.atttypid
    left join pg_attrdef attr_default on attr_default.adrelid = c.oid and attr_default.adnum = a.attnum
    left join pg_collation coll on coll.oid = a.attcollation
    left join pg_namespace coll_namespace on coll_namespace.oid = coll.collnamespace
    where n.nspname = 'public' and c.relkind in ('r', 'p', 'v', 'm')

    union all
    select jsonb_build_array(
      'constraint', n.nspname, c.relname, con.conname, con.contype,
      con.condeferrable, con.condeferred, con.convalidated, con.conislocal,
      con.coninhcount, con.connoinherit, pg_get_constraintdef(con.oid, false)
    )::text
    from pg_constraint con
    join pg_class c on c.oid = con.conrelid
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public'

    union all
    select jsonb_build_array(
      'index', n.nspname, table_class.relname, index_class.relname,
      idx.indisunique, idx.indisprimary, idx.indisexclusion,
      idx.indimmediate, idx.indisclustered, idx.indisvalid, idx.indcheckxmin,
      idx.indisready, idx.indislive, idx.indisreplident, idx.indnullsnotdistinct,
      pg_get_indexdef(idx.indexrelid, 0, false)
    )::text
    from pg_index idx
    join pg_class table_class on table_class.oid = idx.indrelid
    join pg_namespace n on n.oid = table_class.relnamespace
    join pg_class index_class on index_class.oid = idx.indexrelid
    where n.nspname = 'public'

    union all
    select jsonb_build_array(
      'trigger', n.nspname, c.relname, tr.tgname, tr.tgenabled,
      pg_get_triggerdef(tr.oid, false)
    )::text
    from pg_trigger tr
    join pg_class c on c.oid = tr.tgrelid
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and not tr.tgisinternal

    union all
    select jsonb_build_array('internal-trigger-state', tr.tgenabled, count(*))::text
    from pg_trigger tr
    join pg_class c on c.oid = tr.tgrelid
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and tr.tgisinternal
    group by tr.tgenabled

    union all
    select jsonb_build_array(
      'policy', n.nspname, c.relname, pol.polname, pol.polpermissive, pol.polcmd,
      coalesce((
        select jsonb_agg(role_name order by role_name)
        from (
          select role.rolname as role_name
          from unnest(pol.polroles) role_oid
          join pg_roles role on role.oid = role_oid
        ) roles
      ), '[]'::jsonb),
      coalesce(pg_get_expr(pol.polqual, pol.polrelid, false), ''),
      coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid, false), '')
    )::text
    from pg_policy pol
    join pg_class c on c.oid = pol.polrelid
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public'

    union all
    select jsonb_build_array(
      'function', n.nspname, proc.proname, pg_get_function_identity_arguments(proc.oid),
      proc.prokind, proc.prosecdef, proc.proleakproof, proc.provolatile, proc.proparallel,
      pg_get_functiondef(proc.oid)
    )::text
    from pg_proc proc
    join pg_namespace n on n.oid = proc.pronamespace
    where n.nspname = 'public'

    union all
    select jsonb_build_array(
      'type', n.nspname, typ.typname, typ.typtype, typ.typcategory,
      format_type(typ.typbasetype, typ.typtypmod), typ.typnotnull,
      coalesce(typ.typdefault, ''),
      coalesce((
        select jsonb_agg(enum.enumlabel order by enum.enumsortorder)
        from pg_enum enum where enum.enumtypid = typ.oid
      ), '[]'::jsonb)
    )::text
    from pg_type typ
    join pg_namespace n on n.oid = typ.typnamespace
    where n.nspname = 'public'
      and typ.typtype in ('d', 'e', 'm', 'r')
      and typ.typrelid = 0

    union all
    select jsonb_build_array('view', n.nspname, c.relname, pg_get_viewdef(c.oid, false))::text
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind in ('v', 'm')

    union all
    select jsonb_build_array(
      'catalog-format', ${SCHEMA_CATALOG_FORMAT}, current_setting('server_version_num')::integer / 10000
    )::text
  )
  select descriptor from descriptors order by descriptor limit $1
`;
