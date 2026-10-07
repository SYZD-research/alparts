# Migrations

Migrations are applied by `db:migrate:runtime` (`src/scripts/migrate-runtime.ts`)
from `meta/_journal.json` and the numbered SQL files. The runtime schema gate
fingerprints the journal, the SQL and the resulting PostgreSQL catalog
(`src/db/schema-catalog.ts`); update `expectedSchemaCatalog` whenever a
migration changes the schema.

Several migrations (0009–0020) are written by hand because they contain
triggers, functions and data backfills that drizzle-kit cannot express, so
`meta/` has no snapshots for 0009–0017. `meta/0018_snapshot.json` through `meta/0023_snapshot.json` were generated
from `src/db/schema.ts`, so `drizzle-kit generate` diffs against the current
table model instead of the stale 0008 snapshot. Always review generated SQL:
the snapshot does not describe triggers or functions. Never use `db:push`
against a real database.
