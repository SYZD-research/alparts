# ADR 0010: Runtime schema and image coupling

Status: Accepted for the PostgreSQL 16 Phase 1 runtime

## Context

An applied-migration journal proves which migration files were recorded, but it does not prove that a later operator or failed repair did not drop a column, constraint, index, trigger, policy, function, or type while leaving that journal intact. Starting an application against that drift can silently remove a durable security invariant.

## Decision

- The OCI artifact carries the exact ordered SQL bundle and journal used at build time. A separate, advisory-locked migrator applies that bundle.
- Startup and readiness open a repeatable-read, read-only transaction with `search_path=pg_catalog` and require both:
  - an exact timestamp/SHA-256 match for every migration record; and
  - an exact bounded fingerprint of the PostgreSQL 16 `public` catalog after migrations `0000` through `0013`.
- The catalog descriptor covers public relations, columns/defaults/types, constraints, indexes and their validity state, non-internal triggers, aggregate internal-trigger enablement, row policies, functions, custom types, and views. More than 4,096 descriptors fails closed before materialization.
- The application database must be dedicated to Alparts and must not contain unrelated objects in `public`. A schema migration must deliberately regenerate, review, and update the expected catalog fingerprint and its negative integration test.

## Consequences

Persistent catalog drift, including a dropped foreign key with an intact migration journal, makes startup/readiness fail closed. Replaying the same migration bundle remains idempotent, and an older/newer unknown schema cannot be silently accepted.

This deliberately pins the current runtime contract to PostgreSQL major version 16 and its catalog rendering. A PostgreSQL major upgrade is a reviewed migration, restore rehearsal, fingerprint update, and compatibility release—not an in-place configuration toggle.

The fingerprint does not validate row contents, PostgreSQL role memberships/grants, extensions or objects outside `public`, physical durability settings, replication correctness, or a malicious database administrator who can alter and restore state between probes. Least privilege, infrastructure monitoring, backup/restore, audit evidence, and database integrity checks remain separate controls.
