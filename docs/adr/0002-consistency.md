# ADR 0002: Transaction and cross-store consistency

- **Status:** Accepted
- **Date:** 2026-08-30

## Context

Membership, role, key, message and audit changes must remain consistent under concurrency. Holding a DB lock while performing remote object I/O causes pool starvation and cascading failure. PostgreSQL and MinIO cannot commit atomically.

## Decision

Use PostgreSQL transactions, uniqueness and scoped advisory locks for durable invariants. Recheck authorization inside the mutation lock. Use bounded bulk snapshots for viewer calculations. For attachment bytes, use a reservation/chunk/finalize state machine: commit intent, release DB resources, perform remote I/O with deadline, then lock/revalidate/commit metadata. Use conservative bounded cleanup for abandoned state.

## Consequences

- DB failures roll back cleanly and retries can use stable idempotency.
- Orphan objects or reservations can exist after a crash and require cleanup/reconciliation.
- Generic transaction retries are prohibited; any retry needs operation-specific duplicate safety.
- Multi-region writes need a new fencing/conflict ADR rather than stretching local advisory locks.
