# ADR 0008: Central bounded authorization snapshots

- **Status:** Accepted
- **Date:** 2026-08-30

## Context

Calling a DB-backed authorization loader once per returned item or per channel-member pair multiplies queries and makes revocation races difficult. Duplicating permission logic across REST and Socket.IO invites bypasses.

## Decision

Centralize workspace/channel authorization. Load one explicitly bounded workspace snapshot with a fixed query set, validate tenant invariants, then evaluate individual channel/user outcomes purely in memory. For lists and viewer-impact mutations, load/evaluate under the relevant workspace lock and use authorization revisions for client previews. Transport layers must call this policy rather than reconstruct it.

## Consequences

- Query work is predictable at the declared small-team limits and semantics stay consistent.
- Snapshot shape/caps are a security contract; raising limits requires load/query review.
- Any alternate route, WebSocket grant, job or cache must use the same live policy and tenant context.
