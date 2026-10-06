# ADR 0009: PostgreSQL audit chain plus external witness

- **Status:** Accepted interim for one process
- **Date:** 2026-08-30

## Context

Writing an audit record after a state transaction can omit evidence. A chain only in the same database cannot detect tail deletion by that database authority. An external checkpoint cannot be transactionally committed with PostgreSQL, and returning failure after DB commit can cause unsafe caller retries.

## Decision

Append security-sensitive state and HMAC-chained audit rows in one PostgreSQL transaction under a global advisory lock. Message create/edit/delete/replay, reaction/pin, preferences/bookmarks, attachments and management operations are in this path without recording content, ciphertext or signatures. Route high-frequency/provisional authoritative state (read cursors and upload-chunk registration/cleanup) through the same serialized admission gate without a dedicated event. After an audited commit, atomically/fsync advance an HMAC-authenticated external checkpoint. If checkpoint advancement fails, return the already committed result truthfully once, latch failure, fail readiness and deny all later authoritative mutations in either path until the missed checkpoint is written. A transient I/O failure is retried, at most every 2 seconds and with the same chain checks, by the next mutation or readiness probe; an integrity failure stays latched for the operator. Presence and device activity timestamps are advisory, are never authorization inputs, and intentionally remain outside this gate. On startup, verify the chain and prior checkpoint descendant relation. Initial provisioning is an explicit stopped-service operator action.

## Consequences

- Missing/rolled-back witness and DB tail truncation are detected under separated authority.
- A crash may leave DB ahead of the witness; restart may advance only through an intact verified descendant chain.
- The shared one-active/64-pending admission boundary is a deliberate correctness bottleneck. Presence cannot consume it, but accepted message/state write throughput must be measured before raising scale.
- Same-host/same-operator placement is not independence. No WORM receipt/non-repudiation exists.
- Multiple app processes are unsupported until an external durable multi-writer compare-and-swap witness and fencing replace process-local admission.
