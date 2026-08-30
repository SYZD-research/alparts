# ADR 0001: PostgreSQL authority and S3 ciphertext storage

- **Status:** Accepted
- **Date:** 2026-08-30 (documents existing design)

## Context

Identity, authorization, idempotency, message events and key epochs need relational constraints and transactions. Encrypted attachment chunks can be large and need streaming/object semantics. Requiring Kubernetes, a broker or a distributed database would add failure modes without solving the current small-team boundary.

## Decision

Use PostgreSQL as the sole authoritative state store and source of authorization truth. Store only encrypted attachment chunk bytes in an S3-compatible service; keep their reservation/chunk/finalization metadata in PostgreSQL. Keep browser private keys and plaintext outside both server stores.

## Consequences

- Relational constraints/locks can preserve tenant and protocol invariants.
- Object storage can scale independently and is treated as untrusted for content integrity/confidentiality.
- PostgreSQL and object storage have no common transaction, so ADR 0002's state machine and quiesced backup are required.
- No separate cache/broker is currently necessary; if added, it must never become an unscoped authorization authority.
