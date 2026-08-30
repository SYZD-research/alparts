# Architecture decision records

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](./0001-storage.md) | PostgreSQL authority + S3 ciphertext objects | Accepted |
| [0002](./0002-consistency.md) | Local transactions, locks and restart-safe cross-store workflow | Accepted |
| [0003](./0003-tenancy.md) | Shared-schema workspace tenancy with fail-closed IDs and quotas | Accepted for Phase 1 |
| [0004](./0004-deployment-and-ha.md) | Explicit one-process support boundary and capability levels | Accepted |
| [0005](./0005-backup-and-recovery.md) | Quiesced encrypted backup and isolated restore | Accepted interim |
| [0006](./0006-observability.md) | Structured logs, protected metrics and trace correlation | Accepted |
| [0007](./0007-authentication.md) | Invite-gated password/session/device model | Accepted interim |
| [0008](./0008-authorization.md) | Central bounded authorization snapshots and locked recheck | Accepted |
| [0009](./0009-audit-witness.md) | Atomic DB audit chain plus external single-process witness | Accepted interim |
| [0010](./0010-schema-image-coupling.md) | Exact migration journal plus bounded PostgreSQL 16 catalog fingerprint | Accepted for Phase 1 |

ADRs describe deliberate decisions, including their limits. They do not override current code, tests, risk register, or deployment acceptance evidence.
