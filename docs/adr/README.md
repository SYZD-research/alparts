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
| [0011](./0011-account-group-security.md) | Approved devices, transparency, MLS-based epochs, passkeys and user-controlled recovery | Implemented; assurance pending; group protocol superseded by 0012 |
| [0012](./0012-continuous-mls-groups.md) | One continuing MLS group per channel; server-ordered commits active on acceptance, replacing the all-recipient barrier | Implemented; assurance pending |
| [0013](./0013-signed-message-references.md) | Edits, deletions, quotes and forum replies name the referenced message by its author and signed idempotency key (message protocol v5) | Implemented; assurance pending |
| [0014](./0014-sfu-frame-encryption.md) | SFU calls encrypt every audio frame (SFrame) under per-call sender keys, wrapped and signed per device and replaced on every join and leave | Implemented; assurance pending |

ADRs describe deliberate decisions, including their limits. They do not override current code, tests, risk register, or deployment acceptance evidence.
