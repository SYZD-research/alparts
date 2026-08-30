# ADR 0005: Quiesced encrypted backup and isolated restore

- **Status:** Accepted interim
- **Date:** 2026-08-30

## Context

DB and object bytes must represent one usable point, but they have no common snapshot. Restore tools are dangerous when they can target existing/production resources. A backup without a restore test is not evidence of recoverability.

## Decision

Stop all application writers, take a serializable PostgreSQL custom dump and mirror latest object bytes, inventory/checksum/reference them under private temporary storage, and publish only an age-recipient-encrypted non-overwriting artifact. Restore only to narrowly named empty targets owned by an unprivileged role; validate archive path/type/logical size, checksums, rows, references and re-downloaded object bytes. Schedule single-host backups and safe retention, while requiring off-host copy and exercises operationally.

## Consequences

- Strong data-level restore verification with low automation complexity.
- Backup causes a service window and currently targets RPO 24h only when copied independently.
- No PITR, WORM, automatic failover, object versions/policy or browser-key recovery.
- A future online/PITR design must define a consistent DB/object recovery point and preserve these safety gates.
