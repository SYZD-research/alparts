# Disaster recovery

Last verified: 2026-08-30

## Current recovery posture

The repository can create an encrypted, checksummed snapshot of a quiesced PostgreSQL database plus the latest encrypted object bytes from the object store, then restore and compare it only in narrowly named, empty, unprivileged disposable targets. A systemd timer can automate local creation and bounded retention.

This is a recovery building block, not automatic DR. The repository does not provide PostgreSQL PITR/WAL archive, object-store version replication/object lock, automatic off-host/off-region copy, DNS failover, spare-host provisioning, or recovery of browser private keys. The current application topology is single-process and single-region.

## Recovery objectives

- Baseline single-host objective: RPO 24 hours and RTO 8 hours, only after daily artifacts are copied to independent storage and a full exercise meets those numbers.
- Current evidence: data-level isolated restore verification exists; full application RTO/RPO is not yet measured. Therefore these are objectives, not guarantees.
- With operator-supplied continuous PostgreSQL WAL and versioned/replicated object storage, a lower RPO may be designed, but DB and object recovery points must be reconciled and tested together.
- A same-host backup does not protect against host destruction or ransomware. Without a verified independent copy, host-loss RPO is undefined.

## Assets that must be recoverable

| Asset | Primary | Recovery copy | Notes |
| --- | --- | --- | --- |
| PostgreSQL rows/schema | database | encrypted backup; optional externally managed WAL archive | restore into a new empty DB, never over the damaged source |
| Attachment ciphertext | object store | encrypted backup; optional versioned replica | backup contains latest bytes, not bucket policy/version history |
| Audit checkpoint | independent protected path | separately encrypted/off-host evidence copy | preserve authority separation and correlate with DB chain |
| Audit integrity key | systemd/Docker secret provider | separately encrypted escrow | loss makes historic chain unverifiable; do not store only beside DB dump |
| Runtime/backend credentials | secret provider | revocable escrow/reissue procedure | prefer rotation over restoring a suspected compromised credential |
| Age recovery identity | offline custody | independently controlled escrow | never place on application host merely for convenience |
| Reverse proxy/config/unit/image digest/SBOM | configuration/release system | versioned signed operating bundle | repository does not yet produce signed releases |
| Browser device keys/channel state | each endpoint | no server copy by design | server restore may not restore historical decryptability for a lost endpoint |

## Backup policy

1. Run daily through `alparts-backup.timer` or an equivalent orchestrator.
2. Quiesce every application writer for the whole DB+object snapshot. The supplied wrapper stops exactly one active systemd service and always attempts restart.
3. Encrypt to an offline-controlled age recipient; keep staging on protected capacity with strict quotas.
4. Atomically publish without overwrite, record artifact SHA-256 and run ID in an independently authenticated inventory.
5. Copy completed ciphertext to at least one off-host failure domain; for region recovery, maintain an off-region copy. Prefer versioning/object lock and a write-only backup identity.
6. Retain a minimum of 7 daily copies for 30 days by default. The pruning tool is dry-run by default, refuses broad targets, only matches exact artifact names, and requires an explicit acknowledgement to delete.
7. Restore-verify a selected backup to an isolated DB/bucket at least monthly. Run a full application/audit/client decrypt exercise at least quarterly and after material storage/migration changes.

See [the exact backup contract](../BACKUP.md).

## Recovery decision

Do not overwrite the failed environment. Establish incident scope first:

- For a bad binary with compatible data, roll back to a previous immutable image.
- For a failed uncommitted migration, fix forward after inspecting the transaction state.
- For logical deletion/corruption, stop writers and restore a verified backup into new empty dependencies; compare/merge or cut over under an approved plan.
- For host/ransomware/credential compromise, rebuild on clean infrastructure and rotate credentials before importing data.
- For audit checkpoint inconsistency, preserve both DB and checkpoint. Do not initialize a replacement witness until the known-good chain/timeline is independently established.

## Full recovery sequence

1. Declare incident, stop ingress and all writers, record UTC time and suspected last-good point.
2. Isolate compromised assets; preserve database/object snapshots, audit checkpoint, logs, image/config digests and backup inventory as evidence.
3. Select an independently stored artifact by digest; restore with `scripts/restore-verify.sh` into the required empty/unprivileged targets.
4. Validate row counts, object references and bytes, the exact bundled migration journal and PostgreSQL 16 catalog fingerprint, then validate the audit chain with the escrowed integrity key and the known-good external checkpoint.
5. Deploy the exact compatible immutable application build and configuration. Apply only migrations that are known compatible with the restored schema.
6. Run startup/readiness, authenticated synthetic read/write, authorization-isolation, attachment roundtrip, audit append/checkpoint, and selected client decrypt checks.
7. Rotate credentials if exposure is possible; revoke sessions/devices as required. Each conversation's group must remove a revoked device before anyone writes there again; an online member's client does this automatically. A restore that predates group commits some devices already followed makes those devices stop for the affected conversations as a suspected rollback; register those devices again.
8. Put traffic through a controlled gate, observe error/saturation/correctness, then complete cutover.
9. Create a new verified backup, update off-host inventory, and retain old evidence. Record actual RPO/RTO and corrective work.

## DR exercises

Each exercise records artifact/image/config digests, operators/approvals, start/end in UTC, fault injected, rows/objects/audit/client checks, data lost, service unavailable time, and any manual step. Minimum scenarios:

- destroyed application host with surviving off-host backup;
- corrupted/latest unusable backup requiring an older generation;
- PostgreSQL loss with object store retained;
- object-store loss with PostgreSQL references retained;
- expired TLS certificate and backend credential rotation;
- bad migration/binary rollback decision;
- deleted or inconsistent audit checkpoint;
- region loss into a clean environment, once off-region assets exist.

A data restore that never starts the application is not a completed DR exercise.
