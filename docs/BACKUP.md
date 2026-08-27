# Phase 1 backup and restore verification

The scripts in `scripts/` create one recipient-encrypted backup of PostgreSQL and the MinIO bucket, then restore and verify it only in explicitly disposable targets. They are for the Phase 1 single-node deployment. They are not a production disaster-recovery system.

## Safety boundary

- Stop all application writes for the entire backup. The database dump is a consistent PostgreSQL custom-format snapshot, but PostgreSQL and MinIO do not share a transaction. `ALPARTS_BACKUP_QUIESCED=YES_WRITES_ARE_STOPPED` is an explicit operator assertion; the script does not stop the service itself.
- Use a short-lived, read-only backup identity where possible. The MinIO identity needs `GetBucketLocation`, `ListBucket`, and `GetObject` on the source bucket. PostgreSQL needs enough read access for a complete `pg_dump`.
- The plaintext dump, object bytes, inventory, checksums, and manifest exist only below a mode-`0700` `mktemp` directory and are removed by a trap. The published artifact is mode `0600` and encrypted to an `age` recipient public key.
- Point `TMPDIR` at an adequately sized encrypted local filesystem (or appropriately sized protected tmpfs). The trap covers normal exit, errors, HUP, INT, and TERM; no process can clean up after `SIGKILL`, power loss, or storage-device failure, and ordinary unlinking is not a secure-erasure guarantee on SSDs or snapshots.
- The artifact includes ciphertext attachment objects, but object names, sizes, and database metadata remain sensitive and are therefore protected by the outer `age` encryption.
- The server's `AUDIT_INTEGRITY_KEY`, external audit checkpoint file, deployment credentials, reverse-proxy configuration, and browser device private keys are not included. Back up the audit key, checkpoint evidence, and deployment configuration as separately encrypted assets with independent access control. Browser device private keys intentionally remain client-held.
- `age` recipient encryption supplies confidentiality and payload integrity, not proof of who created the backup: anyone with the public recipient can create a different valid artifact. Protect the delivery channel and record the encrypted artifact digest in an independently authenticated system when provenance matters.

Install `pg_dump` matching the source PostgreSQL server major and `pg_restore` matching the verification server major, plus `psql`, `mc` with `alias import` support, `age`, `jq`, GNU `tar`, and normal GNU core utilities on the backup host. The scripts check the PostgreSQL tool/server major versions before dump or restore; this prevents newer clients from emitting session settings an older target does not understand. Both scripts fail before doing work when a dependency or required setting is missing. Secret values marked as such can be passed as `*_FILE`; those files must have no group/other permission bits.

PostgreSQL access uses a mode-`0600` [libpq service file](https://www.postgresql.org/docs/current/libpq-pgservice.html). Only its path and selected section name reach PostgreSQL child processes; the script does not parse a connection URI or put a password in argv or the child environment. MinIO credentials are imported over stdin into the mode-`0700`, trap-cleaned `mc` configuration, and loaded secret settings are removed from the inherited child environment. Neither script enables shell tracing or prints configured credentials. Use authenticated TLS for remote PostgreSQL and MinIO endpoints; plain HTTP MinIO URLs are accepted only on loopback.

## Create a backup

Create an age identity offline and distribute only its recipient public key to the backup host. Keep the identity outside the application node.

With application writes already stopped:

```bash
# /run/credentials/alparts-backup-pg-service.conf (mode 0600):
# [alparts_backup]
# host=db.internal.example
# port=5432
# dbname=alparts
# user=alparts_backup
# password=replace-with-the-backup-role-password
# sslmode=verify-full
# sslrootcert=/run/credentials/postgresql-ca.pem
export DATABASE_SERVICE_FILE=/run/credentials/alparts-backup-pg-service.conf
export DATABASE_SERVICE=alparts_backup
export MINIO_URL=https://minio.internal.example
export MINIO_ACCESS_KEY_FILE=/run/credentials/alparts-backup-minio-access-key
export MINIO_SECRET_KEY_FILE=/run/credentials/alparts-backup-minio-secret-key
export MINIO_BUCKET=alparts
export BACKUP_AGE_RECIPIENT=age1example_replace_with_the_real_recipient
export BACKUP_OUTPUT_DIR=/mnt/encrypted-backups
export ALPARTS_BACKUP_QUIESCED=YES_WRITES_ARE_STOPPED

scripts/backup.sh
```

The only standard-output line is the final artifact path. The encrypted payload contains:

- one PostgreSQL custom-format dump made with `--serializable-deferrable`;
- the latest bytes for every object mirrored from the configured bucket;
- table row counts, attachment/object references, an object inventory, SHA-256 checksums, tool versions, one run ID, and one UTC creation time.

The script refuses to replace an existing output. Publication uses an atomic hard link in the output filesystem, so even a same-name race cannot cause an overwrite.

## Restore and verify

Provision a new empty database and a new empty bucket on an isolated verification PostgreSQL/MinIO deployment, never on the production endpoints. The safety checks deliberately accept only these names:

- database: `alparts_restore_<suffix>` or `alparts_verify_<suffix>`;
- bucket: `alparts-restore-<suffix>` or `alparts-verify-<suffix>`.

Use a dedicated target database owner with no superuser, `CREATEROLE`, `CREATEDB`, replication, `BYPASSRLS`, server-file, or server-program privilege. The script rejects a role that has or can assume those privileges. Give the verification MinIO identity access only to the named disposable bucket.

Names containing `prod`, `production`, `live`, or `primary` are rejected. The default `alparts` bucket and a target bucket whose name equals the source bucket are also rejected. A matching name is not sufficient: the script also queries PostgreSQL for non-system schemas and objects and recursively lists the bucket, and refuses either target unless it is empty. MinIO folder-marker objects are refused rather than silently omitted.

Run the verification with exclusive access to both disposable targets:

```bash
# Use a separate mode-0600 service file containing an alparts_verify section
# for the unprivileged owner of the disposable database.
export VERIFY_DATABASE_SERVICE_FILE=/run/credentials/alparts-verify-pg-service.conf
export VERIFY_DATABASE_SERVICE=alparts_verify
export VERIFY_MINIO_URL=https://minio-verify.internal.example
export VERIFY_MINIO_ACCESS_KEY_FILE=/run/credentials/alparts-verify-minio-access-key
export VERIFY_MINIO_SECRET_KEY_FILE=/run/credentials/alparts-verify-minio-secret-key
export VERIFY_MINIO_BUCKET=alparts-verify-20260826
export RESTORE_AGE_IDENTITY_FILE=/run/credentials/alparts-backup-age-identity
export ALPARTS_RESTORE_ACK=RESTORE_TO_EMPTY_DISPOSABLE_TARGETS

# Optional policy limits; defaults shown.
export RESTORE_MAX_BYTES=1099511627776
export RESTORE_MAX_ARCHIVE_ENTRIES=1000000
export RESTORE_MAX_FILE_BYTES=1099511627776
export RESTORE_MAX_EXPANDED_BYTES=1099511627776

scripts/restore-verify.sh /mnt/encrypted-backups/alparts-backup-<run-id>.tar.age
```

Before filesystem extraction, the script validates the age envelope and bounds the decrypted archive's logical entry count, each expanded regular-file size, and aggregate expanded bytes. GNU tar's logical sizes are used rather than the compact stored size, and compact sparse or unsupported encodings are refused when detected. All four resource-limit settings must be positive integers of at most 18 digits, and the per-file limit cannot exceed the aggregate limit. Set the byte limits below both the filesystem quota and safely available capacity of the protected staging volume; the 1 TiB defaults are protocol ceilings, not a capacity recommendation. The script then validates archive paths and entry types, payload checksums, object inventory, attachment references, custom dump readability, target names, and target emptiness. `pg_restore` runs in a single transaction without `--clean`, ownership restoration, or privilege restoration. The script then copies objects into the still-empty verification bucket, downloads them again, and compares every key, byte size, and SHA-256 checksum. It also compares all database table counts and attachment references with the source snapshot.

The script never drops a schema, clears a bucket, runs a migration, or cleans up a partially failed target. If another actor can write to the verification bucket concurrently, the empty-target precondition cannot be guaranteed; isolate the credentials and bucket for this run.

## Migration gate

Use the wrapper after stopping writes and before applying a migration:

```bash
scripts/pre-migration-backup.sh 0006_example_change
```

It only records a `pre-migration:<label>` reason and creates the encrypted artifact. It never runs the migration. Restore and verify that artifact with `restore-verify.sh`; only after a successful `VERIFIED <run-id>` result should a separate deployment step apply the migration.

## Limitations

This workflow backs up one quiesced logical database snapshot and the latest object bytes. It does **not** provide:

- point-in-time recovery (PITR) or continuous WAL archiving;
- WORM/object-lock retention or protection from a compromised backup identity;
- automatic off-site replication, retention rotation, or media lifecycle management;
- automatic recovery, failover, RTO/RPO guarantees, or a tested full application DR exercise;
- MinIO object version history, bucket policies, lifecycle rules, tags, or all object metadata;
- server-side recovery of browser device private keys.

Copy the encrypted artifact to independently controlled off-site storage, implement retention separately, and schedule restore exercises. A successful script result proves that this artifact can recreate its database rows and latest encrypted object bytes in the tested targets; it does not prove full service recovery or client-side decryptability.
