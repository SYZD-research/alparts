# Phase 1 Prototype operations

English | [日本語](OPERATIONS.ja.md)

Last updated: 2026-09-04

This document covers only the prototype: Windows, macOS and Linux desktop / Web / single node / basic per-channel keys / mainly text, plus voice for up to eight people (peer-to-peer, or through the self-hosted SFU with frames encrypted end to end). It is not a production approval for handling embargoed vulnerabilities, credentials or other high-impact secrets.

## Startup contract

1. Prepare separate least-privilege credentials for PostgreSQL and object storage (SeaweedFS is recommended), and use authenticated TLS for remote connections.
2. Pass secrets through `*_FILE`, systemd credentials or a deployment secret manager. Never put the values in the repository, an image, a command line or logs.
3. Run migrations with a deployment identity separate from the application runtime, with application writes stopped. Before irreversible changes, go through the backup gate described below.
4. Start the process as a non-root user, and terminate public TLS at a trusted reverse proxy. Do not expose PostgreSQL, object storage, probes or management endpoints to the public network.
5. Route the probes separately.

   - `/health/startup`: whether startup has completed.
   - `/health/live`: whether the process event loop can handle HTTP.
   - `/health/ready`: whether the process is not draining and PostgreSQL, the configured object storage bucket (checked every time, so a bucket that disappears after startup is noticed) and the audit checkpoint are available.

Before it starts listening, the process verifies the whole audit HMAC chain. A failure is a security incident. Never rewrite or delete audit rows or checkpoints to make the server start.

The server's listen address accepts only IP literals and is limited to `127.0.0.1` when `BIND_HOST` is not set. The example systemd unit is also fixed to loopback. The container image defaults to loopback as well; only the production Compose file sets `BIND_HOST=0.0.0.0` explicitly inside the container network and publishes it to `127.0.0.1` on the host. Always put a TLS reverse proxy and network policy in front. Requests to object storage have an absolute deadline of `S3_REQUEST_TIMEOUT_MS` (10 seconds by default), and object listings are also bounded in count, key bytes, prefix grammar and absolute deadline. Attachment downloads check the length of the GET response against the size recorded at upload and never send the client more bytes than that size.

New registrations send a 6-digit verification code to the email address entered (valid for 15 minutes, invalidated after five wrong attempts) to confirm that the person owns the address. Set `SMTP_HOST` and `SMTP_FROM` (and `SMTP_USER` and `SMTP_PASSWORD_FILE` if needed) for sending. In production, `SMTP_SECURE=true` (TLS from the start) or STARTTLS is required, and certificates are verified. If `SMTP_HOST` is not set in production, existing accounts can still sign in, but new registrations are refused unless verification is explicitly turned off with `EMAIL_VERIFICATION=disabled`, and a `registration.unavailable` warning is logged at startup. In development, without SMTP, emails are kept in memory and written to the log. An address that already has an account receives a notice instead of a code, so the response does not reveal whether an account exists. Email addresses of accounts created before this change have not been verified.

Registration emails are written in English or Japanese. The client sends the language chosen in the app as `Accept-Language`, and the server uses the first supported language in it, falling back to English. No setting is needed.

Voice calls can use up to four operator-controlled STUN/TURN servers set as JSON in `VOICE_ICE_SERVERS_JSON`. The default empty array never connects to a third-party service, but in exchange it does not guarantee calls between NATs that direct candidates cannot reach. TURN credentials are handed to the clients in the call, so never reuse service administrator credentials; issue short-lived, least-privilege credentials. Prefer authenticated TLS (`turns:`) for TURN, and do not open it to the public Internet as an unrestricted relay. The peer-to-peer mesh is limited to eight people; it is not a media server that scales horizontally.

Setting `VOICE_SFU_ENABLED=true` routes every call of the deployment through the server's own mediasoup SFU instead of the peer-to-peer mesh; the setting takes effect when the server starts. Clients encrypt each audio frame before it leaves the device and replace their keys whenever someone joins or leaves ([ADR 0014](./adr/0014-sfu-frame-encryption.md)), so the SFU forwards only ciphertext. Browsers that cannot encrypt frames cannot join calls, and the app tells the user so. Set `VOICE_SFU_ANNOUNCED_ADDRESS` to the address clients reach the server on, and allow UDP and TCP to `VOICE_SFU_BASE_PORT` and the following ports, one per worker (`VOICE_SFU_WORKERS`). Keep these ports out of the host's ephemeral port range (on Linux `net.ipv4.ip_local_port_range`, by default 32768–60999, which includes 40000), or reserve them with `net.ipv4.ip_local_reserved_ports`: otherwise another program's short-lived socket can hold a port when the first call starts on that worker, and that call fails (the next call tries the same port again). Peers no longer see each other's network addresses, but the server still sees who is in a call and when each participant speaks. Calls stay limited to eight people.

An attachment's database row and its object in object storage are not a distributed transaction. The upload status takes a snapshot of authorization and chunk metadata in the database, releases the database connection and lock, and then checks the objects. Later chunk PUT and finalize steps acquire the lock and authorization again. Objects left behind after a database failure are collected by expiry cleanup, and a ciphertext stream that has already started cannot be recalled if access is lost after the download begins. Do not describe these as an atomic cross-store commit or remote erasure.

## Audit checkpoint

From 2026-09-30, in addition to the local checkpoint, the latest signed head is kept in a separate object storage bucket. Set `AUDIT_HEAD_BUCKET` (`${S3_BUCKET}-audit` by default) and `AUDIT_HEAD_OBJECT_KEY` (an identifier fixed for each deployment). A normal startup never creates a missing head. Even if both the database and the checkpoint file are rolled back, the restart is refused as long as this head is kept.

Audit head migration procedure (existing deployments):

1. Stop the app and confirm that the independently kept record matches the current audit chain. The HMAC check in the initialization command alone cannot detect a correctly signed truncation of the tail that happened before the migration.
2. Create an `AUDIT_HEAD_BUCKET` separate from the one for ordinary pictures and attachments. Allow the app `s3:GetBucketLocation` and `s3:ListBucket` on this bucket and `s3:GetObject` and `s3:PutObject` on the head object. Delete permission is not needed. Do not give rewrite or delete permission on the head to the people who repair the database or checkpoint file, or to the identity used for restoring backups.
3. Save the fixed `AUDIT_HEAD_OBJECT_KEY` and the bucket in the environment settings, and run `pnpm --filter @alparts/server audit:head:init` once with the same database, audit key and checkpoint path as normal. In the distributed image, run `node packages/server/dist/scripts/initialize-audit-head.js`. An existing head is never overwritten. New deployments create both with `audit:checkpoint:init`.
4. Restart and check readiness. From then on, do not change the identifier or bucket between starts, do not restore the head to an earlier point together with ordinary data backups, and do not rerun the initialization automatically when the head is missing.

Updates happen in this order: database commit → fsync and rename of the local checkpoint → saving the head. A failure part-way stops the next write. When the local checkpoint is ahead of the head, it is moved forward only after verifying the whole chain and both anchors at restart. Reads of the checkpoint and head are also serialized with audit writes, so a normal concurrent update is never mistaken for a rollback.

This additional bucket is not WORM. An administrator who can write back the database, the local file and the head together, or a compromise of the whole server, is a different capability, and local verification alone cannot detect a simultaneous rollback. An independent witness can still be used. The existing limits for a commit that stopped before the head was saved, and for records after the witness, remain. Ordinary backup and restore handle only `S3_BUCKET`, so the head is not included and must be preserved independently.

To detect deletion of the newest audit row in the database, place `AUDIT_CHECKPOINT_PATH` on a mount or storage whose write and delete authority is separate from the PostgreSQL operator. The file is authenticated with an HMAC and updated atomically after each audit commit. For a first deployment, with the server stopped, set the same database, `AUDIT_INTEGRITY_KEY` and checkpoint path as production and run `pnpm --filter @alparts/server audit:checkpoint:init` exactly once. Then start the server with `AUDIT_CHECKPOINT_REQUIRED=true`. If a checkpoint already exists, this command does not overwrite it.

In required mode, a missing checkpoint (including for an empty chain), a mismatch in the referenced row or hash, a rollback, a truncated tail, and checkpoint read or write failures all fail closed at startup, at readiness and on authoritative writes. Message create, edit, delete and replay, reactions and pins, preferences and bookmarks, and security and administration mutations put the state change and the audit row in the same transaction. Read positions and provisional upload chunk metadata and cleanup do not add dedicated audit events, but they go through the same process-local admission. Normal appends and checkpoint updates verify the HMAC of the current anchor and its descendant relationship to the database tail under the same PostgreSQL advisory lock, and the external file is replaced atomically only if the value it was compared with has not changed. An integrity failure is sticky within the process, and neither a normal server start nor an audit append recreates or re-signs a missing checkpoint or a truncated suffix. Reprovisioning when it is missing would approve the truncated chain as the new history, so do not do it until incident response has compared it with an independently kept checkpoint or backup.

Because the state mutation and the audit row are committed in the same database transaction, if only the checkpoint I/O right after it fails, the already committed mutation is reported as successful, once. Later audited or guarded authoritative mutations and readiness then fail closed. A checkpoint I/O failure that is not an integrity failure, such as a temporary storage fault, is rewritten with the same chain verification at the next mutation or readiness check (at most every 2 seconds), and service resumes automatically when it succeeds. Integrity failures stay sticky and need recovery by the operator. Reads and writes of the audit head use a dedicated object storage connection and concurrency slot that are not shared with user downloads. Operators must never assume "it was a 500, so the database rolled back too" and retry. Presence and device activity timestamps are advisory telemetry that is not used for authorization and so sits outside the gate; losing them is acceptable. After a readiness failure, drain ingress, and do not take these telemetry updates as a sign that service writes succeeded. This mechanism uses in-process admission, so it does not support multiple application processes.

A local systemd `StateDirectory` improves detection of accidental database row deletion, but it is not operator separation if the same host or operator can delete both the database and the file. Do not claim "operator-independent audit" for a deployment that does not use an independent mount.

`AUDIT_INTEGRITY_KEY` is needed to verify the audit chain and checkpoints. Do not store it only with the same credentials or in the same encrypted container as the database dump; keep it recoverable as a separate encrypted asset.

## systemd

Place the built repository in `/opt/alparts` and install `deploy/alparts.service` in `/etc/systemd/system`. The example unit requires Node.js 24 or later at `/usr/bin/node`. If you installed it elsewhere, change `ExecStart` to that verified absolute path before starting, and run `systemd-analyze verify /etc/systemd/system/alparts.service`. Put root-owned credential files in `/etc/alparts/credentials`, one secret per file, and only non-secret endpoints and policies in `/etc/alparts/alparts.env`. Bind-mount `/var/lib/alparts-audit`, which the example unit creates, onto independently protected storage before claiming separation from the database operator.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now alparts.service
systemctl status alparts.service
curl --fail http://127.0.0.1:3000/health/ready
```

## Migration safety sequence

The migration script and the backup scripts never run each other automatically. The operator manages the following order explicitly.

1. First verify typecheck, tests and build for the revision being deployed, and a migration on a fresh disposable database.
2. Drain or stop the application and stop writes to the database and object storage. The operator guarantees that nothing writes during the backup.
3. Set the age recipient, the backup database read identity, the object storage read identity and the output destination, and run the gate with a migration label.

   ```bash
   export ALPARTS_BACKUP_QUIESCED=YES_WRITES_ARE_STOPPED
   scripts/pre-migration-backup.sh 0006_example_change
   ```

4. Restore the resulting artifact with `scripts/restore-verify.sh` into an empty database and empty bucket separate from production. Do not proceed to the migration unless you get `VERIFIED <run-id>`.
5. Record the backup artifact digest and the verification result in an independent change record.
6. Run the migration with a deployment identity separate from the application runtime.

   ```bash
   pnpm --filter @alparts/server db:migrate:runtime
   ```

7. Start the application and check startup, live and ready, audit integrity, the migration journal and the PostgreSQL 16 `public` catalog fingerprint. Do not get around a fingerprint mismatch by rewriting the expected value; investigate the schema drift and do a forward repair or a verified restore. If a rollback or restore is needed, confirm the cause in a new isolated environment first, then use an approved runbook.

`pre-migration-backup.sh` does not run migrations, stop services, restore or clean up. `restore-verify.sh` does not drop existing schemas or clear existing buckets, and refuses target names that look like production. See [BACKUP.md](./BACKUP.md) for the environment and the full procedure.

## Graceful shutdown

`SIGTERM` and `SIGINT` make readiness fail immediately, refuse new API work, disconnect realtime clients, stop background cleanup, drain HTTP connections for up to 25 seconds and close the database pool. The systemd unit allows 30 seconds before a forced kill.

Do not treat shutdown as an implicit quiesce mechanism for backups. Separately confirm that every write source, including the database, object storage and management tools, has stopped.

## Metrics and alerting

`/metrics` is registered only when `METRICS_ENABLED=true`. A value of at least 32 bytes in `METRICS_TOKEN`, or in a mode-protected `METRICS_TOKEN_FILE`, is required, and the Bearer token is compared in constant time. Even with a token, do not expose the endpoint on a public route.

Collected metrics are HTTP rate, status and latency; database pool total, idle, waiting and max; password and object storage gate active, pending and cap; event loop p50, p99 and max; and process memory and uptime. Add external monitoring for disk and inodes, PostgreSQL, object capacity, TLS expiry, backups, off-host copies and restores, systemd restarts, and synthetic encrypted reads and writes. Logs are structured JSON in UTC with request, trace, actor and tenant context, but never include bodies, tokens, passwords, keys or plaintext.

## Automated single-host backup

`deploy/alparts-backup.timer` starts a oneshot service daily, with a random delay, as a persistent timer. `scripts/backup-under-systemd.sh` refuses to overlap using flock, fails without changing anything if the target service is not active, checks the required commands (including rclone 1.75.1 or later) and settings with `backup.sh --preflight` before stopping the app, and sets the quiesce assertion only after the stop. A trap for success, failure and signals tries to restart the service. Because the backup unit stops the app itself, do not give it a `Requires=` relationship to the app.

Retention runs only after a successful backup and an app restart. `scripts/prune-backups.sh` defaults to a dry run and requires a narrow existing directory, exact file names, a number of days and a minimum number of copies, and `BACKUP_PRUNE_ACK=DELETE_EXPIRED_ENCRYPTED_BACKUPS`. A successful timer alone is not disaster recovery, so monitor off-host and off-region copies of the artifacts and restore tests separately.

## Backup / restore boundary

The backup tooling collects the following under one run ID.

- A PostgreSQL logical dump made with `--format=custom --serializable-deferrable`.
- The latest object bytes in the configured bucket.
- Table counts, attachment and object references, an object inventory, SHA-256 checksums, a manifest and tool versions.

Plaintext staging is created only under a mode-`0700` `mktemp` directory and removed by a trap, and the published artifact is encrypted to an age recipient public key. Existing output files are never replaced. PostgreSQL and object storage share no transaction, so a backup taken without quiescing is not a consistent snapshot.

The restore verifier enforces the following.

- Only `alparts_restore_*` / `alparts_verify_*` databases and `alparts-restore-*` / `alparts-verify-*` buckets are allowed; production-like names and the source or default bucket are refused.
- Only a database with no non-system schemas or objects and a bucket with no objects are allowed.
- The restore owner is checked to be `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS` and unable to inherit dangerous built-in roles.
- Before filesystem extraction, the number of archive entries, the logical bytes of each regular file and the aggregate expanded bytes are checked against the configured limits. The expanded sizes reported by GNU tar are used, and compact sparse or unsupported metadata is refused when it can be detected.
- It decrypts, validates the archive, paths and types, checks checksums, runs a single-transaction `pg_restore`, copies the objects, and then downloads them again to compare every table count, attachment reference and object key, size and SHA.

The PostgreSQL connection is passed as a mode-`0600` libpq service file and a section name, and object storage credentials are written by a shell builtin into a temporary mode-`0600` `rclone` configuration (under the mode-`0700` staging directory). Passwords, access keys and secret keys are never passed in child process argv or environment, and `RCLONE_*` and `AWS_*` environment variables are also removed from children. Set the restore expanded-byte limit at or below the quota and safely available space of the protected staging filesystem.

### Verified round trips

On 2026-08-26, in a unique PostgreSQL 16 and MinIO environment that used no existing database, bucket or volume, `backup.sh` followed by `restore-verify.sh` into an unprivileged, empty verification database and empty bucket completed.

On 2026-10-02, after replacing object storage with SeaweedFS 4.47 and the transfer tool with rclone, the same `backup.sh` → `restore-verify.sh` completed in a unique PostgreSQL 16 and SeaweedFS environment (43 tables, 2 objects including an avatar reference, 74,096 bytes).

- Run ID: `20260826T144441Z-c50148de2d3e`
- Database: source and restore counts matched for 4 tables
- Objects: 2 objects, 144 bytes in total
- Verification: manifest, payload checksums, attachment references, object inventory and re-download SHA all matched

These results show only that the database rows and latest encrypted object bytes of that artifact could be recreated in the verification targets. Application startup, chain verification with the original audit key, fixture decryption with browser device keys, the full client attachment flow, and RTO/RPO were not verified.

### Assets not included in backups

- `AUDIT_INTEGRITY_KEY`, the age identity, and deployment, object storage and PostgreSQL credentials.
- Reverse proxy, systemd, and environment and policy configuration.
- The external audit checkpoint file and the records at its independent storage location.
- Browser device private keys and client-side recovery material for channel keys.
- Object version history, bucket policies, lifecycle, tags and all object metadata.

Encrypt and store these separately, keeping need and authority separated. Do not add browser device private keys to server backups to make it look like end-to-end encryption recovery.

## Operational guarantees not provided

This repository does not provide PITR or a continuous WAL archive, WORM or object lock, automatic off-site replication, scheduled automatic restores, full automatic application recovery, failover, HA, completed quarterly disaster recovery exercises, measured RTO/RPO, or a 72-hour soak. Safe local retention and a daily systemd schedule are implemented, but staying on the same host is not disaster recovery. External SIEM or WORM forwarding of audit records, data retention and export, and signed update and release provenance are also not implemented.

These are formal release blockers in [LIMITATIONS.md](./policies/LIMITATIONS.md), and a successful manual backup round trip does not lift them.
