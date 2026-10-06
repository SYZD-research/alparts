# Deployment guide

Last verified: 2026-08-30

## Supported modes

| Mode | Status | Intended use |
| --- | --- | --- |
| Development | implemented | loopback-only local iteration with disposable Docker PostgreSQL/SeaweedFS |
| Single-host production pilot | implemented template, deployment acceptance required | one Node process under systemd or hardened Compose, durable external/local PostgreSQL and S3-compatible storage |
| Clustered production | unsupported | design target only; do not start multiple app replicas against one deployment |
| Multi-region production | unsupported | design target only; no leader fencing/conflict/failover model |
| Air-gapped / edge appliance | conditionally supported at single-host level | pre-stage exact packages/image/tools; provide local durable dependencies, time, certificates and offline backup export |

See [capability levels](../deployment/CAPABILITY_LEVELS.md) for guarantees and non-guarantees.

## Configuration model

The implementation has two sources, in this order:

1. safe built-in defaults for non-secret bounded settings;
2. explicit environment variables, with a mutually exclusive `NAME_FILE` form for secrets.

There is no general config file, external secret-provider API, or runtime override layer. Docker secrets and systemd credentials are adapters into `NAME_FILE`. Supplying both `NAME` and `NAME_FILE` is an error. Invalid types/ranges, weak required secrets, unsafe bind/origins, missing production audit witness, or insecure non-loopback dependencies abort startup.

Registration mails a code to the address being registered. Configure `SMTP_HOST`, `SMTP_FROM`, optionally `SMTP_USER` with `SMTP_PASSWORD_FILE`, and `SMTP_SECURE=true` for TLS from the first byte; otherwise production requires STARTTLS. Without SMTP, production keeps serving existing accounts but refuses new registrations, logging `registration.unavailable` at startup, unless `EMAIL_VERIFICATION=disabled` explicitly turns the check off.

The service does not silently auto-detect capabilities. Operators select an explicit reviewed mode; absence of Kubernetes/KMS/HA never disables authentication, authorization, TLS requirements, or audit integrity.

## Common preflight gate

Before any production start or update:

1. identify the exact Git revision, immutable OCI digest, Node/pnpm versions, and migration set;
2. review [limitations](./LIMITATIONS.md) and [open risks](../RISK_REGISTER.md) for the data classification;
3. generate unique secrets outside the repository and provide them through protected files/provider mounts;
4. verify a dedicated PostgreSQL 16 database/`public` schema, PostgreSQL/object-store endpoint identity, TLS trust, least-privilege roles, storage durability and capacity;
5. build, lint, typecheck, test, scan secrets/dependencies, and build the exact image;
6. apply every migration to a fresh disposable DB and run the PostgreSQL+object-store integration suite;
7. for an existing deployment, stop/drain writes, create and independently restore-verify a pre-migration encrypted backup;
8. apply migrations with a separate deployment identity while the application is stopped;
9. prove that the database's applied migration timestamps/hashes and bounded PostgreSQL 16 catalog fingerprint exactly match the running image;
10. initialize the audit checkpoint only on first deployment, then require it on every start;
11. start one app process, gate on startup/readiness plus authenticated synthetic read/write, and monitor errors/saturation;
12. retain the previous immutable image and a documented forward/restore rollback decision.

Never reinitialize a missing audit checkpoint merely to make readiness green. Never apply a destructive migration without a verified backup and a separately rehearsed recovery.

## Object storage

Attachments, avatars and the durable audit head live in an S3-compatible object store. The recommended store is [SeaweedFS](https://github.com/seaweedfs/seaweedfs) (Apache-2.0); development and CI run SeaweedFS 4.47 pinned by digest (`docker-compose.yml`, `scripts/ci/start-object-storage.sh`). The server reaches any store through the AWS SDK for JavaScript v3 using path-style requests:

| Setting | Meaning |
|---|---|
| `S3_ENDPOINT`, `S3_PORT`, `S3_USE_SSL` | Endpoint host, port and TLS (TLS is required in production except for an acknowledged loopback endpoint) |
| `S3_ACCESS_KEY`, `S3_SECRET_KEY` (or `*_FILE`) | The application's own identity |
| `S3_BUCKET`, `AUDIT_HEAD_BUCKET` | Object bucket and the separate audit-head bucket (default `${S3_BUCKET}-audit`) |
| `S3_REGION` | Signing region (default `us-east-1`) |
| `S3_REQUEST_TIMEOUT_MS` | Absolute deadline for each request (default 10 s, at most 60 s) |

The former `MINIO_*` names are refused at startup, and by the backup scripts, with a message listing what to rename.

For a production SeaweedFS:

- run the pinned image on a dedicated, persistent volume; plan capacity and, where needed, SeaweedFS replication. A single volume is not redundant; the encrypted backups are the recovery path;
- expose only the S3 API to the application host, over TLS (SeaweedFS `-s3.port.https` with `-s3.cert.file`/`-s3.key.file`, or a TLS proxy on the same host). Disable telemetry (`-master.telemetry=false`) and keep the admin UI, master, volume and filer ports off the network;
- define identities in the `-s3.config` file: an administrator that creates the buckets and is never given to the application; the application with `Read`, `Write` and `List` on `S3_BUCKET` and `AUDIT_HEAD_BUCKET`; a backup identity with `Read` and `List` on `S3_BUCKET` only; and a separate identity for each disposable verification bucket. SeaweedFS grants per bucket, and `Write` includes deletion, so the application can also delete the audit head; treat the store's administrators and the application host as able to roll it back, as described in [operations](../OPERATIONS.md);
- create both buckets before the first start (for example `-bucket=alparts,alparts-audit`). The application never creates the audit-head bucket during normal start.

### Moving an existing MinIO deployment

1. Stop application writes and take a backup with the scripts of the release you are leaving, then restore-verify it.
2. Create both buckets and the identities above on SeaweedFS.
3. With the application still stopped, copy every object of `S3_BUCKET` and of the audit-head bucket, keeping the keys (for example `rclone copy old:alparts new:alparts` and the same for `alparts-audit`), then compare object counts and sizes on both sides. Without the audit head the server refuses to start until it is deliberately re-provisioned, so copy it rather than recreating it.
4. Rename every `MINIO_*` setting to `S3_*` in the environment, the Compose secrets (`s3_access_key`, `s3_secret_key`) and the systemd credentials, and point `S3_ENDPOINT` at SeaweedFS. Backup jobs use `S3_URL`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `S3_BUCKET`, and `rclone` instead of `mc`.
5. Start the application and confirm readiness and an attachment download before re-enabling writes.

## Development

```bash
./dev.sh
```

`docker-compose.yml` is dependency-only and development-only. Ports are loopback-bound; generated `.env` secrets are local mode `0600`; volumes are not automatically deleted on credential mismatch. Stop dependencies with `./dev.sh down`.

Development authentication and TLS settings must never be copied into production. Public registration remains disabled unless an explicit bootstrap invite secret is configured.

## Single-host production with systemd

Requirements:

- Linux host, Node.js 24+, built repository at `/opt/alparts`;
- reverse proxy that exposes only HTTPS and forwards to `127.0.0.1:3000`;
- durable PostgreSQL and S3-compatible object store, private to the service;
- protected credentials under `/etc/alparts/credentials` and non-secret policy in `/etc/alparts/alparts.env`;
- durable `/var/lib/alparts-audit`, ideally on an authority-separated mount;
- encrypted `/var/lib/alparts-backups` plus transfer to independent off-host storage;
- external disk, certificate, process, backup, and synthetic-service monitoring.

Install and validate the unit only after changing any environment-specific executable/path:

```bash
sudo install -m 0644 deploy/alparts.service /etc/systemd/system/alparts.service
sudo install -m 0644 deploy/alparts-backup.service /etc/systemd/system/alparts-backup.service
sudo install -m 0644 deploy/alparts-backup.timer /etc/systemd/system/alparts-backup.timer
sudo systemd-analyze verify /etc/systemd/system/alparts.service \
  /etc/systemd/system/alparts-backup.service /etc/systemd/system/alparts-backup.timer
sudo systemctl daemon-reload
```

The example app uses a dynamic nonroot UID, read-only filesystem protections, no capabilities, finite memory/tasks/fds, restart backoff, and loopback bind. Its explicit insecure-dependency acknowledgement is valid only when PostgreSQL/object-store endpoints are truly loopback or unix-socket local; remote endpoints must use verified TLS and remove that acknowledgement.

Provision the initial audit checkpoint while the app is stopped and with production credentials:

```bash
pnpm --filter @alparts/server audit:checkpoint:init
```

Then start and gate:

```bash
sudo systemctl enable --now alparts.service
curl --fail http://127.0.0.1:3000/health/startup
curl --fail http://127.0.0.1:3000/health/ready
sudo systemctl enable --now alparts-backup.timer
```

Backups deliberately stop the application to make PostgreSQL and the object store consistent. The wrapper locks against overlap, refuses to touch an already inactive service, restarts through a trap, and prunes only exact encrypted artifact names with an acknowledgement. Removing `Requires=alparts.service` from the backup unit is intentional: stopping the app must not stop the backup job that initiated the quiesce window.

## Single-host production with Compose

`compose.production.yml` packages only the application. PostgreSQL and object storage are explicit dependencies so they can be durable local services or managed endpoints without pretending the Compose project is HA.

The profile requires an immutable image tag, exact HTTPS origin, dependency endpoint, six application secret files, and a seventh separately scoped migration-database secret. Set `TRUSTED_PROXIES` to the reverse proxy's address as seen by the container (for example the bridge gateway): HTTP and Socket.IO limits are counted per client address (IPv6 per /64), and without it every client shares the proxy's single budget. The server logs `network.forwarded_without_trusted_proxy` once when it receives forwarded requests with the setting empty. It binds the host port to loopback, uses a read-only root filesystem, tmpfs, no Linux capabilities, `no-new-privileges`, PID/memory/CPU limits, nonroot image user, persistent audit checkpoint volume, graceful stop, restart policy, and readiness healthcheck.

Validate before start:

```bash
docker compose -f compose.production.yml config --quiet
docker compose -f compose.production.yml build --pull app
docker compose -f compose.production.yml --profile operations run --rm --no-deps migrator
# First deployment only; never use this to bypass an unexplained missing witness.
docker compose -f compose.production.yml run --rm --no-deps app \
  node packages/server/dist/scripts/initialize-audit-checkpoint.js
docker compose -f compose.production.yml up --detach --wait
```

Set `AUDIT_HEAD_BUCKET` to a separate object-store bucket and `AUDIT_HEAD_OBJECT_KEY` to a stable deployment identifier before provisioning/startup. Give the application get/put access to that head; DB/checkpoint repair and data-restore identities must not overwrite it. Existing checkpoints need the stopped-server `audit:head:init` upgrade described in [OPERATIONS](../OPERATIONS.md), after independent verification. Never regenerate the head identity or replay this bucket as part of a normal restore.


The image contains the exact ordered migration bundle used to build it. Its database-only runtime migrator receives only the separate migration URL and bounded DB settings, uses a non-waiting PostgreSQL advisory lock, honors connection/statement deadlines, and exits if another migrator is active. The server then compares every applied migration timestamp and SHA-256 plus the bounded PostgreSQL 16 `public` catalog fingerprint with the image contract at startup and readiness; an empty, stale, modified, reordered, newer unknown, or persistently altered schema fails closed. This requires a dedicated Alparts `public` schema and deliberately rejects another PostgreSQL major until a reviewed compatibility migration updates the fingerprint. Existing deployments must complete the quiesced backup/isolated-restore gate before this command. Skip the checkpoint initializer after the first deployment; an existing checkpoint is never overwritten.

Pin and deploy the resulting image by digest in a real release system. The repository currently pins base image tags and CI actions but does not publish signed releases or attestations.

## Rolling, canary, and rollback policy

The current app cannot run two active replicas, so an application rolling/canary update is not available. A single-host update is controlled stop → backup/restore gate → migration → start → health/synthetic gate. Use a second isolated environment for rehearsal, not a second active writer.

Rollback choices:

- If the schema remains backward-compatible, stop and run the previous immutable image.
- If a forward migration has made the old binary incompatible, deploy a corrective forward migration or restore the verified pre-migration backup into a new empty environment. Do not run ad-hoc down migrations against production.
- Preserve failed databases/artifacts for diagnosis; never clear data merely to make startup pass.

## Clustered and multi-region target

External DB/object-store HA may be used today behind the one app process. Multiple app replicas require shared rate/bulkhead state, distributed Socket.IO rooms, fenced upload coordination, shared authorization revision invalidation, and a durable multi-writer audit witness. Until those are implemented and partition-tested, replicas can create inconsistent admission, room, and audit behavior.

Multi-region operation additionally requires a declared consistency model, a single fenced write leader or conflict-free domain design, replication-lag behavior, failover authority, split-brain prevention, clock assumptions, and a tested data/client-key recovery process. DNS or load-balancer failover alone is insufficient.

## Air-gapped and edge

Pre-stage the exact OCI image or pnpm store, PostgreSQL/SeaweedFS packages, CA roots, `age`, `rclone`, pg tools, SBOM, checksums and operator documentation. Disable network-dependent package installation during deployment. Provide a trusted local time source, offline certificate renewal plan, removable-media backup export with two-person handling, and a tested clean-room restore. Do not weaken auth/TLS/audit because the network is isolated.
