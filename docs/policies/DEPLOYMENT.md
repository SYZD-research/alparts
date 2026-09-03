# Deployment guide

Last verified: 2026-08-30

## Supported modes

| Mode | Status | Intended use |
| --- | --- | --- |
| Development | implemented | loopback-only local iteration with disposable Docker PostgreSQL/MinIO |
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

The service does not silently auto-detect capabilities. Operators select an explicit reviewed mode; absence of Kubernetes/KMS/HA never disables authentication, authorization, TLS requirements, or audit integrity.

## Common preflight gate

Before any production start or update:

1. identify the exact Git revision, immutable OCI digest, Node/pnpm versions, and migration set;
2. review [limitations](./LIMITATIONS.md) and [open risks](../RISK_REGISTER.md) for the data classification;
3. generate unique secrets outside the repository and provide them through protected files/provider mounts;
4. verify a dedicated PostgreSQL 16 database/`public` schema, PostgreSQL/MinIO endpoint identity, TLS trust, least-privilege roles, storage durability and capacity;
5. build, lint, typecheck, test, scan secrets/dependencies, and build the exact image;
6. apply every migration to a fresh disposable DB and run the PostgreSQL+MinIO integration suite;
7. for an existing deployment, stop/drain writes, create and independently restore-verify a pre-migration encrypted backup;
8. apply migrations with a separate deployment identity while the application is stopped;
9. prove that the database's applied migration timestamps/hashes and bounded PostgreSQL 16 catalog fingerprint exactly match the running image;
10. initialize the audit checkpoint only on first deployment, then require it on every start;
11. start one app process, gate on startup/readiness plus authenticated synthetic read/write, and monitor errors/saturation;
12. retain the previous immutable image and a documented forward/restore rollback decision.

Never reinitialize a missing audit checkpoint merely to make readiness green. Never apply a destructive migration without a verified backup and a separately rehearsed recovery.

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

The example app uses a dynamic nonroot UID, read-only filesystem protections, no capabilities, finite memory/tasks/fds, restart backoff, and loopback bind. Its explicit insecure-dependency acknowledgement is valid only when PostgreSQL/MinIO endpoints are truly loopback or unix-socket local; remote endpoints must use verified TLS and remove that acknowledgement.

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

Backups deliberately stop the application to make PostgreSQL+MinIO consistent. The wrapper locks against overlap, refuses to touch an already inactive service, restarts through a trap, and prunes only exact encrypted artifact names with an acknowledgement. Removing `Requires=alparts.service` from the backup unit is intentional: stopping the app must not stop the backup job that initiated the quiesce window.

## Single-host production with Compose

`compose.production.yml` packages only the application. PostgreSQL and object storage are explicit dependencies so they can be durable local services or managed endpoints without pretending the Compose project is HA.

The profile requires an immutable image tag, exact HTTPS origin, dependency endpoint, six application secret files, and a seventh separately scoped migration-database secret. It binds the host port to loopback, uses a read-only root filesystem, tmpfs, no Linux capabilities, `no-new-privileges`, PID/memory/CPU limits, nonroot image user, persistent audit checkpoint volume, graceful stop, restart policy, and readiness healthcheck.

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

Pre-stage the exact OCI image or pnpm store, PostgreSQL/MinIO packages, CA roots, `age`, `mc`, pg tools, SBOM, checksums and operator documentation. Disable network-dependent package installation during deployment. Provide a trusted local time source, offline certificate renewal plan, removable-media backup export with two-person handling, and a tested clean-room restore. Do not weaken auth/TLS/audit because the network is isolated.
