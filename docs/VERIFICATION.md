# Verification record

Last executed: 2026-08-30. All database/object-store exercises used uniquely named disposable targets on the local audit containers. No production or pre-existing user data was used. Secrets were generated ephemerally and were not printed.

## Security scan provenance

The requested official CLI was executed as a repository-wide Deep Security Scan:

```bash
npx --yes @openai/codex-security@0.1.24 scan /home/konoha/develop/alparts \
  --mode deep --auth chatgpt --workers 2 --subagents 0 \
  --stop-after-no-new 3 --max-discovery-runs 10 --max-time-hours 1.5 \
  --output-dir /tmp/alparts-codex-security-prechange-20260830-audit1 \
  --headless --verbose
```

- Scan ID: `160868a8-5398-4707-ac05-e4c99c18fdd8`.
- Base revision: `76e0ee7465c82733f1c51355fab24539850be415`.
- Packaging: completed; canonical artifacts include manifest, findings, coverage, report, and SARIF.
- Coverage: `partial` because the time ceiling deferred terminal reconciliation and left some candidates unvalidated.
- Result: 13 canonical findings represented by 15 report instances (10 medium, 5 low). This is not a finding-free or exhaustive result.

The scan was intentionally not rerun after remediation merely to manufacture a zero-finding label. Root-cause mapping and residual status are in [the audit record](../SECURITY_AUDIT.md) and [risk register](./RISK_REGISTER.md).

## Build and automated tests

| Gate | Result |
| --- | --- |
| `pnpm lint` | passed with warnings denied |
| `pnpm typecheck` | passed for shared, server, and client |
| `pnpm test` | passed: server 73/73 and client 98/98; integration-only suites are separately recorded below |
| `pnpm build` | passed; shared/server TypeScript and production Vite bundle built |
| `pnpm test:backup-security` | passed malicious archive, permission, target-name, retention, credential-propagation, and interruption controls |
| `pnpm security:secrets` | passed on tracked files; the ignored developer-local file was not restored to tracking |
| `pnpm audit --prod --audit-level high` | passed: no known production dependency vulnerabilities |
| `pnpm licenses list --prod --json` | passed and produced a parseable production dependency license inventory |
| shell syntax | passed for launchers and all backup/operator/test shell scripts |
| YAML and CI pin validation | all workflow/dependabot YAML parsed; action references are full commit SHAs |
| Compose validation | development and production profiles passed `docker compose ... config --quiet` |
| systemd unit validation | `systemd-analyze verify` passed in an isolated staged root with only the documented executable paths represented by inert stubs |
| `git diff --check` | passed |

## Database, object storage, and concurrency

- Applied migrations `0000` through `0013` to a fresh PostgreSQL database, then replayed the migration command successfully.
- Ran `pnpm --filter @alparts/server test:integration` with `RUN_INTEGRATION=1` against a fresh PostgreSQL 16 database and a uniquely named MinIO bucket after the final bounded-client/password-worker changes: 4/4 passed. This covered the authorization/E2EE/WebSocket/file/key flow, exact DM replay, current-versus-explicit historical key retrieval, 65 pending key epochs, notification replay, schema-catalog verification, audit-chain truncation detection, and checkpoint-write failure followed by fail-closed audited and guarded admission.
- The integration flow verified audit actions for message create/replay/edit/delete, reaction changes, pinning, preferences, and bookmarks. The stored request ID matched the server response, trace context was validated, and ciphertext-adjacent payloads, signatures, idempotency keys, plaintext, and reaction values were absent from audit serialization.
- Ran the image-compatible runtime migrator on another fresh database, replayed it, then held its PostgreSQL advisory lock from another connection. The first two runs succeeded and the concurrent run failed immediately with `MIGRATION_ALREADY_RUNNING`.
- Migration `0013` has a fail-before-change preflight for legacy rows above the new durable quotas. Large existing deployments still require the documented reviewed concurrent-index expand phase.

## Backup and restore

- A negative source-consistency control containing an attachment reference without its object was refused with no artifact publication.
- A target name outside the narrow disposable pattern was refused before database restore.
- Clean run `20260830T094605Z-3e2bb09737cb` created an age-encrypted 112,856-byte artifact for the current 29-table schema plus one 128-byte opaque object.
- The artifact restored under an unprivileged owner into empty `alparts_verify_20260830094602` and empty `alparts-verify-20260830094602`.
- Manifest, payload checksum, table counts, object inventory, object redownload, and SHA-256 comparison passed: `VERIFIED 20260830T094605Z-3e2bb09737cb`.

This proves the scoped data-level mechanism, not off-host custody, PITR/WORM, automatic recovery, full application DR, or browser-key decryptability.

## OCI and supply chain

- Built `alparts-codex-audit:20260830-final5` (`sha256:05ba9022369bab1da9ec0a374470c85c33ec71d7af8c60184efa7aa401141586`) from the pinned Node 24 Alpine base and frozen pnpm lockfile after all bounded-client/password-worker changes.
- Trivy 0.74.0 filesystem scan (`vuln,misconfig,secret`, HIGH/CRITICAL, fixed findings) passed with zero reportable findings.
- The first final-image scan correctly found four fixed-but-unpatched Alpine OpenSSL findings and ten findings in unused npm/Corepack tooling, including one critical. The Dockerfile was remediated to install exact `libcrypto3/libssl3` `3.5.8-r0` and remove npm, Corepack, Yarn, and package-manager caches from the runtime artifact.
- The rebuilt final image passed the same Trivy HIGH/CRITICAL image gate with zero reportable findings. Runtime inspection confirmed UID 1000, exact `libcrypto3/libssl3` `3.5.8-r0`, and the absence of npm, npx, Corepack, pnpm, Yarn, and their runtime caches.
- A disposable Trivy export produced a valid CycloneDX 1.7 SBOM with 170 components. The generated file was validation evidence only and was removed after parsing; CI publishes the retained build artifact.
- CI now scans both the repository filesystem and the built final image; the image scan is a release gate rather than an informational report.

## Production runtime smoke

The rebuilt final image was exercised with production validation, host networking only for disposable loopback dependencies, a read-only root filesystem, no Linux capabilities, `no-new-privileges`, a 256-PID/512-MiB/1.5-CPU limit, a 1,024-file-descriptor limit, and a dedicated checkpoint volume.

1. Server startup against the empty database failed closed at the schema gate before listening.
2. The image-bundled runtime migration then ran twice successfully; startup verified all 14 migration records and the exact catalog fingerprint.
3. The explicit first-deployment checkpoint command provisioned and verified the witness; it persisted as UID 1000, mode `0600`.
4. `/health`, `/health/live`, `/health/startup`, and `/health/ready` succeeded and the container health state became `healthy`.
5. `/metrics` returned 401 without credentials; a valid independent bearer token exposed DB, password/object/audit-admission, request, runtime, and saturation metrics.
6. `docker stop --time 35` produced `server.shutdown_started` and `server.shutdown_complete`; the container exited 0.

## Deliberately unverified claims

No result here proves multiple application replicas, automatic failover, multi-AZ/region/cloud consistency, PITR, WORM/off-site custody, formal cryptographic review, independent external penetration testing, accessibility/i18n conformance, or production load/soak capacity. Those remain explicit open risks rather than simulated guarantees.
