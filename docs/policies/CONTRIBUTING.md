# Contributing

## Supported toolchain

- Node.js 24 or newer
- pnpm exactly as declared by root `packageManager`
- Docker/Compose for disposable PostgreSQL and SeaweedFS integration (`scripts/ci/start-object-storage.sh`)
- GNU shell tools plus PostgreSQL client, `rclone`, `age` and `jq` for backup/restore work

Install with `pnpm install --frozen-lockfile`. Do not regenerate the lockfile incidentally or add unpinned CI actions.

## Architecture rules

- Route/WebSocket code parses transport input and delegates. Durable invariants live in services, database transactions, unique constraints and migrations.
- Every resource operation resolves current tenant membership and permission. Missing tenant/resource context is deny, never global/default access.
- Security-sensitive mutations use `auditedTransaction`; the state and audit row must be one DB transaction.
- Never hold a DB transaction/lock across remote object/network I/O. Use a short reservation/state machine, remote call with deadline, then locked revalidation.
- New collections/fan-outs/queues/retries/concurrency must have explicit count/byte/time limits and an overload response. Do not add unbounded materialization or per-item DB authorization loops.
- Retried mutations require a durable idempotency key or a proof that duplication is harmless. Retry policy must be finite with deadline/backoff/jitter.
- Do not add process-global mutable state that would be mistaken for cluster-safe state. Record the topology impact in architecture/capability docs.
- Browser cryptographic changes require canonical serialization vectors, tamper/relocation/replay tests, identity/resource binding and compatibility/versioning analysis.
- Keep secrets, plaintext, request bodies, tokens and private keys out of source/logs/tests. Use synthetic unmistakable fixtures only in excluded test paths.

## Change workflow

1. Read `docs/INDEX.md`, relevant ADRs, threat model, limitations and risk register.
2. State the invariant and failure behavior before changing code.
3. Add the smallest durable control at the owning boundary; retain compatibility or provide a forward migration/deprecation path.
4. Add unit tests for success, denial, boundary, timeout/retry, concurrency/idempotency and cleanup where applicable.
5. Run the full local gate below. Database/storage changes also require the disposable integration gate.
6. Update inventory, architecture, risk, operation/runbook, environment example and ADRs when behavior/guarantees change.
7. Have a reviewer attempt bypasses through alternate routes, realtime paths, races, legacy rows and failure paths.

## Required local gate

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm test:backup-security
pnpm build
pnpm security:secrets
pnpm audit --prod --audit-level high
git diff --check
bash -n scripts/*.sh scripts/lib/*.sh scripts/tests/*.sh
```

Run `pnpm --filter @alparts/server test:integration` only against a uniquely named, empty, disposable PostgreSQL database and object-store bucket after applying all migrations. Never point tests at production-like names or credentials.

## Database migrations

- Migrations are forward-only and ordered; never edit an already deployed migration.
- Prefer additive expand → compatible code → contract changes. Long-running index creation on populated systems must use a separately approved concurrent phase.
- Add a preflight that aborts before changing data when a new invariant conflicts with legacy rows. Do not silently truncate/delete to satisfy a limit.
- Verify first install, replay/no-op, supported old-schema upgrade, failure rollback and application compatibility.
- Because runtime readiness fingerprints the PostgreSQL 16 `public` catalog, every schema migration must regenerate and review the expected catalog snapshot, retain the dropped-object negative test, and document any PostgreSQL-major compatibility change. Never update the digest merely to make an unexplained drift pass.
- For production, stop writers, create an encrypted pre-migration backup, restore-verify it in empty targets, apply with a separate role, then gate startup/readiness/synthetic behavior.

## Security-sensitive changes

Update `docs/security/THREAT_MODEL.md` and `docs/RISK_REGISTER.md`. Authentication, authorization, cryptography, audit, tenant isolation, secret loading, restore, shell execution, URL/rendering and deployment-boundary changes require explicit abuse-case tests. Do not weaken auth, TLS verification, checkpoint requirements or safe bind defaults for convenience.

Vulnerability details and real secrets must not be placed in public issues. Follow `SECURITY.md`.

## Documentation truth

Use “implemented and tested”, “deployment requirement”, “target”, and “unsupported” distinctly. Kubernetes, multiple endpoints or replicated storage do not justify an HA/multi-region claim without application coordination and tested failover. A successful data restore does not imply full client decryptability or measured RTO.

## Release gate

CI must pass build/lint/type/unit/integration/backup/security/dependency/migration gates and produce an SBOM. Before any production-readiness claim, also resolve/accept the current release blockers, commission independent review, run load/soak/fault/DR exercises, establish off-host recovery and measured SLOs, choose a project license, and implement signed release/provenance. Current repository outputs remain a prototype until those actions are evidenced.
