# Incident response runbook

This runbook is deliberately fail-safe. Commands that delete, prune, drop, or overwrite production data are not provided. Use the narrow restore verifier and a reviewed change record for every state-changing recovery.

## Common first response

1. Declare severity and incident lead; record UTC start and affected tenants/functions.
2. If integrity, isolation, credentials, audit, or corruption may be involved, remove traffic and stop all writers. Do not start a second app replica.
3. Preserve structured logs, release/image/config hashes, PostgreSQL and object-store snapshots, current external checkpoint, backup catalog, supervisor journal, and monitoring timeline.
4. Never paste tokens, passwords, keys, plaintext messages, or unredacted dumps into chat/tickets.
5. Check `/health/live`, `/health/startup`, `/health/ready`, process/supervisor state, disk, database, object store, audit, and recent deployment independently.
6. Recover into new/isolated targets where data correctness is uncertain. Gate return to service on an authenticated synthetic encrypted read/write and audit verification.

## Database failure

- **Detect:** readiness 503, DB pool waiting/errors, PostgreSQL health/replication alerts.
- **Contain:** stop writes if timeline or corruption is uncertain; keep liveness for evidence only.
- **Recover:** restore connectivity or promote only through the DB platform's fenced procedure. Verify server version, target timeline, schema journal, row invariants, audit chain/checkpoint, object references, then application readiness.
- **Escalate:** any missing transaction, audit mismatch, unexpected role/extension/schema, or split-brain evidence.

## Disk full

- **Detect:** filesystem/inode thresholds, DB/object errors, checkpoint/backup write failure.
- **Contain:** stop application writes. Do not delete WAL, database files, audit checkpoint, logs under investigation, or the only backups.
- **Recover:** expand or attach replacement storage; move only approved non-evidence data using filesystem-safe procedures; check filesystem/database/object integrity and capacity headroom before restart.
- **Prevent recurrence:** alerts at deployment-specific 70/85/95%, log rotation, backup target quotas, growth forecast.

## Data corruption

- **Detect:** checksums, DB checks, audit verification, restore/object mismatch, client AEAD failures.
- **Contain:** stop writers and isolate the suspect timeline/endpoint.
- **Recover:** choose a known-good artifact/checkpoint, restore to empty targets, verify every supported layer, then controlled cutover. Preserve corrupted copy for root-cause analysis.
- **Do not:** repair hashes or re-provision the audit checkpoint merely to accept corrupted state.

## Expired or invalid certificate

- **Detect:** external expiry/handshake probes and backend TLS errors; alert at 30/14/7 days.
- **Contain:** do not disable TLS or verification. Keep private service unavailable if identity cannot be authenticated.
- **Recover:** issue through the approved CA, atomically install full chain/key with strict permissions, reload (not edit in-place), validate hostname/time/chain from client and backend networks.

## Credential compromise

- **Contain:** revoke the smallest affected credential immediately; block source where appropriate; preserve audit evidence.
- **Rotate:** session/JWT secret rotation invalidates sessions; database/object-store/TURN/metrics/audit/backup keys have different blast radii and procedures. Use overlap only where the protocol safely supports it.
- **Recover:** deploy through secret files/provider, restart/drain as required, verify old credential rejection and new operation, audit affected actions, notify according to policy.
- **Special:** the historically tracked development-account password must be rotated or the account destroyed in every retained environment; repository removal cannot revoke it.
- **Password pepper:** stored hashes are `p2:` (pepper id + salt + HMAC) or legacy `p1:`. To rotate, set the new value as `PASSWORD_PEPPER` and the old one as `PASSWORD_PEPPER_PREVIOUS` (or the `_FILE` / compose `password_pepper_previous` secret), then restart. Each successful password login rewraps that user's hash under the new pepper and records `passwordRewrapped` in the `user.login` audit entry. Hashes cannot be rewrapped without the password, so keep the previous pepper until the remaining users have signed in or reset their passwords, then remove it. Until then, anyone holding a database snapshot and the old pepper can attempt offline guessing against the not-yet-rewrapped hashes.
- **Secrets in git history:** rotate first, then purge. `scripts/check-history-files.sh` and the `secret-history` CI job (gitleaks over full history) fail while such objects remain reachable. Purging requires `git filter-repo`, a force-push, and every clone/fork/CI cache to be replaced; deleting a file in a new commit does not remove it.

## Dependency outage

- **Detect:** readiness and dependency-specific metrics/errors.
- **Contain:** keep liveness; let finite deadlines/gates shed work. Do not increase queue, retry, timeout or DB pool bounds reflexively.
- **Recover:** restore authenticated endpoint/DNS/network, verify correct data timeline and TLS identity, then readiness. Degrade attachment or voice features only when isolation/auth/integrity remain intact.

## Bad deployment

- **Detect:** readiness/synthetic failure, error/latency/saturation change, client protocol incompatibility.
- **Contain:** stop rollout/traffic and preserve the failed image/config/logs.
- **Recover:** previous immutable binary only when schema compatibility is proven. Otherwise fix forward or restore the verified pre-migration artifact to new dependencies.
- **Gate:** fresh migration/integration, startup/readiness, authz isolation, encrypted write/read, attachment, audit.

## Failed migration

- **Contain:** keep app stopped; inspect migration journal and transaction state on a clone.
- **Recover:** if atomic and rolled back, correct a forward migration. If partially applied/nontransactional, follow a migration-specific repair reviewed against backup. Restore only to new empty targets.
- **Large tables:** create indexes concurrently in an approved expand phase where required; never improvise a long production lock.

## Overload or retry storm

- **Detect:** 429/503, latency, event-loop, DB/gate waiting, CPU/memory/network/disk.
- **Contain:** upstream rate control and principal/tenant isolation; retain application bounds. Disable optional feature entry points only through a reviewed safe configuration.
- **Recover:** remove attacker/load source, let queues drain, verify no DB lock/backlog, gradually restore traffic.
- **Do not:** enable unbounded retries, queues, body size, connections, or public bypass endpoints.

## Accidental deletion

- **Contain:** stop writers immediately; preserve audit/checkpoint and storage versions/snapshots.
- **Recover:** restore closest known-good artifact into isolated targets, measure delta, perform reviewed merge or cutover. Validate authorization, audit, object references and decrypt fixtures.
- **Evidence:** actor, request/trace, resource scope, exact result, and whether the deletion was authorized must be retained without secrets.

## Ransomware or host compromise

- **Contain:** isolate network/host; assume served browser code, local checkpoint, runtime credentials and same-host backups are untrusted.
- **Recover:** clean/new host from a reviewed immutable source/image; rotate all exposed credentials; restore only independently held verified artifacts/checkpoint evidence; re-enroll/revoke devices and rotate channel epochs as appropriate.
- **Return:** require external security review of persistence and supply chain. Do not “clean” the original host in place and reuse it as proof of recovery.

## Region outage

- **Current behavior:** manual DR only. There is no safe automatic multi-region writer failover.
- **Recover:** use a pre-approved clean environment and off-region artifacts; establish one fenced writer, restore/verify, update routing only after application correctness gates.
- **Do not:** point two regions at divergent databases/object stores or infer quorum from a single node.

## Audit checkpoint failure

- Drain all traffic and stop authoritative writers; preserve the exact DB/checkpoint state. Advisory presence/activity is not evidence that authoritative admission remained open.
- Determine whether failure is I/O/capacity, checkpoint deletion/rollback, DB truncation, or authority compromise.
- Fix storage and restart only if the intact DB chain is a verified descendant of the last independently held checkpoint.
- Never run `audit:checkpoint:init` after unexplained loss until incident authority has established and approved a new canonical history.

## Backup or restore failure

- A missing/failed daily artifact immediately increases RPO; fix and rerun while preserving service restart safety.
- A failed restore disqualifies that artifact until explained. Try an older independently inventoried artifact in a new empty target.
- Never weaken target-name, emptiness, owner-privilege, path/type, expanded-size, checksum, or source/target isolation checks to make a restore pass.

## Closure

Document root cause, scope, actual RPO/RTO, evidence locations, credential/session actions, tests/control added, and residual risk owner/date. Correctness, tenant isolation, secret leakage, audit integrity, or unrecoverable loss requires a release freeze until verified remediation.
