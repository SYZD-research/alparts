# Reliability model

Last verified: 2026-08-30

Alparts currently provides a bounded, restart-safe single-process service model. It does not provide application-process redundancy, automatic failover, or a distributed consistency protocol. External PostgreSQL and object-storage redundancy can protect those dependencies, but does not make multiple Alparts application replicas safe.

## Reliability invariants

- Every queue, fan-out, request body, remote listing, socket set, password hash pool, DB pool, and user/tenant collection has an explicit ceiling.
- Remote calls have finite connect, statement, header, inactivity, or absolute-operation deadlines. There is no unbounded application retry loop.
- Security-sensitive mutations either commit state and audit together in PostgreSQL or roll back. Read cursors and provisional upload-chunk metadata use the same fail-closed admission without a dedicated audit row. External audit checkpoint failure blocks readiness and every later authoritative write in either path.
- Presence and device activity timestamps are advisory, may be omitted, and are never used for authorization, key, quota, retention, or recovery decisions; they deliberately cannot consume the audit gate.
- PostgreSQL is the durable authority for idempotency and state machines. Process memory is used only for bounded admission, ephemeral realtime state, and scheduling.
- Authorization failures are fail-closed. Dependency failures degrade affected functions or readiness; they never enable bypass access.
- Shutdown stops admission before draining and closing dependencies. Fatal process errors exit non-zero after a bounded drain so the supervisor can restart.
- PostgreSQL/object-store backup consistency requires a quiesced write window because the two stores have no common transaction.

## Retry and timeout policy

| Operation | Policy |
| --- | --- |
| Client idempotent request retry | Exact request object reused; default 3 attempts, hard maximum 8, capped exponential backoff with jitter; no retry for ambiguous non-idempotent operations |
| Password work | bcrypt executes on at most 2 Worker threads, with 16 queued, a 5-second queue deadline and a 30-second execution watchdog; reject with 503; validate stored bcrypt cost before work; current-password KDF completes before audit/key/row locks |
| Authoritative audit admission | 1 active, 64 queued, 30-second admission deadline shared by audited and guarded durable writes; reject with `AUDIT_UNAVAILABLE`/503 |
| DB connection/query | bounded pool, 5-second connect and 15-second statement defaults; transaction failure is returned, not blindly retried |
| Object-store operation | bounded active/pending gate, 10-second default request deadline, stream inactivity/absolute listing deadline |
| Upload work | 16 pending reservations/user, 200/workspace; 4 outstanding operations/upload and 64/process |
| Browser HTTP/work | every JSON/chunk response has a 60-second total deadline with caller-abort propagation; 100 encrypted outbox commands/device, 64 authorization tasks, 64 voice operations/peer, 16 active attachment runtimes; draft writes coalesce; message verification is 1 active + 1 pending/channel with a cancel-aware 30-second lifetime, 64-way crypto batches and 1,000/channel, 5,000/global, 32-channel resident windows |
| Channel-key history | current scope is active/pending only; explicit requests accept at most 64 versions and 864 deliveries; deprecated no-query compatibility is the newest 16 non-aborted versions |
| HTTP server | 15-second headers, 120-second request, 5-second keepalive, 1,000 requests/socket |
| Shutdown | 25-second HTTP drain within a 30-second supervisor window |
| Supervisor restart | systemd restart on failure, 5-second delay, burst-limited to 5 in 5 minutes |
| Backup | one non-overlapping run; no automatic retry storm; timer is persistent and the next scheduled attempt is observable |

Retries that could duplicate a durable mutation must reuse the operation's idempotency key and exact signed/encrypted request. New dependency retries must use exponential backoff, jitter, a total deadline, and a small attempt cap; they must not be added generically around transactions.

## Degraded behavior

| Failure | Safe behavior |
| --- | --- |
| PostgreSQL unavailable | readiness 503; authenticated/durable operations fail; liveness stays up for diagnosis |
| Object store unavailable | readiness 503; attachment operations fail; existing client-held plaintext and some metadata-only UI may remain usable |
| Audit checkpoint unavailable/inconsistent | readiness and subsequent authoritative writes fail closed; preserve the already committed audited DB result exactly once; advisory presence/activity is non-authoritative and may be dropped |
| Audit-commit saturation | excess mutations fail promptly with 503; no unbounded process-memory queue is created |
| Metrics collector unavailable | no application dependency; scrape fails without blocking service |
| STUN/TURN unavailable | text remains available; calls that cannot establish direct connectivity fail |
| Password-work saturation | login/registration reject promptly with 503 and `Retry-After`; event loop capacity is preserved |
| Object-store saturation | attachment request rejects promptly with 503; normal channel capacity and DB pool are not allowed to grow without bound |
| Browser message burst/history saturation | one coalesced verifier drains bounded batches; unloaded-channel events are ignored and reconciled by REST; oldest resident data/channels are evicted and history paging stops visibly at the local window |
| No usable group member left | old ciphertext remains honestly unavailable; the server reports `historyRecoveryRequired`, the UI offers to start without earlier messages, and after step-up a device may start only a new group for future messages |
| Members offline | writes continue; returning devices catch up from the ordered commit log; devices waiting to be added are added by the next online member |
| Persistent database catalog drift | startup/readiness fail closed even when the migration journal is intact; repair forward or restore a verified database rather than editing the expected hash ad hoc |
| Disk full | writes/checkpoints/backups fail; readiness should fail through dependency/checkpoint checks; operator must stop writes and recover space without deleting evidence |

## Single-host durability

Use a journaling filesystem, durable PostgreSQL storage with WAL/fsync enabled, persistent object storage, an independent audit-checkpoint mount, a process supervisor, UPS where appropriate, encrypted daily backup, and off-host replication of completed artifacts. The repository does not disable PostgreSQL durability settings and does not pretend a single disk is redundant.

The systemd and production Compose examples use nonroot operation, read-only filesystem boundaries, restart policy, finite resources, health gates, and a persistent audit volume. The application cannot detect whether the underlying volume actually honors fsync or survives host loss; this is a deployment acceptance test.

## Cluster and region boundary

Multiple app replicas are prohibited until process-local admission, Socket.IO rooms, upload locks, authorization revision coordination, and the audit checkpoint are replaced or fenced with shared durable coordination. Multi-region writes additionally require an explicit leader/fencing and conflict model. See [capability levels](../deployment/CAPABILITY_LEVELS.md) and [ADR 0004](../adr/0004-deployment-and-ha.md).

## Evidence and targets

- Failure details and recovery: [failure-mode analysis](../reliability/FAILURE_MODES.md).
- Provisional, measurable objectives: [SLI/SLO baseline](../reliability/SLO.md).
- Operational response: [incident runbook](../runbooks/INCIDENT_RESPONSE.md).
- Verified commands/results: [verification record](../VERIFICATION.md).

No “five nines” or unmeasured durability claim is made.
