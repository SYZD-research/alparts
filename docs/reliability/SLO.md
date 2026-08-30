# SLI/SLO baseline

Last reviewed: 2026-08-30

These are provisional operating objectives for a correctly configured, single-host production pilot. They are not measured historical performance and are not a claim that the prototype is approved for high-impact secrets. A deployment must collect at least 30 days of valid telemetry and complete restore/failure exercises before promoting them to a customer commitment.

## Service definition

The service is available when `/health/ready` succeeds and an authenticated synthetic user can complete a read and a small idempotent encrypted write. Liveness alone is not availability. Planned maintenance is counted unless a deployment-specific contract explicitly excludes it.

## Initial objectives

| Property | SLI | Provisional objective | Measurement notes |
| --- | --- | --- | --- |
| Availability | successful synthetic read/write intervals / scheduled intervals | 99.5% monthly for a supervised single host | Probe every minute from outside the host; require both API and durable write |
| Request success | non-5xx completed API requests / admitted API requests | 99.9% monthly, excluding explicit client 4xx and planned fault injection | Split auth, message, admin, attachment, readiness |
| Latency | server-side request duration | p95 < 500 ms and p99 < 2 s for non-upload API | Establish under declared hardware/tenant bounds; bcrypt and streaming endpoints separate |
| Correctness | synthetic encrypted writes readable with identical authenticated envelope | 100% sampled checks | Any mismatch is an incident, not an error-budget event |
| Auditability | audited mutations with contiguous verified chain/current checkpoint and guarded authoritative writes admitted only while that witness is healthy | 100% | Any gap or unavailable witness freezes both authoritative paths and consumes all budget; advisory presence/activity is excluded and cannot authorize |
| Backup success | completed encrypted backups copied off-host / scheduled backups | 100% daily | Local artifact creation alone does not count |
| Restore evidence | independently restored and verified selected backups | at least monthly; quarterly full application DR | Record artifact digest, duration, row/object checks, application/audit/client decrypt checks |

## Recovery objectives

| Deployment | RPO objective | RTO objective | Current evidence |
| --- | --- | --- | --- |
| Single host with daily off-host encrypted backup | 24 hours | 8 hours | Backup/isolated data restore tooling exists; full application RTO is not yet measured |
| Single host with operator-supplied PostgreSQL WAL archive and versioned object storage | deployment-defined, target ≤ 15 minutes | target ≤ 4 hours | Not configured or tested by this repository |
| Cluster/multi-AZ | not defined | not defined | Unsupported application topology |
| Multi-region | not defined | not defined | Unsupported; no regional fencing/failover implementation |

If an artifact was never copied away from a failed/compromised host, there is no host-loss RPO guarantee. Browser-held private keys are intentionally absent from server backup; restoration of server data does not guarantee every historical ciphertext remains decryptable on a replacement endpoint.

## Error budget policy

For the provisional 99.5% monthly availability objective, the nominal 30-day budget is 216 minutes. Correctness, authorization isolation, audit-chain integrity, and unrecoverable data loss have zero acceptable budget: they trigger incident response and release freeze regardless of availability performance.

Pause feature releases when either condition occurs:

- more than half the monthly availability budget is consumed before mid-month; or
- any correctness, tenant-isolation, secret-exposure, audit-integrity, or failed-restore event is unresolved.

Resume only after root cause, a regression test or control, and a verified recovery path are recorded.

## Required telemetry

The built-in metrics cover request count/status/latency, DB pool state, password/audit/object-store gate saturation, event-loop delay, memory, and uptime. Operators must add external probe history, host/disk/filesystem metrics, PostgreSQL replication/WAL/backup metrics, object-store capacity/versioning metrics, certificate expiry, backup copy/restore results, and alert delivery. Full distributed tracing is not implemented; trace IDs currently provide log correlation only.
