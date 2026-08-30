# Operations

The canonical operator procedures are:

- [Detailed service operations](./docs/OPERATIONS.md)
- [Deployment and migration](./DEPLOYMENT.md)
- [Reliability and SLOs](./RELIABILITY.md)
- [Backup/restore](./docs/BACKUP.md)
- [Disaster recovery](./DISASTER_RECOVERY.md)
- [Incident runbook](./docs/runbooks/INCIDENT_RESPONSE.md)
- [Risk register](./docs/RISK_REGISTER.md)

## Daily operating contract

- Expose only the TLS reverse proxy; app, probes, metrics, PostgreSQL and object storage remain private.
- Require `/health/ready`, not liveness, for traffic admission.
- Alert on 5xx/rate, p95/p99 latency, event-loop delay, DB/gate saturation, disk/object capacity, checkpoint failures, certificate expiry, backup/timer failures and missing off-host copies.
- Review audit events and access changes without exporting secrets or plaintext.
- Treat `DATA_INVARIANT`, `DATABASE_SCHEMA_*`, `AUDIT_UNAVAILABLE`, repeated object-store limits, and failed restore verification as operator incidents.
- Confirm the daily encrypted backup was copied off-host; run isolated data restore at least monthly and full application DR at least quarterly.
- Patch through a reviewed immutable revision and the migration/backup gate. Do not edit running containers or production data manually.

## Escalation

Authorization isolation, audit-chain failure, secret exposure, data corruption, failed restore, or unexplained deletion is severity 1 regardless of current availability. Freeze writes/releases, preserve evidence, and use the incident runbook. Dependency outage or overload that remains safely contained is severity 2 until an SLO or data-safety threshold is crossed.

The current topology is one process. Starting a second replica is not an availability response.
