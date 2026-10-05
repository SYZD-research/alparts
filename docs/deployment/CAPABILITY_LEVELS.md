# Deployment capability levels

The levels describe what an environment can make possible; they do not upgrade the application automatically. Current Alparts support stops at Level 1 for application compute.

| Level | Topology | Current status | Can reasonably guarantee | Cannot guarantee / required additions |
| --- | --- | --- | --- | --- |
| 0 | one process, ephemeral or non-durable dependencies | development only | bounded process behavior, auth/authz/crypto semantics during runtime | durability, host recovery, useful RPO/RTO |
| 1 | one host/process + durable PostgreSQL/object storage + supervisor + backup | supported production-pilot template | restart recovery, transactional DB state, bounded resource use, quiesced encrypted backup, explicit health | host/disk SPOF unless dependencies/backups leave host; no zero-downtime deploy |
| 2 | one host + redundant app process | unsupported | none beyond Level 1 today | process-local Socket.IO, gates, locks and audit admission must be shared/fenced; active-passive supervisor may only start exactly one fenced process |
| 3 | multi-node, one site | unsupported app topology | external DB/object storage may be multi-node behind one app process | distributed room/rate/upload/audit coordination, fencing and partition tests |
| 4 | multi-AZ | unsupported app topology | dependency AZ redundancy may reduce storage outages | application replica safety, AZ failover exercise, PDB/HPA semantics, shared witness |
| 5 | multi-region | unsupported | off-region encrypted backups can improve recoverability | consistency/leader/conflict model, lag policy, split-brain fencing, routing and tested RPO/RTO |
| 6 | multi-cloud | unsupported | independent backup custody can reduce common-mode risk | portable identity/KMS/network control, reproducible signed artifacts, cross-cloud failure and legal/operational model |

## Level 0: development

- Bind only loopback and use synthetic data.
- Disposable PostgreSQL/SeaweedFS is acceptable.
- Security semantics remain enabled; production secrets and public traffic are prohibited.
- No durability statement is valid.

## Level 1: current appliance baseline

Required:

- exactly one Alparts application process;
- durable PostgreSQL with WAL/fsync and monitored storage;
- durable private S3-compatible storage;
- systemd/OCI restart supervision and bounded resources;
- public TLS reverse proxy, exact origin, backend TLS except explicit local loopback;
- required, durable audit checkpoint and separately protected integrity key;
- daily encrypted quiesced backup, off-host copy, retention, and restore exercises;
- host filesystem/capacity/certificate/time/process monitoring.

Possible: safe process restart, local transaction integrity, tamper-evident audit under stated authority split, and recovery to the latest verified artifact. Impossible: survival of an unrecoverable host plus same-host backup loss, zero downtime, automatic failover, or quorum claims.

## Level 2: active-passive only after fencing

A supervisor may keep a cold spare, but only one process may access the deployment at a time. Promotion needs a durable fencing token that prevents the old process from writing or serving rooms. Merely configuring two `Restart=always` services is not redundancy; it is unsafe concurrent operation.

## Levels 3–4: required engineering

- shared authenticated rate/admission counters and bounded queues;
- distributed Socket.IO adapter with revocation-before-delivery ordering;
- PostgreSQL-backed or equivalent fenced upload/job ownership;
- external append-only audit witness with atomic multi-writer compare-and-swap;
- replicated DB/object storage with tested failover and consistent recovery point;
- load tests, partition/failover/duplicate-job/clock-skew tests;
- rolling compatibility contract and migration expand/contract phases.

Kubernetes Deployment/PDB/HPA/probes can orchestrate these controls after they exist. Kubernetes alone does not create them, so this repository intentionally does not ship a misleading multi-replica manifest.

## Levels 5–6: required engineering

Choose and document one:

- a single write region with lease/fencing and read-only/degraded remote regions; or
- a domain-specific multi-writer conflict model that preserves membership, authorization, audit and key-epoch invariants.

Define replication lag exposure, failover decision authority, RPO/RTO, DNS/load-balancer behavior, checkpoint/witness placement, credential/KMS portability, data residency, and recovery of client-held keys. Perform scheduled regional evacuation and split-brain tests. Until then, use off-region backups only and label the deployment Level 1.

## Graceful capability degradation

Loss of an optional capability may remove a feature: no TURN can disable calls; no object store can disable attachments; no metrics collector can remove dashboards. It must never disable authentication, authorization, origin checks, encryption verification, audit integrity, or data consistency. If a required safety dependency is absent, readiness fails closed.
