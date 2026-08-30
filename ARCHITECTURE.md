# Architecture

Last verified: 2026-08-30

## Status and scope

Alparts is currently a small-team, browser-based encrypted collaboration prototype. The supported runtime topology is one Node.js application process backed by PostgreSQL and one S3-compatible object store. A hardened single-host deployment is provided. Horizontal application scaling, automatic failover, multi-region consistency, and multi-cloud operation are target capabilities, not current guarantees.

The design deliberately keeps the server out of message and attachment plaintext while acknowledging that the served browser origin, endpoint, application process, and authorization metadata remain security-critical.

## Current architecture

```text
Browser SPA
  ├─ WebCrypto: device signatures, channel/file AEAD, local-state AEAD
  ├─ IndexedDB: non-extractable keys, encrypted drafts/outbox
  ├─ REST ───────────────────────────────┐
  └─ Socket.IO / WebRTC signaling ──────┤ exact-origin + live session/device
                                        v
Reverse proxy / TLS boundary -> Node.js Express + Socket.IO (one process)
                                  ├─ route validation / bounded admission
                                  ├─ authentication and RBAC snapshots
                                  ├─ domain services / audited transactions
                                  ├─ in-process realtime and work bulkheads
                                  ├─ PostgreSQL: identity, authz, ciphertext metadata,
                                  │  messages, upload state, audit HMAC chain
                                  ├─ MinIO/S3: encrypted attachment chunks
                                  └─ external checkpoint file: audit tail witness

Operator plane
  ├─ systemd or OCI supervisor
  ├─ structured logs + protected Prometheus endpoint
  ├─ encrypted quiesced backup + isolated restore verifier
  └─ reverse proxy, certificate, database, object-store and off-host backup
     services supplied by the deployment
```

The browser-to-application connection must be TLS-protected outside local development. PostgreSQL, object storage, metrics, probes, and operator interfaces are private endpoints. The application defaults to loopback binding and production dependency TLS.

## Responsibility boundaries

### Web client

`packages/client/src` owns UI state, plaintext rendering, client cryptography, key use, deterministic message projection, encrypted draft/outbox persistence, attachment encryption/decryption, and WebRTC peer handling. Projector verification provenance is process-local rather than a network field; conflicting signed envelopes for one event are quarantined and remain sticky until authoritative reconciliation. It does not authorize server resources, provide OS-backed key custody, independently verify the server's device directory, or guarantee erasure from a compromised endpoint.

### Shared protocol

`packages/shared/src` owns cross-client/server schemas, permission constants, and canonical byte serialization for signed security envelopes. It does not perform persistence or network I/O.

### HTTP and realtime adapters

`packages/server/src/app.ts`, `routes/`, and `websocket/` own transport parsing, origin/session admission, bounded payloads, error mapping, room membership, and invocation of services. They do not directly define business invariants where a service or database constraint can enforce them.

### Domain and policy services

`packages/server/src/services` owns workspace/channel/role/invitation/message/key/upload state transitions. Authorization is centralized in `authorization.service.ts`; cryptographic envelope validation is centralized in `security/message.ts`, attachment contracts, and shared serializers. Mutations recheck authorization while holding a workspace-scoped PostgreSQL advisory lock where concurrent policy changes matter.

### Persistence

`packages/server/src/db` and migrations own the relational model, unique/FK constraints, indexes, statement/connect timeouts, and pool bounds. PostgreSQL is the source of truth for authorization, idempotency, state machines, and audit order. MinIO stores only encrypted attachment chunks and is not a source of authorization truth.

### Cross-store attachment workflow

PostgreSQL and MinIO do not share a transaction. Uploads therefore use a restart-safe reservation/chunk/finalize state machine:

1. reserve and authorize in PostgreSQL;
2. write a bounded encrypted chunk to MinIO outside a DB transaction;
3. re-lock, re-authorize, stat the object, and record chunk metadata;
4. finalize only after the fixed chunk manifest is complete;
5. clean expired reservations and orphan objects conservatively.

This is compensating-state recovery, not atomic cross-store commit. A storage deletion failure retains recoverable metadata/log evidence and may require operator cleanup.

### Audit witness

Security-sensitive state and its audit row commit in one PostgreSQL transaction. This includes message create/edit/delete and replay, reaction/pin changes, channel preferences and bookmarks as well as account, tenancy, key, file-finalization and administration events; audit details contain identifiers, server-generated request ID, trace ID and bounded state only, never ciphertext, signatures, emoji, request bodies or file bytes. Source IP is not retained by the application default; a deployment that needs it must define ingress retention/privacy policy and correlate on request ID. High-frequency/provisional authoritative state that would create disproportionate evidence volume—read cursors and upload-chunk registrations/cleanup—uses the same admission boundary without appending a dedicated row. An HMAC chain is serialized with a database advisory lock. A separately stored, HMAC-authenticated checkpoint is atomically advanced after commit. A process-local audit gate admits one active authoritative commit and at most 64 waiters for at most 30 seconds; saturation fails with `AUDIT_UNAVAILABLE` instead of accumulating work. Checkpoint failure makes readiness and every later authoritative mutation through either path fail closed within the process. The just-committed audited mutation is reported truthfully because it cannot be rolled back after PostgreSQL commit.

Presence and device `lastActiveAt` are explicitly advisory telemetry: they are never authorization, key, quota, retention or recovery inputs, may be omitted, and do not enter the audit gate. This prevents presence traffic from exhausting the correctness boundary. Once readiness fails, ingress must drain traffic; a late advisory update is not evidence that an authoritative mutation was admitted.

The checkpoint is independent only when its write/delete authority is separated from the database operator. Process-local admission means more than one application process is unsupported. A crash between database commit and external checkpoint durability can be reconciled on restart when the intact DB chain descends from the prior witness, but this is not a multi-writer consensus or WORM ledger.

## Consistency and concurrency

- PostgreSQL transactions and unique constraints protect durable invariants and idempotency keys.
- Workspace-scoped advisory locks serialize membership, role, channel, key-recipient, and viewer-impact transitions.
- A shared user advisory lock serializes workspace creation with invitation acceptance so the per-user membership quota cannot race.
- Bulk authorization snapshots replace per-item DB authorization calls. Every snapshot checks explicit tenant limits before materializing data.
- Replacement-device enrollment locks at most 50 memberships in stable order and reconciles provisional key epochs one workspace at a time. Each pass is bounded by the durable 300-channel workspace ceiling, so another tenant cannot consume an account-global cleanup cap and permanently prevent enrollment.
- In-process gates bound password hashing, audit commits, object-store work, downloads, HTTP bodies, sockets, voice participants, uploads, and selected background work.
- Browser work is finite as well: encrypted outbox entries, authorization reconciliation, WebRTC signaling/ICE, attachment runtimes, and tracked channel-key scopes have explicit ceilings; every API response has a 60-second total deadline and caller cancellation propagates to `fetch`. Draft persistence coalesces to one running and one latest pending write per channel. Message verification uses one active plus one coalesced pending pass per channel, a cancel-aware 30-second lifetime, at most 64 parallel crypto operations, and resident windows of 1,000 events/channel, 5,000 events total, and 32 channels. Cancelled work continues to occupy its bounded slot until it actually unwinds.
- Time stored in PostgreSQL and protocol timestamps is UTC. Timeouts use elapsed timers where possible; authorization/session expiry uses wall time and assumes a reasonably synchronized host clock.

Process-local gates, rate limits, upload locks, Socket.IO rooms, and the audit admission queue are why multiple application replicas are not safe today.

## Secure and bounded defaults

The canonical server bounds are in `packages/server/src/security/limits.ts`. Important ceilings include 50 workspace members, 8 active devices and 16 active sessions per user, 100 normal channels plus 200 DMs per workspace, 50 DMs created by one user per workspace, 32 roles, 16 role assignments per member, 100 active/1,000 retained invitations, 1,000 bookmarks and pins, 1,000 reactions per message, 16 pending uploads per user/200 per workspace, 400 atomic key recipients, 64 explicitly requested historical signing identities per directory lookup, 64 explicitly requested key versions, and a 16-version deprecated compatibility window. Current/historical key responses have an absolute 864-delivery ceiling. Request bodies, header counts, request/statement/connect timeouts, DB pool size, sockets, downloads, password/audit/object-store work, and object listings are also bounded. The browser keeps at most 100 encrypted outbox commands per device and finite message/realtime/attachment work.

Quota checks execute under the same logical lock as insertion. Migration `0013_bounded_tenant_indexes.sql` refuses to establish the new runtime contract when legacy rows already exceed a cap; it does not silently delete or truncate data.

## Availability behavior

- Liveness answers only whether the process can execute.
- Startup reports whether the process is still accepting startup responsibility.
- Startup and readiness compare every applied migration timestamp/hash with the exact bundled migration journal and the bounded expected PostgreSQL 16 `public` catalog fingerprint, then check PostgreSQL, MinIO, and the audit checkpoint; persistent schema/image drift or drain fails closed. The database must be dedicated to Alparts; this does not validate row contents, database roles/grants, objects outside `public`, or physical durability.
- A dependency outage removes readiness but does not deliberately crash the process.
- SIGTERM/SIGINT stops admission, disconnects realtime clients, stops the cleanup scheduler, drains HTTP for a bounded period, flushes audit state, closes DB connections, and exits.
- Uncaught exceptions and unhandled rejections trigger the same bounded shutdown and a non-zero exit so a supervisor can restart the service.
- Authentication and storage overload return bounded 503 responses with `Retry-After`; queues and retries are finite.

The service remains a single failure domain unless its external database/object store and host are separately protected. See [capability levels](./docs/deployment/CAPABILITY_LEVELS.md).

## Observability

Logs are structured JSON with UTC timestamp, severity, component/operation, outcome, request ID, trace ID, actor ID, and tenant ID when known. Error objects are reduced to safe name/code; secrets and request bodies are not logged. W3C `traceparent` is validated and propagated as correlation context, but a full OpenTelemetry exporter is not implemented.

The optional bearer-protected Prometheus endpoint reports HTTP rate/status/latency, DB pool saturation, password/audit/object-store gate saturation, event-loop delay, memory, and uptime. It is disabled by default and should remain privately routed even when token-protected.

## Improved and target architecture

The current changes move the prototype from implicit/unbounded single-node behavior to an explicit bounded single-process appliance model: safe bind/TLS defaults, fail-closed configuration, bulk authorization snapshots, durable quotas, bounded remote listings, audit write admission, structured telemetry, supervised backup, pinned CI actions, source/final-image security scanning, image-coupled migrations, patched pinned runtime libraries, and production packaging without JavaScript package-manager tooling.

Further scale must be additive, not an environment-detection shortcut:

1. replace process-local rate/gate/room/lock state with an authenticated shared coordination plane;
2. retain PostgreSQL uniqueness and transactions as the final invariant guard;
3. use a Socket.IO distributed adapter with revocation fencing and tested partition behavior;
4. replace the file witness with an append-only external witness supporting multi-writer compare-and-swap;
5. add database HA/PITR and versioned/object-locked storage before claiming node/AZ durability;
6. define one primary write region or a formally fenced conflict model before multi-region writes;
7. test restore/failover under the exact topology and publish measured RPO/RTO.

No configuration in the current repository automatically enables these claims. Security controls never disable themselves when deployment capabilities are absent.
