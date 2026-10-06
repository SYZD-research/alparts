# System inventory

Last verified: 2026-09-04. This inventory covers first-party source, build, test, deployment, and operating artifacts. Generated `dist/`, dependency trees, `.git`, and ignored local secret files are not implementation sources.

## Repository map

| Location | Contents | Owner boundary |
| --- | --- | --- |
| `packages/client/src` | React SPA, browser crypto, stores, WebRTC, UI tests | Endpoint/plaintext plane |
| `packages/desktop` | Electron main/preload, OS vault, native file save, package configuration | Desktop host boundary |
| `packages/server/src/routes` | REST adapters and validation | HTTP boundary |
| `packages/server/src/websocket` | Socket.IO admission, rooms, presence, typing, voice | Realtime boundary |
| `packages/server/src/services` | Domain state transitions, authorization, storage adapter | Application/domain plane |
| `packages/server/src/security` | Limits, session/envelope checks, bounded gates, logging | Cross-cutting security policy |
| `packages/server/src/middleware` | auth/RBAC/origin/body/rate/audit/request context | Request policy boundary |
| `packages/server/src/db` | Drizzle schema, pool, migrations | Durable relational state |
| `packages/shared/src` | Protocol types/constants/canonical serializers | Shared pure contract |
| `scripts` | backup, restore verification, retention, safety tests | Operator data plane |
| `deploy` | systemd app/backup units | Single-host supervisor plane |
| `.github` | CI, CodeQL, dependency updates | Supply-chain plane |
| `Dockerfile`, Compose files | OCI build, development dependencies, production app profile | Packaging/deployment plane |
| `docs`, root Markdown | Architecture, risk, operations, specification | Governance plane |

## Major components

### Browser application

- **Location:** `packages/client/src/App.tsx`, `components/`, `stores/`, `services/`.
- **Purpose/responsibility:** authenticated UI, plaintext presentation, message projection, client-side crypto, encrypted draft/outbox, attachment transfer, realtime synchronization, WebRTC calls.
- **Non-responsibility:** authoritative access control, server durability, key transparency, OS secure storage, malware scanning, background push.
- **Input/output:** validated REST/Socket.IO JSON and user/device APIs; signed encrypted envelopes, encrypted chunks, UI/media output.
- **External/internal dependencies:** browser WebCrypto, IndexedDB, MediaDevices/WebRTC; shared protocol and server APIs.
- **Persistence:** non-extractable `CryptoKey` objects and encrypted local state in same-origin IndexedDB; decrypted data in memory.
- **Security boundary:** served origin and endpoint are trusted; URL schemes and active attachment types are restricted; logout/revocation performs scoped best-effort cleanup.
- **Failure/retry/idempotency:** durable server events are deduplicated; outbox uses stable idempotency keys and capped exponential/jitter retry; every API response has a 60-second total deadline and propagates caller cancellation; missing keys fail closed rather than showing ciphertext as plaintext. Draft writes coalesce to one running and one latest pending operation per channel.
- **Scaling/availability:** per browser; no cross-device local-state replication. Each device stores at most 100 encrypted outbox commands. Message verification has one active plus one coalesced pending pass per channel, a cancel-aware 30-second lifetime, 64-way crypto batches, and resident ceilings of 1,000 events/channel, 5,000 events total and 32 channels; cancelled work retains its slot until it unwinds, and unloaded/evicted state reconciles from REST. Authorization/voice queues, attachment runtimes, and key-scope history are also bounded. Server outage preserves already encrypted local drafts but blocks durable collaboration.
- **Operate/test:** serve only the built same-origin bundle with CSP; `pnpm --filter @alparts/client test`, typecheck, build.

### Desktop host

- **Location:** `packages/desktop/src`, `packages/desktop/scripts`, package build configuration, `.github/workflows/desktop.yml`.
- **Purpose/responsibility:** package the shared client for Windows/macOS/Linux, serve only bundled UI assets at the selected deployment origin, protect endpoint keys with the OS, lock local plaintext state, and stream decrypted attachments to a user-selected file.
- **Non-responsibility:** authoritative authorization, server TLS termination, Passkey/OIDC, signed automatic updates, notarization, or mobile clients.
- **Input/output:** one validated HTTPS deployment origin (loopback HTTP only for development), a narrow context-bridge API, encrypted OS-vault records, and user-selected attachment files.
- **Dependencies/persistence:** Electron `safeStorage`, Chromium session storage, Windows DPAPI/macOS Keychain/Linux Secret Service, opaque files under Electron user data. Linux plaintext fallback is rejected.
- **Security boundary:** sandbox and context isolation are mandatory; Node integration/webviews/renderer navigation/display capture are disabled; IPC accepts only the top frame of the one trusted window; external URLs go to the system browser; CSP prevents remote application code.
- **Failure/retry/idempotency:** invalid origins and vault records fail closed. Settings/vault writes use same-directory temporary files and rename. Attachment saves are limited to two active handles, 100 MiB/file and 5 MiB/write; partial files are removed on failure/cancel/quit.
- **Scaling/availability:** one local process and one window. Every deployment has a separate cookie/storage/vault namespace; changing it clears the old namespace.
- **Operate/test:** see `docs/DESKTOP.md`; run desktop unit/type checks, native platform packaging, fuse inspection, and signed-release verification.

### Cryptographic protocol and channel-key state

- **Location:** `packages/shared/src/security`, client `crypto.service.ts`, server `security/message.ts`, `services/key*.ts`.
- **Purpose/responsibility:** canonical signed representations, P-256 device signatures, AES-256-GCM message/attachment protection, recipient-bound key wraps, two-phase key epoch activation.
- **Security update:** MLS-based epoch groups, signed device-directory history, client checkpoint comparison and encrypted history recovery are described in [the protocol document](security/ACCOUNT_AND_GROUP_SECURITY.md). Per-message forward secrecy, independent witness operation and account credential reset remain outside this implementation.
- **Input/output:** device keys, ciphertext metadata and signatures; verified plaintext only on authorized clients.
- **Dependencies/persistence:** WebCrypto; PostgreSQL device public keys, commitments, epoch state, acknowledgements, and wrapped keys; private keys remain client-side.
- **Security boundary:** every message/key/attachment/voice envelope binds its operation, resource, author/device, and security-relevant metadata. Server and recipient both enforce applicable bindings.
- **Failure/retry/idempotency:** malformed/stale/uncommitted envelopes fail closed; aborted versions are never reused; delivery acknowledgements are idempotent against unique state. If all accepted holders are lost, archived keys may be restored using the user-held code; without an archive, `historyRecoveryRequired` permits only a fresh future epoch. A manager/DM participant may also explicitly start without unavailable history after exact-action step-up and device-signature verification. Every eligible endpoint must contribute and acknowledge the fresh group epoch; offline endpoints can block writes.
- **Scaling/availability:** atomic fan-out is capped at 400 active recipient devices. Explicit history lookup is at most 64 versions/864 deliveries; the deprecated no-query bridge is the newest 16 versions. Key rotation blocks new writes until safely active.
- **Operate/test:** protocol vectors and tamper cases in shared/server/client unit tests plus integration flow.

### HTTP API

- **Location:** `packages/server/src/app.ts`, `routes/`, `middleware/`.
- **Purpose/responsibility:** exact-origin browser boundary, authentication, RBAC adapters, schema validation, bounded body/rate admission, status/error mapping, static production SPA.
- **Non-responsibility:** TLS termination, long-lived business invariants, distributed throttling.
- **Input/output:** JSON REST, cookies or explicit bearer tokens; JSON/errors, ciphertext streams, health and optional metrics.
- **Dependencies/persistence:** Express/Helmet/CORS; delegates all durable work to services/PostgreSQL/the S3-compatible object store.
- **Security boundary:** no public admin bypass; protected resources require live DB-backed session and current membership/permission. Production defaults secure cookies, CSP/HSTS, and exact HTTPS origins.
- **Failure/retry/idempotency:** 512 KiB default JSON ceiling (2 MiB for bounded group proposals), request/header/server timeouts, bounded admission; stable 4xx/503 responses. Mutation idempotency is service-specific.
- **Scaling/availability:** one process only because rate and other admission state is local.
- **Operate/test:** health endpoints and private metrics; HTTP security, configuration and integration suites.

### Authentication, sessions, and devices

- **Location:** `routes/auth.ts`, `routes/devices.ts`, `services/auth.service.ts`, `device.service.ts`, `security/session.ts`, `password-work.ts`.
- **Purpose/responsibility:** invite-gated registration, bcrypt password verification, hashed session-token persistence, session/device binding, challenge-based device enrollment/revocation.
- **Security update:** WebAuthn/Passkeys and exact-action step-up are implemented. OIDC, email delivery, native-origin WebAuthn and threshold recovery remain outside this implementation.
- **Input/output:** email/password/invite/challenge/device public keys; secure session cookie or explicit token, public device directory.
- **Dependencies/persistence:** bcrypt, JWT HS256, cryptographic RNG, PostgreSQL users/devices/sessions/invitations.
- **Security boundary:** cheap invite preflight occurs before password hashing; bcrypt has separate public/authenticated pools of at most two Worker threads each; public admission is 2-active/0-pending through audit completion and authenticated admission is 2-active/16-pending/5-seconds, validates pepper-protected stored format and cost 12–15 before work, and terminates a Worker after a 30-second execution watchdog; current-password KDF completes before audit/key/row locks; live session hash/expiry/revocation and active device are rechecked.
- **Failure/retry/idempotency:** capacity returns 503/Retry-After; at most 16 unexpired sessions/user and 8 active devices/user are admitted; tokens/invitations are single-use where applicable; revoked identity cannot be silently rebound. New-device pending-epoch cleanup is partitioned across at most 50 memberships and 300 channels/workspace. Historical signer lookup is explicitly scoped to at most 64 requested IDs; the deprecated no-ID bridge is capped at 400 current/referenced devices.
- **Scaling/availability:** password gate and rate limits are process-local; cluster use is unsupported.
- **Operate/test:** rotate all deployment secrets, revoke compromised sessions/devices; auth/device unit and integration cases.

### Tenant authorization and administration

- **Location:** `authorization.service.ts`, workspace/channel/role/invitation/permission-override services and routes.
- **Purpose/responsibility:** workspace isolation, ownership, role hierarchy/bitmasks, category/channel overrides, private membership, invitations, viewer-impact/revocation events.
- **Non-responsibility:** cross-organization federation, ABAC policy language, directory synchronization, cluster-wide coordination.
- **Input/output:** authenticated principal/resource IDs and requested mutations; authorized records, effective permissions/reasons, revocation/rekey notifications.
- **Dependencies/persistence:** PostgreSQL membership, roles, assignments, revisions, overrides and invitations.
- **Security boundary:** missing membership/tenant context denies access. Bulk snapshots are bounded and evaluated in memory; mutation-time locks prevent stale authorization decisions.
- **Failure/retry/idempotency:** database failures roll back; quota/invariant failures are explicit. Invitations are hashed, expiring, single-use, and revocable.
- **Scaling/availability:** 50 members/workspace, 50 memberships/user, 20 owned workspaces, 32 roles, 16 assignments/member, 100 normal channels, 50 categories, bounded invites.
- **Operate/test:** inspect quota and data-invariant 503 alerts; management unit tests and full integration authorization matrix.

### Messaging, state, and direct messages

- **Location:** `message.service.ts`, `dm.service.ts`, message/DM/user-state routes, matching client stores.
- **Purpose/responsibility:** encrypted event persistence, edit/delete/reaction/pin/read/preference/bookmark state, direct-message membership/channel creation.
- **Non-responsibility:** server plaintext search, global retention/export, guaranteed remote deletion, message broker delivery.
- **Input/output:** signed ciphertext events and bounded queries; durable events/snapshots and realtime notifications.
- **Dependencies/persistence:** PostgreSQL messages, compact reaction/pin state, read positions, preferences, bookmarks, DM provenance/members.
- **Security boundary:** message and channel authorization is resolved from current tenant state; DMs are isolated from generic channel mutation paths.
- **Failure/retry/idempotency:** message IDs/idempotency and event projection deduplicate exact retries. Message create/edit/delete/replay, reaction/pin, preferences and bookmarks commit an audit row atomically; read positions use the same fail-closed admission without per-cursor audit volume. Verification provenance is process-local, and a second non-identical signed envelope for one event is sticky-quarantined rather than overwriting the first. DMs have a separate workspace cap (200) and per-creator cap (50); normal channel capacity remains reserved.
- **Scaling/availability:** server list pages and saved state are bounded; the browser retains a finite 1,000-event/channel and 5,000-event/32-channel working set. Each channel has at most 1,000 pins and each message at most 20 distinct emoji, 20 reactions/user and 1,000 reactions total. There is no DM archive/reclaim workflow, so the total workspace cap still requires operator-visible product lifecycle work.
- **Operate/test:** API integration tests, deterministic projector/unit tests; monitor quota responses.

### Realtime, presence, typing, and voice

- **Location:** `packages/server/src/websocket`, client `socket.ts`, presence/voice stores and voice UI.
- **Purpose/responsibility:** authenticated rooms, message notifications, presence/typing, signed WebRTC SDP/ICE relay, bounded participant registry.
- **Non-responsibility:** durable queue, offline push, SFU/SFrame, recording, video/screen sharing, distributed room state.
- **Input/output:** Socket.IO events and signed signaling; room/event delivery and peer-to-peer DTLS-SRTP media.
- **Dependencies/persistence:** Socket.IO in process; PostgreSQL live session/authorization. Typing/voice registry is ephemeral; presence and device activity timestamps are advisory PostgreSQL telemetry that may be omitted and are never authorization inputs.
- **Security boundary:** handshake is admitted before DB work, room joins are serialized with authorization revision checks, signaling binds channel/participant/device/sequence, clients verify before WebRTC use.
- **Failure/retry/idempotency:** disconnect clears ephemeral state; reconnect rehydrates bounded memberships. Presence/typing/activity loss degrades safely and stays outside authoritative audit admission; messages remain durable via REST/DB.
- **Scaling/availability:** one process, maximum 8 voice participants/channel; P2P mesh and NAT traversal depend on configured STUN/TURN.
- **Operate/test:** socket expiry/origin/budget/room-race and voice tests plus integration.

### Attachment workflow and object storage adapter

- **Location:** file routes, `file.service.ts`, `object-storage.ts`, `attachment-contract.ts`, client attachment services/store.
- **Purpose/responsibility:** bounded reservations, fixed 5 MiB encrypted chunks, resume/finalize/cancel/download, storage reconciliation.
- **Non-responsibility:** plaintext inspection, malware disarm, atomic PostgreSQL+object-store commit, secure erasure from all replicas.
- **Input/output:** inert ciphertext/octet streams and signed manifests; authorized ciphertext chunks.
- **Dependencies/persistence:** S3-compatible object bytes (SeaweedFS recommended) through the AWS SDK for JavaScript v3; PostgreSQL upload/chunk/attachment metadata.
- **Security boundary:** opaque strict object keys, prefix grammar, key/count/byte bounds, active-content download defenses, reauthorization around remote operations.
- **Failure/retry/idempotency:** header/inactivity/absolute listing deadlines; bounded active/pending gates; at most 16 pending reservations/user, 200/workspace, 4 outstanding operations/upload and 64/process; idempotent chunk state and conservative orphan cleanup. Reservation/cancel/finalize are audited; provisional chunk registration and cleanup use common fail-closed admission. External writes receive a preflight but remain compensating-state operations. No unbounded retries.
- **Scaling/availability:** bounded per-user/global downloads and remote work; the official client admits 16 active attachment runtimes and retains at most 64 task records. Object-store outage fails readiness and attachment operations, while already loaded text may remain usable.
- **Operate/test:** alert on storage-limit/timeout errors, run cleanup, reconcile only scoped prefixes; unit fault tests and PostgreSQL/SeaweedFS integration.

### PostgreSQL and migrations

- **Location:** `db/schema.ts`, `db/index.ts`, `db/migrations`, Drizzle config.
- **Purpose/responsibility:** durable source of identity, authorization, crypto metadata, message state, upload state, and audit order.
- **Non-responsibility:** attachment bytes, browser private keys, automatic HA/PITR.
- **Input/output:** parameterized Drizzle/SQL transactions; relational rows and locks.
- **Dependencies/persistence:** PostgreSQL major 16 with a dedicated Alparts `public` schema; bounded pool (default 10), 5-second connect and 15-second statement timeouts.
- **Security boundary:** least-privilege runtime and separate migration/backup roles are deployment requirements. Remote production connections require TLS by default.
- **Failure/retry/idempotency:** failed transactions roll back; no generic automatic write retry. Migrations are forward-only files, journaled, and the quota migration preflights incompatible legacy data. Startup and readiness use one repeatable-read read-only snapshot to compare the complete applied timestamp/hash sequence and a bounded exact PostgreSQL 16 public-catalog fingerprint. Missing, extra, reordered, altered, or persistently drifted schemas fail closed; row contents/roles/grants/physical settings are outside this fingerprint.
- **Scaling/availability:** external PostgreSQL may be local durable, HA, or managed; application still remains single-writer-process. Database failure removes readiness.
- **Operate/test:** backup/restore gate before destructive migration, fresh migration/replay in CI, integration suite, and migration/start smoke from the final OCI artifact.

### Audit trail

- **Location:** `middleware/audit.ts`, `audit-log.service.ts`, audit routes/UI, checkpoint initializer.
- **Purpose/responsibility:** actor/action/target/outcome records, atomic state+audit rows, HMAC chain, external tail witness, tamper/truncation detection.
- **Non-responsibility:** WORM/SIEM retention, non-repudiation against the application key holder, multi-process consensus.
- **Input/output:** security mutations/read events plus guarded high-frequency authoritative writes; append-only actor/time/action/target/outcome/request/trace rows and signed checkpoint JSON.
- **Dependencies/persistence:** PostgreSQL audit table, `AUDIT_INTEGRITY_KEY`, atomic local/independent filesystem checkpoint.
- **Security boundary:** checkpoint authority should differ from DB authority; log details must exclude request bodies, tokens, passwords, keys and plaintext. Source IP is an ingress-policy concern and is correlated through the server-generated request ID rather than retained by default.
- **Failure/retry/idempotency:** a one-active/64-pending process gate with a 30-second admission deadline bounds audited and guarded authoritative commit work; the chain lock serializes append; checkpoint I/O failure fails readiness and every later authoritative write closed until the missed checkpoint is rewritten; transient failures are retried at most every 2 seconds, integrity failures stay latched. The audit head uses its own object-storage connections and concurrency, separate from downloads. Presence/activity timestamps are explicitly non-authoritative and excluded. Startup scans in 1,000-row batches.
- **Scaling/availability:** one application process. Audit unavailability or admission saturation deliberately sacrifices writes to preserve evidence integrity; gate depth is exported as a metric.
- **Operate/test:** never re-provision after unexplained loss; preserve evidence and follow incident runbook. Unit missing-anchor and integration truncation tests.

### Configuration and secret loading

- **Location:** `config/index.ts`, validation helpers, `.env.example`, systemd/Docker secret mappings.
- **Purpose/responsibility:** typed/ranged startup validation, safe defaults, `VALUE` xor `VALUE_FILE`, production TLS/origin/audit requirements.
- **Non-responsibility:** fetching cloud KMS/Vault secrets directly or rotating external credentials.
- **Input/output:** built-in defaults plus environment or protected secret files; immutable process configuration.
- **Dependencies/persistence:** OS environment/files, Docker/systemd credential facilities; no app persistence.
- **Security boundary:** secret files are regular, at most 64 KiB, not group/other writable in production; values are not logged.
- **Failure/retry/idempotency:** invalid/dangerous configuration aborts startup. Insecure dependency transport is allowed only by explicit acknowledgement for loopback/unix-socket deployment.
- **Scaling/availability:** each process validates independently; configuration drift detection is an operator/release concern.
- **Operate/test:** configuration unit tests, deployment preflight, tracked-file secret scan.

### Health, telemetry, and lifecycle

- **Location:** `app.ts`, `index.ts`, `observability/metrics.ts`, structured logger/request context.
- **Purpose/responsibility:** liveness/startup/readiness, safe log correlation, protected metrics, cleanup scheduling, bounded shutdown.
- **Non-responsibility:** external alert routing, dashboarding, log retention, OpenTelemetry export, supervisor implementation.
- **Input/output:** process/dependency state and request lifecycle; JSON logs, health JSON, Prometheus text.
- **Dependencies/persistence:** Node process/perf hooks, DB pool and gate snapshots; telemetry is not persisted by the app.
- **Security boundary:** metrics disabled by default and requires a 32-byte bearer secret when enabled; identifiers are context fields, not raw request content.
- **Failure/retry/idempotency:** dependency failure makes readiness 503 without forcing restart. Cleanup cannot overlap. Fatal errors trigger drain then exit 1.
- **Scaling/availability:** per-process metrics and state only.
- **Operate/test:** private scrape, rate/error/latency/saturation alerts; probe deployment gates and shutdown tests/manual smoke.

### Packaging, CI, deployment, backup and restore

- **Location:** `Dockerfile`, Compose files, `deploy/`, `.github/`, `scripts/`.
- **Purpose/responsibility:** immutable build inputs, nonroot/read-only runtime patterns, CI gates, supervised restart, encrypted quiesced backups, retention safety, isolated restore verification.
- **Non-responsibility:** issuing TLS certificates, provisioning cloud infrastructure, automatic database/object-store HA, release signing currently, off-host transfer currently.
- **Input/output:** source/lockfile/config/secrets; OCI image, CI reports/SBOM, encrypted `.tar.age` backup and verification result.
- **Dependencies/persistence:** Node/pnpm, Docker/systemd, pg tools, `rclone`, `age`, independent backup media.
- **Security boundary:** pinned GitHub actions, frozen lockfile, secret/dependency/CodeQL/Trivy source and final-image gates; the final image removes npm/Corepack/store/cache tooling, and the production container drops capabilities and binds host port to loopback.
- **Failure/retry/idempotency:** image build is reproducible from lockfile but not bit-for-bit guaranteed; the image carries its exact migration bundle and a non-waiting advisory-locked database-only migrator using a separately scoped secret; backup refuses concurrent/non-quiesced runs and never overwrites; retention is dry-run by default and requires exact acknowledgement.
- **Scaling/availability:** systemd/Compose address single host. External HA services can reduce storage failures but cannot make the current app horizontally safe.
- **Operate/test:** CI, Docker build/health smoke, systemd preflight, daily timer, off-host copy, periodic isolated restore/full DR exercise.

## Durable data model

| Domain | Tables |
| --- | --- |
| Identity | `users`, `devices`, `sessions` |
| Tenancy/RBAC | `workspaces`, `workspace_members`, `roles`, `member_roles`, `workspace_invitations` |
| Channel policy | `categories`, `channels`, `channel_members`, category/channel role overrides |
| Key protocol | `channel_keys`, `channel_key_epochs`, `channel_key_epoch_recipients` |
| Messaging/user state | `messages`, `message_pins`, `message_reactions`, `read_positions`, `channel_preferences`, `message_bookmarks` |
| Direct messages | `dm_conversations`, `dm_members`; DMs also have a channel row |
| Attachments | `attachments`, `attachment_uploads`, `attachment_upload_chunks`; ciphertext bytes are in object storage |
| Audit | `audit_logs`; the current tail witness is outside PostgreSQL |

All durable schema changes are in the ordered migration journal. There is no separate broker, cache server, scheduler database, or background worker process.

## Tests and tools

- Server unit/security tests: `packages/server/src/**/*.test.ts`.
- PostgreSQL+object-store boundary test: `packages/server/src/security/integration.test.ts` with `RUN_INTEGRATION=1`.
- Client state/protocol tests: `packages/client/src/**/*.test.ts(x)`.
- Backup/restore safety tests: `scripts/tests/backup-security.test.sh`.
- CI: build, lint, typecheck, unit, integration, backup safety, secret/dependency scan, CodeQL, Trivy, SBOM.
- Operator tools: audit checkpoint initializer, backup, pre-migration gate, restore verifier, retention, systemd backup wrapper.
