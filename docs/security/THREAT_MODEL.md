# Threat model

Last reviewed: 2026-09-16

## Scope

This model covers the current Web and Windows/macOS/Linux Electron clients, the single-process Alparts server, its PostgreSQL and S3-compatible storage dependencies, endpoint-held cryptographic state, operator backup/restore tooling, container/systemd/desktop packaging, and CI supply chain. It is not approval for regulated, embargoed, credential-vault, or other high-impact secret use. `SPECIFICATION.md` contains future requirements and is not assumed implemented.

See [account/group security](ACCOUNT_AND_GROUP_SECURITY.md) for the updated device, directory, epoch, authentication and recovery threat boundaries.

## Security objectives

1. A principal without current membership/permission cannot read, mutate, subscribe to, or receive keys for another tenant/resource.
2. The server/database/object store do not receive message or attachment plaintext in the intended client flow.
3. Signed/AEAD data cannot be relocated, replayed as another operation, or attributed to another user/device without detection.
4. Revocation prevents future session/device/room/key use; it does not erase ciphertext/plaintext already received by an authorized endpoint.
5. Attacker-controlled resource use remains bounded and cannot consume unbounded CPU, memory, DB queries/connections, queues, objects, or tenant metadata.
6. Security-sensitive state changes are attributable and tamper-evident; audit failure denies later authoritative mutations rather than silently discarding evidence. Advisory presence/activity is never a security decision input.
7. Secrets remain outside tracked source, images, logs, argv and public endpoints; production transport and defaults fail closed.
8. Recovery never requires destructive in-place restore and can validate database/object consistency before cutover.

## Assets

- message, attachment, draft/outbox and voice plaintext;
- endpoint device private keys, local-state keys, channel/file keys and wrapped key history;
- password hashes, invitation tokens, session capabilities, device identities and revocation state;
- workspace membership, role/override/private-channel policy and tenant metadata;
- server-readable profile data (display name, bio, avatar PNG) and per-workspace profile warnings;
- encrypted message events, attachment chunks, signatures, commitments and key-epoch state;
- PostgreSQL integrity/availability, MinIO ciphertext objects and storage credentials;
- audit HMAC chain, integrity key, external checkpoint and independently retained evidence;
- encrypted backup artifacts, age identity, deployment credentials/config and recovery inventory;
- source, lockfile, CI credentials, OCI/release artifact, served Web bundle, packaged desktop bundle and update channel;
- availability capacity: event loop, memory, DB pool, storage gates, sockets, disk and network.

## Actors

- unauthenticated Internet client sending malformed, replayed, cross-origin, or high-rate traffic;
- authenticated ordinary member or cross-tenant user;
- delegated workspace/channel/role manager abusing valid cost or policy authority;
- removed member, revoked device, or holder of a stolen but still-live session;
- malicious authorized endpoint controlling its signed ciphertext, URLs, files, SDP/ICE and timing;
- malicious dependency/build/release actor, compromised served Web origin, or modified desktop package;
- PostgreSQL, object-store, TURN, network, backup-storage, host or cloud operator/attacker;
- authorized operator making a configuration, migration, retention, restore or credential mistake;
- disaster/ransomware causing loss or unavailability without a malicious application request.

## Trust boundaries

1. **Browser endpoint/origin.** Plaintext and usable non-extractable keys exist here. Non-extractable prevents key export, not malicious same-origin use. A compromised endpoint/origin is outside E2EE protection for that endpoint.
2. **Desktop host/renderer.** The renderer uses packaged UI assets under Chromium sandbox and context isolation. A top-frame-only preload mediates protected storage, lock settings, and bounded native saves. OS protection reduces offline key theft but cannot protect keys from authorized code while the user session is running. The package, OS account, and IPC surface are trusted endpoint boundaries.
3. **Client ↔ ingress.** Public TLS/reverse proxy is deployment-owned. Web and desktop cookie mutations and sockets use the deployment's exact allowed Origin; originless automation requires an explicit bearer capability.
4. **Authentication/session.** Untrusted credentials cross into invite lookup and bounded bcrypt; protected routes then cross a DB-backed live token/session/device check.
5. **Tenant authorization.** Every workspace/channel/message/file ID crosses membership, private-member and role/override checks. Missing tenant context denies; it never becomes global access.
6. **Realtime rooms.** Socket identity/workspace/channel/voice registry state is a separate ephemeral capability, rechecked against current DB authorization and revisions.
7. **Client cryptography ↔ routing server.** Server routes ciphertext/signed metadata and supplies device directory. Clients verify exact bindings, but no independent key-transparency witness detects a malicious server split view.
8. **Application ↔ PostgreSQL.** PostgreSQL is authoritative for identity, authorization, idempotency, state machines and audit order. Least privilege, private routing and verified TLS are deployment controls.
9. **Application ↔ object store.** MinIO holds untrusted ciphertext bytes. Object keys/listings/streams are bounded and checked; PostgreSQL remains authorization truth.
10. **Audit DB ↔ checkpoint.** Independent truncation evidence exists only if checkpoint write/delete authority is separated from DB authority. The current process-local admission supports one app process.
11. **Backup/restore.** Source read identities, encrypted artifact, offline age identity and empty unprivileged target are separate authorities. Recipient encryption does not authenticate who created an artifact.
12. **Build/deploy.** The lockfile and pinned CI actions cross into OCI, Web, and desktop artifacts that can access endpoint plaintext. CI scanning and Electron fuse checks reduce but do not eliminate supply-chain compromise; signed releases/provenance are absent.

## Attack surfaces and controls

| Surface | Representative abuse | Primary controls |
| --- | --- | --- |
| Registration/login | account enumeration, bcrypt CPU flood/corrupt cost, pending-epoch enrollment denial, stolen tracked credential | uniform invite failure, cheap preflight, source/account limits, two-Worker/16-pending password bulkhead, stored-cost validation/30s watchdog, per-workspace bounded device reconciliation, hashed sessions, secret scan |
| REST bodies/IDs | parser exhaustion, injection, cross-tenant object reference | pre-parser byte/concurrency budgets, Zod/exact forms, parameterized DB access, current resource authorization, no raw shell execution |
| Cookie/browser boundary | CSRF/cross-origin credential use, XSS/exfiltration | SameSite/HttpOnly/Secure cookie, exact Origin checks, CSP/Helmet, no runtime third-party scripts, safe URL/Markdown rendering |
| Desktop host/IPC | remote-code loading, privileged navigation, key/file theft, arbitrary native calls | packaged UI interception, sandbox/context isolation, no Node/webview/shell, top-frame sender validation, narrow typed IPC, OS vault, bounded opaque file handles, external system browser, hardened fuses |
| Roles/membership/invites | privilege escalation, stale decision, resource flooding | hierarchy/mask validation, locked mutation-time recheck, revision events, hashed single-use invite, durable transactional quotas |
| Collection/viewer calculations | query amplification and DB pool starvation | bounded tenant invariants, fixed-query bulk snapshot, in-memory evaluation, statement/pool limits |
| DM creation | ordinary member consumes all normal channel capacity | separate normal/DM quotas, 50 per creator and 200 total DMs, creator provenance; lifecycle still residual |
| Message/key protocol | forged author, replay/relocation, conflicting envelope, stale key, incomplete fan-out, all-holder loss | canonical signed v3 envelope, AEAD AAD, active-device binding, process-local verification provenance/conflict quarantine, frozen recipients/commitment/all-recipient ack, abort/no version reuse, explicit future-only recovery state |
| Attachments/object store | active-content execution, path/key confusion, unbounded listing/stream, orphan growth | client encryption, inert preview/CSP/type warning, opaque exact keys, count/byte/deadline gate, bounded cleanup and DB state machine; desktop quarantine/non-executable native saves |
| Profiles/avatars | image parser or polyglot exploitation, tracking pixels/external links, cross-tenant profile disclosure, impersonation/phishing bio, warning abuse | client re-encode to 256×256 PNG, server chunk/CRC/IHDR/inflate validation re-emitting only IHDR/IDAT/IEND, no external URLs or SVG, `sandbox` CSP/nosniff/same-origin CORP, 404 unless requester shares a workspace, plain-text bio with control/format characters rejected; managers (MANAGE_MEMBERS/owner, strictly lower targets) can gate a profile behind a per-workspace warning; one lifetime appeal per account; edits audited without content |
| WebSocket/voice | handshake/room exhaustion, stale room grant, forged SDP/ICE, peer targeting | pre-auth budgets, live DB session/device, locked joins/revocation, participant cap, signed exact envelope and monotonic sequence verification |
| Audit | omitted audit, mutation routed around admission, tail truncation, checkpoint rollback/write failure | atomic rows for important changes, common audited/guarded authoritative-write gate, HMAC chain/advisory lock, signed external checkpoint, startup/readiness/later-authoritative-write fail-closed |
| Metrics/logs | secret leakage, public operational reconnaissance | safe structured fields only, body/secret omission, metrics disabled by default and bearer-protected/private |
| Migration/restore/admin | long lock, intact journal with altered catalog, production overwrite, archive traversal/bomb | fresh migration CI, exact journal + bounded PostgreSQL 16 catalog fingerprint, legacy preflight, quiesced encrypted backup, empty narrowly named unprivileged restore, path/type/logical-size/checksum gates |
| CI/dependency | malicious package/action, leaked CI secret | frozen integrity lockfile, exact action SHAs, minimal checkout credentials, audit/CodeQL/Trivy/secret scan/SBOM; provenance signing residual |
| Host/operator | public bind/TLS disable/root/world-write, accidental pruning | loopback defaults, production TLS validation, secret files, nonroot/read-only/cap-drop, narrow dry-run/ack retention, runbooks |

## Abuse cases considered

- A member creates unlimited workspaces/roles/invites/bookmarks/DMs to grow shared state or multiply authorization queries. Runtime quotas, common advisory locks, migration preflight, bounded lists and bulk snapshots now contain this; historical over-cap data blocks migration instead of truncating.
- Many public login/registration requests force password work. A fixed two-Worker pool keeps bcrypt off the event loop, the shared gate sheds work before unbounded queueing, malformed/excess-cost stored hashes fail before bcrypt, a 30-second watchdog terminates stuck work, public invite rejection happens before hashing, and current-password KDF is completed before transactional locks.
- A workspace manager creates 65 or more legitimate pending public-channel epochs containing an ordinary member, then that member needs a replacement device. Cleanup is partitioned by the member's bounded workspace set and each workspace's durable channel ceiling, so no account-global 64-row cap can permanently deny enrollment.
- An operator drops a foreign key or index but leaves the migration journal intact. Startup/readiness hash a bounded PostgreSQL 16 catalog snapshot and fail closed; this does not detect corrupt row data, privilege drift, or a malicious DBA who restores catalog state between probes.
- A malicious/compromised MinIO returns an endless or foreign-prefix listing. Exact key grammar, aggregate key bytes/count and absolute deadline abort before unbounded materialization.
- The audit checkpoint filesystem fails after the DB transaction commits. The committed result remains truthful; readiness and subsequent audited or guarded authoritative mutations fail closed. Restart can advance from an intact descendant chain, but no crash-proof external WORM receipt exists. Presence and `lastActiveAt` may still be omitted/updated briefly because they are advisory and cannot grant access.
- A repository reader uses a previously tracked development password. The file is now untracked/ignored and CI scans current tracked files, but every external retained account must still be rotated/deleted and Git history treated as exposed.
- A role/private-channel change races a room join or viewer-notification calculation. Workspace locks and revision rechecks prevent stale grants; bulk snapshots are loaded under the same lock.
- A compromised server can serve malicious JavaScript to the Web client or a false device directory to every client. Desktop UI routes are replaced with packaged assets, but directory transparency and signed release distribution are still absent; these remain formal blockers.
- An operator uses backup/restore tooling against production by mistake. Exact acknowledgement, target naming, emptiness, nonprivileged owner and non-destructive restore behavior contain the common path, but DB/object administrators remain high privilege.

## Audit events and privacy

Important account/session/device, workspace/member/role/invite, channel/key, message create/edit/delete/replay, reaction/pin, preference/bookmark, file, permission, and audit-read mutations include actor, UTC time, target, outcome, server-generated request ID and trace ID in the HMAC chain. Read cursors and provisional upload-chunk registration/cleanup do not create one audit event per update, but they use the same fail-closed authoritative-write gate. Audit message metadata excludes ciphertext, nonce, signature, idempotency key and emoji; file evidence excludes bytes and plaintext names. Request/trace/actor/tenant context appears in structured operational logs. Neither channel/message plaintext, attachment bytes/name plaintext, password, raw invite/session/JWT, secret, private key nor full request body may be logged. Source IP is sensitive deployment metadata and is not retained by the application default; an explicit ingress retention policy may record it and correlate on request ID.

## Residual risks / release blockers

- Phase 1 per-channel key epochs are not MLS and lack forward secrecy/post-compromise security/key transparency/existing-device approval.
- Losing every accepted holder and the user recovery code permanently loses history. Only keys already uploaded to the encrypted archive can be recovered. No organization escrow or threshold recovery exists.
- Web passkeys and exact-action step-up are implemented. Native WebAuthn, OIDC, organization authenticator policies and threshold recovery remain open.
- Same-origin Web, extension, modified desktop package, OS-account, or endpoint compromise defeats confidentiality for data available to that endpoint. OS-wrapped desktop keys primarily protect at-rest material.
- One process/region remains an availability and coordination boundary; process-local gates/rooms/locks/audit admission prevent safe replicas.
- Audit lacks an external append-only/WORM witness, multi-process CAS, retention pipeline and SIEM alerting.
- No DM archive/reclaim, organization-wide retention/export, account/workspace deletion lifecycle, or legal hold.
- Backup lacks PITR, automatic off-host/off-region copy, object versions/policy, scheduled restore and measured full-service RPO/RTO.
- No malware scanner/sandbox; encrypted active files cannot be inspected server-side. Desktop adds quarantine/non-executable saves, while Web download defenses remain browser-dependent.
- No signed release/update or generated provenance attestation; an SBOM workflow alone does not establish artifact authenticity.
- External credential rotation for the removed tracked development account cannot be proven from this repository.
- Metadata (membership, timing, IDs, sizes, MIME/chunk count, routing and network candidates) remains visible to relevant server/storage/peer operators.
- Project is `UNLICENSED`; this is a distribution/governance blocker, not a cryptographic control.

## Review triggers

Re-review this model before changing the desktop IPC/native surface, adding replicas, broker/cache, mobile clients, passkeys/OIDC, server-side search, bots/webhooks, SFU/media recording, federated/multi-region operation, new secret provider, recovery of private keys, retention/export/delete, a new object/DB topology, or a new CI/release channel. Every resolved residual risk needs a regression test and updated risk/ADR/operations material.
