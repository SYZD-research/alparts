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
- encrypted message events, attachment chunks, signatures, commitments, key-version state and the ordered group commit log;
- PostgreSQL integrity/availability, object-store ciphertext objects and storage credentials;
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
9. **Application ↔ object store.** The S3-compatible object store holds untrusted ciphertext bytes. Object keys/listings/streams are bounded and checked; PostgreSQL remains authorization truth.
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
| Message/key protocol | forged author, replay/relocation, conflicting envelope, stale key, forked or poisoned group commit, writes to a group that still holds a revoked device, loss of every usable member | canonical signed v5 envelope that names an edited, deleted or quoted message by its author and signed idempotency key (v3/v4 still accepted from older clients), AEAD AAD, active-device binding, process-local verification provenance/conflict quarantine; one server-ordered commit per version (compare-and-swap on the previous transcript, under the authorization locks); committer-signed envelopes binding roster, directory heads and key commitment; client chain pin with equivocation stop and downgrade refusal; writes refused until devices without access are removed; rejoin; step-up fresh start only under stated conditions; no version reuse |
| Forum posts | moving a reply to another post, turning a reply into a post, quoting across posts, replying to locked/deleted posts, probing hidden posts/tags | v4/v5 envelope and AAD bind `postId`, and v5 also the post's first message by its author and signed idempotency key; the layout follows the (signed, immutable) channel type, never the payload; server locks the post row and checks post/channel/quote membership; replies are shown only under the post their signature names; composite keys keep tags and posts in one channel; hidden posts/tags answer 404; tag names are plaintext like channel names |
| Attachments/object store | active-content execution, path/key confusion, unbounded listing/stream, orphan growth | client encryption, inert preview/CSP/type warning, opaque exact keys, count/byte/deadline gate, bounded cleanup and DB state machine; desktop quarantine/non-executable native saves |
| Profiles/avatars | image parser or polyglot exploitation, tracking pixels/external links, cross-tenant profile disclosure, impersonation/phishing bio, warning abuse | client re-encode to 256×256 PNG, server chunk/CRC/IHDR/bounded-inflate validation and re-encoding of the decoded pixels into a fresh IHDR/IDAT/IEND PNG, no external URLs or SVG, `sandbox` CSP/nosniff/same-origin CORP, 404 unless requester shares a workspace, plain-text bio with control/format characters rejected; managers (MANAGE_MEMBERS/owner, strictly lower targets) can gate a profile behind a per-workspace warning that also hides former members' pictures; one lifetime appeal per account, only after a real change; the avatar row is re-read under lock before an uncertain upload deletes its object (a referenced missing object would stop backups); edits audited without content; formal model M6 |
| WebSocket/voice | handshake/room exhaustion, stale room grant, forged SDP/ICE, peer targeting; with the SFU: reading, relabeling or replaying frames, key messages for the wrong call or recipient | pre-auth budgets, live DB session/device, locked joins/revocation, participant cap, signed exact envelope and monotonic sequence verification; SFU sessions only for the socket's own call participant, every frame SFrame-encrypted by its sender under per-call keys wrapped and signed per device, accepted only on its key owner's stream with a fresh counter, keys replaced on every join and leave (ADR 0014, formal model M8 VE2/M8k) |
| Audit | omitted audit, mutation routed around admission, tail truncation, checkpoint rollback/write failure | atomic rows for important changes, common audited/guarded authoritative-write gate, HMAC chain/advisory lock, signed external checkpoint, startup/readiness/later-authoritative-write fail-closed |
| Metrics/logs | secret leakage, public operational reconnaissance | safe structured fields only, body/secret omission, metrics disabled by default and bearer-protected/private |
| Migration/restore/admin | long lock, intact journal with altered catalog, production overwrite, archive traversal/bomb | fresh migration CI, exact journal + bounded PostgreSQL 16 catalog fingerprint, legacy preflight, quiesced encrypted backup, empty narrowly named unprivileged restore, path/type/logical-size/checksum gates |
| CI/dependency | malicious package/action, leaked CI secret | frozen integrity lockfile, exact action SHAs, minimal checkout credentials, audit/CodeQL/Trivy/secret scan/SBOM; provenance signing residual |
| Host/operator | public bind/TLS disable/root/world-write, accidental pruning | loopback defaults, production TLS validation, secret files, nonroot/read-only/cap-drop, narrow dry-run/ack retention, runbooks |

## Abuse cases considered

- A member creates unlimited workspaces/roles/invites/bookmarks/DMs to grow shared state or multiply authorization queries. Runtime quotas, common advisory locks, migration preflight, bounded lists and bulk snapshots now contain this; historical over-cap data blocks migration instead of truncating.
- Many public login/registration requests force password work. A fixed two-Worker pool keeps bcrypt off the event loop, the shared gate sheds work before unbounded queueing, malformed/excess-cost stored hashes fail before bcrypt, a 30-second watchdog terminates stuck work, public invite rejection happens before hashing, and current-password KDF is completed before transactional locks.
- A workspace manager creates 65 or more legitimate pending public-channel epochs containing an ordinary member, then that member needs a replacement device. Cleanup is partitioned by the member's bounded workspace set and each workspace's durable channel ceiling, so no account-global 64-row cap can permanently deny enrollment. Since group protocol 4 no pending epochs are created at all (migration 0023 aborted the remaining ones); the bounded cleanup remains.
- A malicious member commits an update whose path secret for one member is wrong, or adds a device with a Welcome it cannot open. The server cannot see this. The affected device keeps its keys and asks to be added again, and the next commit by another member removes and re-adds it. Rejoin requests are limited to three per device and channel a day; a device whose request has waited 30 minutes, or a manager after 15 minutes, may start the conversation again. Audit names the committer device of every version, so managers can remove the member.
- A compromised server shows different devices different commit histories, or rolls a channel back. A device stops for that conversation as soon as it receives a commit that does not chain to its last verified version, a version below it, or no group after it verified one; it keeps its state. Withholding commits is a denial of service that clients cannot prevent.
- An operator drops a foreign key or index but leaves the migration journal intact. Startup/readiness hash a bounded PostgreSQL 16 catalog snapshot and fail closed; this does not detect corrupt row data, privilege drift, or a malicious DBA who restores catalog state between probes.
- A malicious/compromised object store returns an endless or foreign-prefix listing. Exact key grammar, aggregate key bytes/count, a 4 MiB cap on each listing response read before parsing, a page cap with repeated-token detection and an absolute deadline abort before unbounded materialization.
- A malicious/compromised object store answers a download with more bytes than were stored, to append a forged HTTP response on a keep-alive connection. The GET length must equal the stored size, a stream stops before any extra byte, and the response refuses to finish with a mismatched Content-Length.
- The audit checkpoint filesystem fails after the DB transaction commits. The committed result remains truthful; readiness and subsequent audited or guarded authoritative mutations fail closed until the missed checkpoint is written, which a transient failure retries automatically with the full chain checks. Restart can advance from an intact descendant chain, but no crash-proof external WORM receipt exists. Presence and `lastActiveAt` may still be omitted/updated briefly because they are advisory and cannot grant access.
- A repository reader uses a previously tracked development password. The file is now untracked/ignored and CI scans current tracked files, but every external retained account must still be rotated/deleted and Git history treated as exposed.
- A role/private-channel change races a room join or viewer-notification calculation. Workspace locks and revision rechecks prevent stale grants; bulk snapshots are loaded under the same lock.
- A compromised server replays an author's earlier signed message, edit or delete under a new event id and time, for example to roll an edited message back. The database keeps one event per channel and idempotency key, so clients quarantine a second verified event with the same channel, author and signed idempotency key, and stop loading that channel's history. Replays whose original is outside the loaded history, and reordering or omission of events, are not detected: envelopes carry no per-sender sequence number.
- A compromised server moves a file to another message of the same author by serving that message's envelope under the original message id. New file signatures include the message's signed idempotency key, and clients open a file only for a verified message with that key. Files signed by older clients are still accepted for the server-assigned message id.
- A compromised server serves two messages of the same author under each other's server ids. A message does not sign its own id, so a reference by id alone can be moved. The v5 envelope that current clients sign also names the edited, deleted or quoted message, and in a forum the post's first message, by its author and the idempotency key that author signed; the server serves that pair with each event and cannot give it to another event. Clients apply an edit or a deletion, show a quote and list a reply only with the message it was signed for; a quote whose original does not match says that the original cannot be shown (formal model M9). Events signed by older clients (v3/v4) are still accepted and name their target by server id only, so the server can still move those; a reference to a message sent before idempotency keys were signed is made in the older layout (RISK_REGISTER R-051). Messages without references keep the older layout; clients that have not been updated cannot verify v5 events, so they do not apply edits or deletions made with updated clients and cannot show their quotes and forum replies. Serving an event the client already holds again under its id with another time changes nothing it shows; the client keeps the first time.
- A compromised server carries an SFU call. It ends DTLS-SRTP, but every audio frame is encrypted in the sender's browser (SFrame) under a key only the call's participants received, wrapped for each recipient device and signed by the sender device; it sees only headers, ciphertext, who is in the call and when each participant speaks. It cannot pass off one participant's stream as another's, and replayed frames are dropped. It can still give a key to a device it adds to the call (shown as a participant) or to a false directory entry, and help a participant pass off audio as another participant's, since every receiver holds the sender's symmetric frame key (ADR 0014).
- A compromised server can serve malicious JavaScript to the Web client or a false device directory to every client. Desktop UI routes are replaced with packaged assets, but directory transparency and signed release distribution are still absent; these remain formal blockers.
- An operator uses backup/restore tooling against production by mistake. Exact acknowledgement, target naming, emptiness, nonprivileged owner and non-destructive restore behavior contain the common path, but DB/object administrators remain high privilege.

## Audit events and privacy

Important account/session/device, workspace/member/role/invite, channel/key, message create/edit/delete/replay, reaction/pin, preference/bookmark, file, permission, and audit-read mutations include actor, UTC time, target, outcome, server-generated request ID and trace ID in the HMAC chain. Read cursors and provisional upload-chunk registration/cleanup do not create one audit event per update, but they use the same fail-closed authoritative-write gate. Audit message metadata excludes ciphertext, nonce, signature, idempotency key and emoji; file evidence excludes bytes and plaintext names. The workspace audit view shows activity inside a channel (messages, DMs, channel membership, keys, group packages, files, forum posts) only to viewers who can currently see that channel and to the member who acted, and never shows members' own channel settings or bookmarks; workspace management events stay visible to every audit viewer. Ids in request paths and socket events are accepted only in their stored lowercase form, so a request cannot record an id the view's scope does not match. Request/trace/actor/tenant context appears in structured operational logs. Neither channel/message plaintext, attachment bytes/name plaintext, password, raw invite/session/JWT, secret, private key nor full request body may be logged. Source IP is sensitive deployment metadata and is not retained by the application default; an explicit ingress retention policy may record it and correlate on request ID.

## Residual risks / release blockers

- Channel keys come from one continuing MLS group per channel (group protocol 4). Retained archive keys rule out per-message forward secrecy. Post-compromise security reaches only devices that commit with an UpdatePath (writers at least weekly) or are removed; a member that never makes such a commit is healed only by removal. An eligible malicious member can deny service inside a group. The device directory has no independent witness.
- Losing every member device that held a version and the user recovery code permanently loses that history. Only keys already uploaded to the encrypted archive can be recovered. No organization escrow or threshold recovery exists.
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
- Project code is licensed AGPL-3.0-only. This is a governance matter, not a cryptographic control.

## Review triggers

Re-review this model before changing the desktop IPC/native surface, adding replicas, broker/cache, mobile clients, passkeys/OIDC, server-side search, bots/webhooks, SFU/media recording, federated/multi-region operation, new secret provider, recovery of private keys, retention/export/delete, a new object/DB topology, or a new CI/release channel. Every resolved residual risk needs a regression test and updated risk/ADR/operations material.
