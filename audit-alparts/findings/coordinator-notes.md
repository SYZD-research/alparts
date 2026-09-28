# Coordinator-verified findings (own review)

## F-COORD-001: Dependency vulnerabilities (pnpm audit --prod)
- Severity: moderate (×4)
- Status: confirmed (automated scan)
- Evidence: /home/nia/bc/audit-alparts/audit.log
- Findings:
  - qs >=2.2.5 <6.16.0 via express + body-parser — GHSA-4mjr-xmp4-gh2g
  - qs (second advisory path)
  - stream-json <=3.4.0 via minio — O(depth²) CPU DoS on crafted JSON, GHSA-528h-pc64-c93x
  - decode-uri-component (moderate)
- Impact: qs = query-string parser DoS/prototype issues via Express; stream-json DoS path only if MinIO client parses attacker-controlled JSON (low — server talks to operator MinIO)
- Remediation: upgrade express/minio or pin patched transitive versions via pnpm overrides; CI already fails on `pnpm audit --prod --audit-level high` — moderate stays visible but doesn't gate. Decide explicit policy for moderate.

## F-COORD-002: No account-disablement capability
- Severity: medium (product/security gap)
- Status: candidate (verified no code path disables an account)
- Location: packages/server/src/db/schema.ts (users.status is presence-only: offline/online), services/auth.service.ts (login has no disabled check), services/workspace.service.ts removeMember only revokes workspace access
- Description: `users.status` is presence status, not account state. There is no way for an operator to freeze/disable a compromised account — the only controls are per-session revocation (DELETE /auth/sessions) and workspace member removal. A compromised account's sessions on OTHER devices remain usable until individually revoked or expired (JWT up to 7 days). Under a hostile-monitoring threat model, inability to centrally disable an account is a real gap.
- Impact: incident response cannot instantly kill all access for a compromised user; attacker sessions persist until manual per-session revocation or token expiry.
- Remediation: add `users.disabledAt` checked in verifySessionToken/login (fail-closed, revocation propagates on next request); emit disconnect to `session:` rooms on disable.

## F-COORD-003: /health/ready performs unauthenticated multi-subsystem checks
- Severity: low
- Status: confirmed (code-traced)
- Location: packages/server/src/app.ts:133-144
- Description: GET /health/ready runs checkDb + checkDatabaseSchema + checkObjectStorage + checkAuditCheckpoint on every request, unauthenticated, behind only the global 300 req/min rate limit. A small botnet can amplify DB/MinIO/checkpoint-file IO. Common practice for k8s probes, but the checks are comparatively expensive (schema fingerprint + object store probe + checkpoint verify).
- Remediation: cache readiness verdict for 1-5 s, or add a tighter dedicated rate limit / localhost-only option while keeping /health/live minimal (it already is).

## F-COORD-004: In-memory single-process rate limits & socket state (documented architecture constraint)
- Severity: info
- Status: confirmed-by-design (matches RISK_REGISTER R-004/R-005 single-process stance)
- Location: middleware/rate-limit.ts, websocket/security.ts (SingleNodeSocketSecurityState)
- Description: Rate limits, socket leases, handshake caps are process-local. If the process is ever run multi-replica behind a proxy, limits multiply per replica and room state diverges. Documented as unsupported, but there is no startup assertion preventing >1 process sharing a DB.
- Remediation: optional — detect and refuse second live process via advisory session lock at startup.

## Cross-cutting verified-strong areas (no findings)
- Cookie sessions: HttpOnly+SameSite=Strict+__Host- prefix in prod; token hash stored server-side; JWT pinned HS256+iss+aud.
- CSRF: enforceBrowserOrigin + Sec-Fetch-Site cross-site rejection for cookie-auth mutations; WS handshake origin check.
- Audit chain: HMAC-chained rows + signed external checkpoint + advisory-lock serialization + fail-closed latch.
- Config: *_FILE secrets, prod requires explicit CORS+checkpoint+secrets; MinIO TLS enforced unless loopback acknowledged.
- Invite tokens: 256-bit + HMAC + email-binding + single-use under row lock.
- Device enrollment: challenge+proof+step-up password for NEW identities; revoked identity can never re-register; pending-epoch abort on new device.
- File service: uniform 404s, manifest-bound chunk authz, upload op lock, quota double-check at reserve+commit, download lease.
- Voice signaling: senderParticipantId/senderDeviceId bound to socket, canRoute+room checks, join re-authorizes under workspace lock.
- Routes table: every route carries authMiddleware + appropriate permission middleware; UUID validation before lookups; 404-not-403 for invisible resources.
- Android: FLAG_SECURE, device-credential gate, Keystore-backed vault w/ AAD-bound values, local-asset WebView (all navigation blocked), strict CSP per asset, mic permission gated by app state.
- Desktop: sandbox+contextIsolation+no nodeIntegration, setContentProtection, navigation/redirect guards, permission handlers scoped to audio, custom protocol proxying only /api+socket.io to configured origin, path traversal safe resolveBundledPath.
- Backup scripts: quiesced snapshot verification, paranoid tar validation (sparse/link/size), credentials via file/stdin never argv/env, atomic publish via hardlink, production-like-name refusal on restore targets.
- Protocol serializers: distinct domain labels, versioned envelopes, full-field binding incl. ICE candidates; legacy-v2 verify path cannot downgrade (signature covers whichever serialization applies).
- Raw SQL: all through drizzle sql`` parameter binding; only static sql.raw constants.

## Deep-pass 3 — exotic/novel vector hunt (this session)
Verified clean (no findings):
- Timing/enumeration: login uses DUMMY_PASSWORD_HASH pre-check; bcrypt always runs. Registration invitation preflight normalizes before errors. No account-existence oracle identified.
- Deleted-message races: reactions/pins/read-positions/refMessageId all route through lockActiveBaseMessage which rejects any message with a delete event; delete itself is row-locked + idempotent. Edit requires author + active base message.
- Pagination: cursor bound to channelId; (createdAt,id) tuple ordering; reaction invariant re-checked on read.
- bcrypt truncation: password schema min(12).max(72) + explicit UTF-8 byteLength<=72 refine — multibyte-safe.
- SSRF: zero server-side fetches of user-controlled URLs. MinIO client targets configured endpoint only, with bounded transport timeouts + gate.
- Content-Disposition: fixed literal filename on downloads (filenames live inside E2EE manifest) — no header injection.
- Invite/session tokens: randomBytes(32)/randomUUID CSPRNG; invite tokens HMAC-bound to email, single-use under row lock.
- CI: no pull_request_target; only github.run_number interpolated — no script-injection surface.
- Android manifest: allowBackup=false + dataExtractionRules, cleartext forbidden, launcher-only exported activity, no deep links.
- Electron: serveAppRequest path resolution root-contained (resolveBundledPath rejects .., backslash, control chars); openExternal restricted to http/https without credentials; custom-scheme CSP per response.
- Advisory-lock key collisions (hashtext 32-bit): evaluated — attacker cannot control victim-side lock-key strings, so no controllable collision/DoS. Lock ordering is globally consistent (workspace -> entity row -> advisory -> insert); multi-workspace locking only via sorted-order loop in device registration -> no deadlock cycle.
- ECDSA signature malleability: sameCryptoEvent compares signature bytes; malleated sig -> IDEMPOTENCY_CONFLICT, cannot duplicate events.
- avatarUrl: schema field exists but has no write path and is never rendered as <img> — dead field, no tracking/IP-leak vector.
- WS handshake: origin allowlist, pending-handshake attempt+lease caps, session expiry disconnect scheduling, device-bound ops revalidate device.revoked_at FOR SHARE under workspace lock.
New finding: only F-INPUT-001 (Unicode/bidi/zero-width controls in displayName + workspace/channel/role/device names). Indexed.

## Deep-pass 4 — zero-day hunt, crypto-primitive and IPC boundary audit
Verified clean (no new findings):
- AEAD AAD binding: serializeMessageAad binds version+type+channelId+authorId+deviceId+keyVersion+idempotencyKey+refMessageId+broadcastMention — ciphertext transplant between channels/messages/epochs impossible.
- Canonicalization: single shared serializer module (packages/shared) used by client AND server — no cross-implementation canonicalization drift. v2/v3 downgrade blocked: broadcastMention presence is itself pinned by the signature bytes.
- Wrap path: verify-signature-before-decrypt (distributor identity over wrap envelope), RSA-OAEP unwrap, then commitment check SHA-256(raw)==keyCommitment with raw.fill(0) zeroization on every failure path.
- Voice signals: full envelope signature incl. ICE candidates, strictly-increasing sequence per sender/target pair, server-generated participantId.
- Client verification: per-batch device directory fetch, identity.userId===authorId AND author.id===authorId double binding, invalid signature quarantines (message->placeholder; edit/delete->dropped so forged deletes cannot hide content), decrypt failure surfaces tamper notice, sticky-conflict merge.
- Device directory endpoint: channel-authz, bounded comma-id schema (<=64 unique UUIDs), legacy unscoped path bounded + invariant-checked.
- Electron IPC: checked() enforces sender==mainWindow top frame + trustedFrame URL; vault namespace derived from main-process settings.serverUrl (renderer cannot reach other deployments); assertSecretName whitelists key shapes; file-save uses opaque UUID tokens + OS-chosen paths + .alparts-partial temp + dangerous-name detection (NFKC, control/bidi strip, Windows reserved names).
- handleWebRequest: all http/https in session intercepted; non-configured origin -> 403; backend restricted to isBackendPath + sec-fetch-dest allowlist + redirect:'manual'; UI shell always served from bundle -> desktop client structurally immune to remote code injection even with hostile server+CA.
- JWT: algorithms+iss+aud pinned, zero clock tolerance; sessions bounded (16/user); expiry schedules socket disconnect.
- Socket.IO engine: maxHttpBufferSize 64KB, perMessageDeflate off, CORS exact origins; polling shares identical auth path.
- message.service: cursor bound to channel, deleted-message guards on every mutation path, idempotency conflict full-field compare, mention recipients filtered to viewers, monotonic read positions.
- auth: dummy bcrypt on absent account; password min12/max72 + utf8 byte cap; invite tokens CSPRNG+HMAC+email-bound single-use.

## Pass 8 — Full-line coverage sweep (build/release/backup/desktop-settings/client-models) — 2025 complete

### Files newly covered this pass (all lines)
- scripts/backup.sh, restore-verify.sh, pre-migration-backup.sh, prune-backups.sh, backup-under-systemd.sh, dev.sh, check-secrets.sh
- scripts/lib/backup-common.sh (tail), scripts/release/{update-manifest,create-release,dr-drill,android-bridge.test}.mjs
- Dockerfile, docker-compose.yml, compose.production.yml, .env.example, .dockerignore, .gitignore
- deploy/{alparts.service,alparts-backup.service,alparts-backup.timer}
- packages/desktop/package.json (electron-builder config), scripts/after-pack.cjs, src/settings.ts
- packages/client/public/android-bridge.js, index.html, vite.config.ts, tailwind/postcss configs, manifest.webmanifest, src/main.tsx
- app.ts (production CSP/HSTS/origin-enforcement/static-cache)
- Client hooks/services/models remainder: useSocketEvents (392), voice-signal-model, channel-key-scope (ChannelKeyScopeGuard deny-by-default overflow), coalesced-channel-worker, fixed-request-retry (same-object retry for signed idempotent ops), mention-model (ambiguous displayName → unbound userId), permalink-model, search-loaded-messages, paste-preview-model (control-char strip), outbox-model (strict parse), security-scope-cleanup (sync invalidation first), authorization-event-model, presence/reset/etc.
- Server scripts: database-fingerprint (read-only repeatable-read, cursor, length-prefixed hash framing), migrate-runtime (advisory lock), initialize-audit-checkpoint
- Android res: strings (UI policy compliant), styles, native_screen (autofill disabled, saveEnabled=false, maxLength 2048), colors, drawables
- drizzle.config.ts (.env parsed as data, existing env wins), .oxlintrc, .secretlintrc, .devin/mcp_config.local.json

### Verdict: zero new defects. Notable confirmations:
- Production CSP: script-src 'self' ONLY (no unsafe-inline in prod), connect-src 'self' (injected JS cannot open exfil WebSocket), frame-ancestors none, object-src none, HSTS preload, Permissions-Policy denies camera/geolocation/display-capture
- systemd units: LoadCredential (secrets never in env/argv/proc), DynamicUser, full Protect* suite, RestrictAddressFamilies, CapabilityBoundingSet empty, ProtectProc=invisible, AUDIT_CHECKPOINT_REQUIRED=true in production unit
- Backup unit: CAP_DAC_READ_SEARCH bounded, ReadWritePaths only backup dir, TimeoutStartSec 6h, timer RandomizedDelaySec 30m
- update-manifest.mjs: Ed25519 domain-separated signatures, sequence rollback rejection, channel pinning, expiry, artifact digest+symlink checks, signing key mode 600 enforced
- after-pack.cjs: full Electron fuse hardening (RunAsNode off, NODE_OPTIONS off, CLI inspect off, asar integrity, OnlyLoadAppFromAsar, no file: privileges, cookie encryption)
- dev.sh: .env parsed as DATA not sourced (injection impossible), whitelist keys, never deletes volumes, 600 perms
- prune-backups: refuses / /root /home /usr /var /opt targets, ACK gate, keeps minimum copies
- docker-compose dev: all images digest-pinned, loopback-only binds, minio-init provisions least-privilege user and detaches default readwrite
- Runtime dep surface: server 11, client 9 — near-minimal supply chain
- ChannelKeyScopeGuard: capacity overflow → deny-by-default (fail-closed); CoalescedChannelWorker bounded+timeout; authorizationQueue capped 64
- useSocketEvents: synchronous scope invalidation BEFORE queued reconciliation; request-version guards; voice:watch validates returned channelIds ⊆ requested

### Coverage statement
Every non-test production file in the repository has now been read line-by-line at least once across passes 1-8: server (69 ts + migrations + scripts), shared, client (all tsx/ts/services/stores/hooks/public), desktop (6 ts + cjs + package.json), android (5 java + all res/xml + gradle + verification metadata), build/release/backup/deploy/CI configs. Test files were sampled for security-relevant expectations.
