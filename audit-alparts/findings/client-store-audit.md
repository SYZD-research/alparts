# Client Stores Audit — packages/client/src/stores + hooks/services

Subagent report (fe16edbc) verified and consolidated by coordinator. Each finding below was
cross-checked against source where marked [verified].

## Medium candidates

### F-STORE-001 — `auth.store.ts` `login()` lacks generation guard [verified]
- File: `packages/client/src/stores/auth.store.ts:33-50`
- `loadUser` (73-89) and `unlockAuthenticatedClient` (111-124) capture and re-check
  `authenticationGeneration` with rollback; `login` never checks it.
- Scenario: `login` is awaiting `api.login`/`ensureDeviceSession`/`connectSocket` while a
  concurrent `logout()` or `invalidateExpiredSession()` (fired via `queueMicrotask` on any
  in-flight 401, `services/api.ts` unauthorized handler, line 129-142 + `setUnauthorizedHandler`)
  runs: socket disconnected, device cleared, all stores reset, `user: null`. `login` then
  resumes and executes `initializeAuthenticatedClient` + `set({ user })` — resurrecting an
  authenticated UI **after** `clearActiveDevice()` ran. `getActiveDevice()` throws for every
  subsequent crypto operation → broken half-session until reload; explicit user logout can be
  overridden by a late login completion.
- Remediation: capture generation at entry; after `initializeAuthenticatedClient`, if
  `generation !== authenticationGeneration` run the same disconnect/clear/reset rollback used
  in `loadUser` (84-87) before setting state.

### F-STORE-002 — transient `loadChannels` error wipes all channel scopes incl. drafts + unsent outbox [verified]
- Files: `stores/channel.store.ts:65-69`, `hooks/useSocketEvents.ts:130-141`,
  `stores/security-scope-cleanup.ts` (deletes drafts and persisted outbox commands).
- Scenario: `workspace:permissions-updated`/reconnect triggers `refreshWorkspaceAuthorization`;
  `api.getChannels` fails transiently (timeout/5xx — not a revocation). Handler treats
  `after.error` identically to revocation and erases channel keys, drafts, and **unsent queued
  outbox plaintext** for every previously visible channel.
- Impact: permanent loss of user-authored unsent messages/drafts on a network blip.
  Fail-closed erasure is deliberate for revocation, but `error` conflates "revoked" with
  "unreachable". `loadWorkspaces` (`workspace.store.ts:47-49`) deliberately preserves the last
  validated list on transient failure — the channel path has no equivalent distinction.
- Remediation: only clear scopes when the call succeeded and the channel is absent, or on
  explicit revoke events; on error, keep scopes and surface a retry state.
- Status: candidate — verify product intent (fail-closed vs data preservation).

### F-STORE-003 — `outbox.store.ts` `enqueue` bypasses ordering of queued/in-flight items [verified]
- `enqueue` flushes the new item directly (`void get().flushItem(command.idempotencyKey)`);
  `sending` is keyed per idempotency key, so a new item runs concurrently with a mid-flight
  retry or queued predecessors.
- Impact: whichever HTTP request lands first gets the earlier server `createdAt` → permanent
  display reordering under flaky networks. Delivery still guaranteed via idempotency.
- Remediation: route through `flushAll`/per-channel queue instead of per-item flush.

### F-STORE-004 — `draft.store.ts` `clearChannel` does not invalidate queued/in-flight writes [verified]
- `queuePersistence` gates on `pending.generation === draftGeneration`, but `clearChannel`
  (173-188) only bumps per-channel `draftVersions`, not `draftGeneration`. Contrast
  `outbox.store.ts` which bumps its generation on `clearChannel`.
- Additionally `queuePersistence` unconditionally replaces `pendingPersistence[channelId]` —
  a save queued after a pending delete overwrites it (last-writer-wins), so a late `setDraft`
  timer can resurrect a draft post-revocation.
- Impact: plaintext draft for a revoked channel persists (encrypted at rest under device key).
  Best-effort cleanup is acknowledged in `security-scope-cleanup.ts`, but the asymmetry vs
  outbox suggests oversight.
- Remediation: bump `draftGeneration` or store a per-channel tombstone checked by
  `queuePersistence`.

## Low / trivial

### F-STORE-005 — `loadMoreMessages`/`loadMessages` cursor race [verified]
- `message.store.ts:322-358` vs `261-320`: `loadMoreMessages` does not capture `loadVersions`;
  a late page-N response overwrites fresh page-1 `hasMore`/`cursors` installed by a concurrent
  `loadMessages` (generation/epoch unchanged → `isMessageContextCurrent` passes).
- Impact: next `loadMoreMessages` resumes from the stale cursor → silent scrollback gap.
- Remediation: capture `loadVersions.get(channelId)` at entry and check before applying.

### F-STORE-006 — `workspace.store.ts` `removeWorkspace` can leave `isLoading` stuck true [verified]
- `removeWorkspace` bumps `workspaceListGeneration`; in-flight `loadWorkspaces` then early-returns
  at line 42 without `set({ isLoading: false })`. Needs a bare `removeWorkspace` as the last
  list op — the socket revoke path re-calls `loadWorkspaces`, so window is narrow.

### F-STORE-007 — `dm.store.ts` reuse-check bypassed by superseded load [verified]
- `createOrReuseDm` (89-99): `loadDms` returns `[]` when superseded; `findReusableOneToOneDm([])`
  → `null` → `api.createDm` proceeds without checking the real list → possible duplicate 1:1 DM
  if server does not enforce uniqueness (server-side dedupe not verified).

### F-STORE-008 — voice dropped-offer glare / no repair for simultaneous joins
- `voice.store.ts:214-223` (joiner offers), `536-539` (`signalingState !== 'stable'` → drop,
  no rollback/retry). Mutual near-simultaneous joins can both end `have-local-offer` → both
  offers dropped → pair never connects; no renegotiation. Any dropped offer leaves a permanent
  "connecting" ghost.
- Remediation: polite/impolite tie-break (compare participantId/joinedAt), or one-shot retry
  when a peer stays `connecting` beyond N seconds. Server-side snapshot behavior not verified.

### F-STORE-009 — voice sequence tracker reset on rejoin enables replay of old signed signals
- `voice.store.ts:532` accept, `916` `removePeer` deletes the per-participant high-water mark.
  If the server ever reissues the same `participantId`, a captured still-validly-signed old
  offer/answer is accepted again. Bounded: replayed SDP still requires DTLS against the
  sender's certificate — worst case a failed/spoofed connection attempt (DoS), not key
  compromise. Likely non-replayable today (participantId reuse not verified server-side).

### F-STORE-010 — device-directory race can drop a new joiner's first signals
- `voice.store.ts:433` nulls `directoryPromise` on `participant-joined`, but an in-flight
  fetch captured earlier may still resolve with the pre-join directory → `directory.get(C.deviceId)`
  → `undefined` → offer dropped with no retry (compounds F-STORE-008).

### F-STORE-011 — `rejoinActiveChannel` gives up silently after 3 attempts
- `useSocketEvents.ts:299-312`: on permanent `channel:join` failure no error surfaced and no
  fallback `loadMessages` → open channel stops receiving `message:new` until next connect.

### F-STORE-012 — `ChatArea.tsx` `channel:join` emit has no ack timeout
- Unlike `rejoinActiveChannel` (`socket.timeout(3000)`), this emit has no timeout; lost ack →
  `loadMessages` never runs → stale view, no error.

### F-STORE-013 — `presence.store.ts` typing entries never expire [verified]
- `typingUsers` entries persist until explicit `isTyping:false`/`clearChannel`. Lost
  `typing:stop` (tab crash/offline) leaves permanent "typing…" indicator.
- Remediation: expire entries after ~5-10s without refresh.

### F-STORE-014 — `noteBaseMessage` counts own messages as unread
- `user-state.store.ts:180-207`: `unreadCount + 1` lacks `authorId === self` exclusion →
  messages sent from another device inflate the badge until next `loadWorkspaceState`.
  (Verify server excludes own messages first.)

### F-STORE-015 — `loadMessages` clobbers aggregate `isLoading` while other channels load [verified]
- `message.store.ts:293,300` sets `isLoading: false` unconditionally; the eviction path
  correctly computes `Object.values(loadingByChannel).some(Boolean)`. Minor UI flag bug.

### F-STORE-016 — `cancelUpload` retains the runtime against the 16-slot capacity cap [verified]
- `attachment.store.ts:513-520` keeps the `runtimes` entry; `startUploads:445` rejects when
  `runtimes.size + files.length > 16`. 16 cancelled-but-not-dismissed uploads → all new uploads
  rejected until each is dismissed. `failed` tasks also retain runtimes + `File` refs.

### F-STORE-017 — LRU eviction can evict the actively-viewed channel [verified]
- `message.store.ts:133`: victim selection excludes only the channel being updated, not
  `activeChannelId`. A flood elsewhere can evict the open channel → `isAuthorizedLoadedChannel`
  then drops live socket events → empty/frozen view until reload.

### F-STORE-018 — `bookmarkRequests` map is append-only within a session [verified]
- One entry per toggled message, removed only on clear/reset. Tiny — completeness note.

### F-STORE-019 — `decryptMessages` all-or-nothing batch churns under large backlogs
- `message.store.ts:705-834` + worker 30s scope timeout: ~1000 unverified events processed in
  a single pass that only `set`s at the end; abort discards all work; each subsequent socket
  event retriggers a full re-verify of the still-unverified snapshot. Self-limiting via the
  worker's single pending flag; consider progress checkpoints or per-batch `set`.

## Verified non-issues (deliberate/correct designs)

- Voice signaling: signature verified before any SDP/ICE applied; covers every envelope field;
  target/sender binding to participant record + device-directory identity key; strict parsing;
  ≤8 participants; identity-change on rejoin rejected; SDP/ICE size caps; per-peer ordered
  outbound queues; full runtime teardown.
- Outbox: `pendingEnqueueReservations` closes in-memory TOCTOU on the 100-item cap;
  `putBoundedOutboxRecord` re-checks capacity inside the IndexedDB transaction; retry reuses
  the exact signed envelope (no re-encryption under same idempotency key); principal-scoped
  contexts + generation checks prevent cross-account sends.
- message.store: context re-checked after every await; `mergeDuplicateEvent` never lets
  unverified wire data overwrite verified plaintext/author; forgeable `cryptoVerified` JSON
  property stripped at every merge boundary; unsigned delete events fail closed; quarantine for
  invalid signed edit/delete; bounded resident windows with dependent-map invalidation.
- crypto.service / channel-key-scope: synchronous scope invalidation before async key
  deletion; post-write scope re-check removes late writes; `restoreChannelKeyScope` drains
  pending deletions; deny-by-default at map capacity.
- useSocketEvents: revocation cleanup runs synchronously outside the serialized queue;
  bounded authorization queue (64); complete listener teardown.
- draft.store: drain preserves save-before-delete order per channel; `reset()` skips queued
  writes via generation (but see F-STORE-004 for the clearChannel asymmetry).
- socket.ts: single-shot re-handshake on server disconnect; stale-socket guard via identity.
