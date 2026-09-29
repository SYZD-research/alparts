# API and realtime inventory

All `/api` responses are `Cache-Control: no-store` except versioned avatar images (below). Protected endpoints require a live DB-backed session; workspace/channel/message/file routes additionally enforce current resource authorization. Cookie-authenticated browser mutations require an exact allowed Origin. JSON is strict and bounded to 512 KiB globally, with tighter route schemas.

This is an inventory, not a stable public OpenAPI contract. No formal API version prefix exists; incompatible changes require a compatibility/versioning decision before release.

## Health and telemetry

| Method/path | Purpose | Authentication |
| --- | --- | --- |
| `GET /health`, `/health/live` | process/drain and liveness | private network; no credentials |
| `GET /health/startup` | startup/drain gate | private network; no credentials |
| `GET /health/ready` | DB + object store + audit witness readiness | private network; no credentials |
| `GET /metrics` | Prometheus process/request/pool/gate metrics | route exists only when enabled; bearer secret + private network |

## Authentication and devices

| Paths | Responsibility |
| --- | --- |
| `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me` | invite-gated account creation and session lifecycle |
| `GET /api/auth/sessions`, `DELETE /api/auth/sessions/:id`, `DELETE /api/auth/sessions` | bounded session inventory (maximum 16 unexpired/user) and scoped/all revocation |
| `POST /api/devices/challenge`, `POST /api/devices`, `POST /api/devices/:id/bind` | session-bound device enrollment/binding proof; new-device provisional-epoch reconciliation is partitioned by the bounded workspace set |
| `GET /api/devices`, `DELETE /api/devices/:id` | active/revoked device inventory and idempotent revocation; dirty-key notifications name only current workspaces with an affected active/pending recipient |

## Workspaces, invitations, roles and permissions

| Paths | Responsibility |
| --- | --- |
| `POST/GET /api/workspaces`, `GET /api/workspaces/:id` | bounded workspace creation/list/detail |
| `GET /api/workspaces/:id/members`, `DELETE /api/workspaces/:id/members/:userId` | bounded member view/removal |
| `POST /api/invitations/accept` | existing-account invitation acceptance |
| `POST/GET /api/workspaces/:wid/invitations`, `DELETE /api/workspaces/:wid/invitations/:id` | create/list/revoke hashed expiring invitations |
| `GET/POST /api/workspaces/:wid/roles` | role list/create |
| `PUT/DELETE /api/workspaces/:wid/roles/:roleId` | role update/delete with hierarchy/revision checks |
| `POST/DELETE /api/workspaces/:wid/members/:userId/roles/:roleId` | role assignment/removal |
| `GET /api/workspaces/:wid/members/:userId/permissions` | effective workspace permissions and reason |
| `POST /api/workspaces/:wid/roles/preview` | bounded viewer/permission impact preview |

## Categories, channels and overrides

| Paths | Responsibility |
| --- | --- |
| `GET/POST /api/workspaces/:wid/categories` and `PUT/DELETE .../categories/:categoryId` | bounded category management |
| `GET/POST /api/workspaces/:wid/channels`, `GET/PUT/DELETE /api/channels/:id` | authorized channel list/create/detail/update/delete |
| `GET/POST /api/channels/:id/members`, `DELETE .../members/:userId` | private-channel membership |
| `GET/PUT/DELETE /api/workspaces/:wid/{categories|channels}/:targetId/permission-overrides/:roleId?` | override list/upsert/delete |
| `POST .../permission-overrides/preview` | stale-safe revisioned impact preview |
| `GET /api/workspaces/:wid/channels/:targetId/permissions/effective?userId=...` | effective channel permission explanation |

## Profiles

| Paths | Responsibility |
| --- | --- |
| `GET/PATCH /api/profile` | own display name, plain-text bio (≤200 code points, ≤5 lines; control/format/line-separator characters rejected) and warnings on the own profile per workspace; 30 updates/hour |
| `PUT/DELETE /api/profile/avatar` | replace/remove the avatar; body is raw `image/png`, exactly 256×256, ≤320 KiB, re-emitted with only IHDR/IDAT/IEND; the previous object is deleted immediately; 10 uploads/hour |
| `GET /api/users/:userId/avatar/:version` | avatar bytes for oneself or a user sharing a workspace, else 404; `private, max-age=86400, immutable`, `nosniff`, `default-src 'none'; sandbox`, same-origin CORP |
| `GET /api/workspaces/:wid/members/:userId/profile` | member profile; for a warned profile the bio and avatar are returned and the client withholds them until the viewer confirms |
| `GET /api/workspaces/:wid/profile-flags` | warned profiles in this workspace (MANAGE_MEMBERS or owner) |
| `PUT/DELETE /api/workspaces/:wid/members/:userId/profile-flag`, `POST .../profile-flag/deny` | warn/clear/deny an appeal; MANAGE_MEMBERS or owner, target strictly below the actor (owner never), step-up required |
| `POST /api/workspaces/:wid/profile-flag/appeal` | the warned user asks this workspace's managers to clear the warning; only after editing the profile following the warning, and once per account across all workspaces |

Bio, display name and avatar are server-readable profile data, not end-to-end encrypted. Profile edits audit only actor/action/time (`user.profile.update`, `user.avatar.update|remove`, no content). Warning operations audit actor, target and workspace (`profile.flag|unflag`, `profile.appeal.request|deny`).

## Direct messages

| Paths | Responsibility |
| --- | --- |
| `GET/POST /api/workspaces/:wid/dms` | authorized bounded DM list and creation; 2+ distinct participants, per-creator/workspace quotas |

DMs are represented by a channel plus conversation/member rows but cannot be managed through generic channel mutation/override routes.

## Messages and user state

| Paths | Responsibility |
| --- | --- |
| `GET/POST /api/channels/:id/messages` | paged ciphertext history and signed idempotent create |
| `PUT/DELETE /api/messages/:id` | signed edit/delete |
| `POST /api/messages/:id/reactions`, `POST /api/messages/:id/pin` | compact bounded state: 20 emoji/user, 20 distinct emoji and 1,000 reactions/message; 1,000 pins/channel |
| `GET /api/channels/:id/pins`, `POST /api/channels/:id/read` | pin list and read position |
| `GET /api/workspaces/:wid/channel-state`, `PATCH /api/channels/:id/preferences` | bounded channel preferences/read/unread state |
| `POST /api/messages/:id/bookmark`, `GET /api/bookmarks` | idempotent bookmark toggle and bounded bulk-authorized list |

## Channel keys

| Paths | Responsibility |
| --- | --- |
| `GET /api/channels/:id/key-recipients` | frozen bounded active-device recipient input |
| `GET /api/channels/:id/keys?scope=current` | authorized wrapped keys for active/pending epochs; this is the official-client default |
| `GET /api/channels/:id/keys?version=N` or `?versions=N,...` | one or at most 64 unique positive historical versions; active/pending candidates and the accepted retired delivery are returned within an absolute 864-delivery bound |
| `GET /api/channels/:id/keys` | deprecated rollout bridge for pre-change tabs: newest 16 active/pending/retired versions, with `Deprecation: true` and a warning; it is not an all-history API |
| `GET /api/channels/:id/device-directory?ids=<uuid,...>` | at most 64 explicitly requested public signing identities, returned only when current-eligible or referenced by a message/attachment in this channel |
| `GET /api/channels/:id/device-directory` | deprecated bounded rollout bridge: union of current devices and historical message/attachment signers, maximum 400, with `Deprecation: true`; clients must migrate to explicit IDs |
| `POST /api/channels/:id/keys` | propose immutable signed recipient deliveries/epoch commitment |
| `POST .../keys/start-fresh` | password-confirmed, device-signed fresh epoch for an authorized manager/DM participant that explicitly continues without unavailable history |
| `POST .../keys/acknowledge`, `POST .../keys/abort` | exact-delivery acknowledgement or signed abort/state transition |

## Attachments

| Paths | Responsibility |
| --- | --- |
| `POST /api/files/uploads` | reserve one bounded signed/encrypted upload; maximum 16 pending/user and 200/workspace |
| `GET/DELETE /api/files/uploads/:uploadId` | resume status/cancel |
| `PUT /api/files/uploads/:uploadId/chunks/:index` | write and record one fixed encrypted chunk |
| `POST /api/files/uploads/:uploadId/finalize` | validate manifest/chunks and publish attachment metadata |
| `GET /api/files/:id`, `GET /api/files/:id/chunks/:index` | authorized metadata and inert ciphertext stream |

## Audit

| Paths | Responsibility |
| --- | --- |
| `POST /api/workspaces/:wid/audit-logs?cursor=&limit=` | paginated audit read; the read itself is audited |
| `POST /api/workspaces/:wid/audit-integrity` | rate-limited current integrity status; not an unbounded user-triggered full scan |

Message create/edit/delete/replay, reaction/pin, channel preference and bookmark mutations append bounded actor/action/tenant/target/outcome/request-ID/trace-ID evidence atomically with state. That evidence excludes message ciphertext/nonces/signatures/idempotency keys/emoji and file bytes/plaintext names. Source IP is not retained by the application default; deployments may correlate an explicitly governed ingress log by request ID. Read positions and provisional upload-chunk registration/cleanup do not append one event per update, but share the same fail-closed authoritative-write admission. Presence and device activity are advisory, may be lost, and never grant access.

## WebSocket events

Client-to-server admission includes `channel:join`, `channel:leave`, `message:send/edit/delete`, `presence:update`, `typing:start/stop`, and `voice:join/leave/state/signal`. Server-to-client delivery includes durable message events, authorization/channel/key change events, presence/typing changes, voice participant/state/signal events, `member:profile-updated`, `workspace:profile-flags-changed`, `attention:new` (including `profile-appeal` to workspace managers) and `operation:error`.

Socket handshake is source/global bounded before token DB work, then binds a live session and active device. Joins and server-driven grants are reauthorized under workspace locks. Presence/typing/voice state is ephemeral; durable messages remain in PostgreSQL. Voice signaling is exact-schema/device-signed/sequence-checked by recipients, while audio is peer-to-peer DTLS-SRTP and never passes through the application server.

## Reliability contract

- Pagination is cursor/limit bounded where history may grow; fixed product collections have transactional hard caps and invariant checks.
- The official browser client applies a 60-second total-response deadline to every API call and propagates scope cancellation to in-flight fetch/body consumption.
- The official browser client bounds durable outbox entries to 100/device, authorization/voice work to 64 queued operations at each documented scope, and active attachment runtimes to 16.
- Capacity/invariant/dependency errors return 503 with `Retry-After` where retry may later succeed; validation/authorization/quota conflicts use stable 4xx responses.
- Clients must not retry an ambiguous mutation without its stable idempotency key.
- There is no generic server retry, public admin endpoint, API key bypass, GraphQL interface, webhook/bot API, or persistent background queue.

The OCI artifact also contains non-HTTP operator entry points at `dist/scripts/migrate-runtime.js` and `dist/scripts/initialize-audit-checkpoint.js`. The migrator deliberately loads only database configuration and should use a separate migration identity; the checkpoint initializer requires the normal audit/database configuration. Both run only while the app is stopped and must never be exposed as network endpoints.
