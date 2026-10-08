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
| `POST /api/devices/challenge`, `POST /api/devices`, `POST /api/devices/:id/bind` | session-bound device enrollment/binding proof; cleanup of protocol-2/3 provisional epochs (none are created since migration 0023) is partitioned by the bounded workspace set; enrollment and approval tell the user's devices to publish group packages for every channel they see |
| `GET /api/devices`, `DELETE /api/devices/:id` | active/revoked device inventory and idempotent revocation; dirty-key notifications name only current workspaces with an affected recipient or group member, and members of every group that still contains the revoked device are told to remove it |

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
| `GET/PATCH /api/profile` | own display name, plain-text bio (≤200 code points, ≤5 lines; control/format/line-separator characters rejected) and warnings on the own profile per workspace; 30 updates/hour. A save that changes nothing is not recorded and does not count as a change |
| `PUT/DELETE /api/profile/avatar` | replace/remove the avatar; body is raw `image/png`, exactly 256×256, ≤320 KiB; the decoded pixels are re-encoded into a fresh IHDR/IDAT/IEND PNG (nothing else from the upload is kept); re-uploading the picture in use is a no-op; the previous object is deleted immediately; 10 uploads/hour |
| `GET /api/users/:userId/avatar/:version` | avatar bytes for oneself or a user sharing a workspace, else 404; `private, max-age=86400, immutable`, `nosniff`, `default-src 'none'; sandbox`, same-origin CORP |
| `GET /api/workspaces/:wid/members/:userId/profile` | member profile; for a warned profile the bio and avatar are returned and the client withholds them until the viewer confirms |
| `GET /api/workspaces/:wid/profile-flags` | warned profiles in this workspace (MANAGE_MEMBERS or owner) |
| `GET /api/workspaces/:wid/warned-users` | any member: IDs of users warned in this workspace, including former members whose messages remain (newest 1,000; `complete: false` when cut, and clients then hide pictures of unlisted non-members) |
| `PUT/DELETE /api/workspaces/:wid/members/:userId/profile-flag`, `POST .../profile-flag/deny` | warn/clear/deny an appeal; MANAGE_MEMBERS or owner, target strictly below the actor (owner never), step-up required |
| `POST /api/workspaces/:wid/profile-flag/appeal` | the warned user asks this workspace's managers to clear the warning; only after actually changing the profile following the warning (both times come from the database clock), and once per account across all workspaces |

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

## Forums

A forum is a channel of type `forum`. Posts and replies are messages in that channel, encrypted with its channel key. Every forum event uses the v4 signed envelope, which adds `postId` (null only for the message that starts a post) to the v3 fields; the server requires v4 in forums and rejects it elsewhere. Starting a post needs `CREATE_POSTS`; replying needs `SEND_MESSAGES`. Titles are part of the encrypted text; tag names are plaintext, like channel names.

| Paths | Responsibility |
| --- | --- |
| `GET/POST /api/channels/:id/forum/posts` | page posts (pinned first, then `sort=activity\|created`, optional `tagId`) with the viewer's capabilities; start a signed post with up to 5 tags |
| `POST /api/channels/:id/messages` with `postId`; `PUT/DELETE /api/messages/:id` with `postId` | reply to, edit or delete within a post; a reply may quote only the post or a reply in it; locked posts accept replies from channel managers only |
| `GET /api/forum/posts/:postId`, `GET /api/forum/posts/:postId/messages` | one post summary; its events newest first |
| `POST /api/forum/posts/:postId/read` | record the viewer's read position: the post's server activity time, or the earlier `shownActivityAt` the client actually displayed (later replies stay unread) |
| `PUT /api/forum/posts/:postId/lock` / `resolved` / `tags` | lock (managers); resolved and tags (author or managers); audited |
| `GET/POST /api/channels/:id/forum/tags`, `PATCH/DELETE /api/forum/tags/:tagId` | list; manager-only create/rename/delete (20 per forum, 20 characters, channel-name text rules) |

Anything the caller cannot see answers 404. Pinning applies to whole posts only. `POST /api/messages/:id/pin` toggles without a body; with `{ "pinned": true|false }` it sets that state, so a retried request is harmless. For a forum post the response also carries `forumPost`, the post's new list state, read in the same transaction as the pin; notifying other viewers happens after commit and never changes the response.

## Channel keys

| Paths | Responsibility |
| --- | --- |
| `GET /api/channels/:id/key-recipients` | the caller's bounded key state: active version and protocol, eligible devices, and for group protocol 4 the group (`genesisVersion`, `groupId`, `epoch`, `transcript`, roster), `ownMembership`, `pendingAddDeviceIds`, `requiredRemoveDeviceIds`, `updateRequired`, `ownLeafRefreshDue`, `canCommit`, `canCreate`, `genesisWaiting`, `rotationRequired` and `historyRecoveryRequired`. The former pending-epoch fields stay for old clients and are always empty. A read by a member also records that the device is online. |
| `GET /api/channels/:id/keys?scope=current` | authorized wrapped keys and protocol-3 locators for protocol-2/3 epochs; group protocol 4 versions have no deliveries (devices derive them from their group) |
| `GET /api/channels/:id/keys?version=N` or `?versions=N,...` | one or at most 64 unique positive historical versions; active/pending candidates and the accepted retired delivery are returned within an absolute 864-delivery bound |
| `GET /api/channels/:id/keys` | deprecated rollout bridge for pre-change tabs: newest 16 active/pending/retired versions, with `Deprecation: true` and a warning; it is not an all-history API |
| `GET /api/channels/:id/device-directory?ids=<uuid,...>` | at most 64 explicitly requested public signing identities, returned only when current-eligible or referenced by a message/attachment in this channel |
| `GET /api/channels/:id/device-directory` | deprecated bounded rollout bridge: union of current devices and historical message/attachment signers, maximum 400, with `Deprecation: true`; clients must migrate to explicit IDs |
| `POST /api/channels/:id/keys` | an identical resend of an existing protocol-2 delivery only. Since migration 0023 every channel with an active protocol-2/3 key needs its first group before anything new, so a new delivery is refused (409 `KEY_ROTATION_REQUIRED`, or 400 `INVALID_KEY_VERSION` once the first group retired that key); a new device reads earlier versions only from the recovery archive. New versions, protocol-3 versions and group protocol 4 versions are refused |
| `POST .../keys/start-fresh` | retired: `410 UPDATE_REQUIRED` |
| `POST .../keys/acknowledge`, `POST .../keys/abort` | signed acknowledgement of a protocol-2/3 delivery, and the legacy abort of a pending epoch (none exist since migration 0023) |

## Channel groups (group protocol 4)

One MLS group continues per channel; see [the protocol document](../security/ACCOUNT_AND_GROUP_SECURITY.md#group-key-lifecycle). Every route needs a bound device; channel routes also need current channel access. Errors use `{ error: 'GROUP_STATE_CHANGED', code, message, statusCode }`: 409 when the answer depends on state the client may have read earlier (read the state again and retry), 403 when the request is invalid in every state or not permitted for this device. Schema errors are 400 `VALIDATION`; unknown channels or versions are 404. Reads allow 600 requests per minute per device.

| Paths | Responsibility |
| --- | --- |
| `POST /api/channels/:id/mls/group/packages` | publish this device's one-time member package `{packageId, keyPackage, signature, rejoin?}`. 201 when created or changed, 200 for an identical resend. 409 `PACKAGE_CONSUMED` (package ID used before), `PACKAGE_KEY_CONFLICT`, `ALREADY_MEMBER` (a member without `rejoin`), `REJOIN_LIMIT` (more than three rejoin requests in 24 hours); 403 `INVALID_MLS` or `DEVICE_APPROVAL_REQUIRED`. `rejoin` from a non-member is ignored. 120 per minute per device. |
| `GET /api/channels/:id/mls/group/packages` | valid packages of the devices waiting to be added (and rejoin requests), with user ID and current identity key; only for an eligible device |
| `POST /api/channels/:id/mls/group/commits` | `{commit}`: one signed commit envelope (`kind: 'create'` for a channel's first group, `'commit'` otherwise). 201 `{version, epoch}`; a retry with the same bytes answers 200 `{version, epoch, replay: true}`. 409 codes include `MLS_CONFLICT` (also for a create that lost the race for the channel's first group), `GENESIS_WAITING`, `KEY_ROTATION_NOT_REQUIRED`, `COMMIT_RATE_LIMITED`, `PACKAGE_KEY_CONFLICT`; 403 `INVALID_MLS` (including an UpdatePath longer than any tree of 400 members, 9 nodes), and `KEY_FRESH_START_REQUIRED` for a create on a group that existed before. The route ID must equal `commit.channelId`. 60 per minute per device and channel; add-only and empty commits are also limited to 60 per channel per hour. |
| `POST /api/channels/:id/mls/group/fresh-start` | `{commit, freshStartSignature}` with exact-action step-up: replace the group with a new one (create) when the documented conditions hold, otherwise 409 `KEY_FRESH_START_NOT_REQUIRED`. Managers (or the other DM participants) receive `attention:new` with kind `channel-restarted`. |
| `GET /api/channels/:id/mls/group/commits?after=V&limit=L` | accepted commits after version V in ascending order (`L` at most 16, about 4 MiB per page) as `{version, transcript, envelope}`: only versions at which this device was a member, and the version that removed it; the page ends at the first version it may not see |
| `GET /api/channels/:id/mls/group/members?version=V` | roster at version V with each member's add-time package, signature, leaf index, directory sequence and current identity key; only for a device that was a member at V |
| `GET /api/mls/group/pending?cursor=` | for this device across the user's workspaces: channels where it should publish a package (`needPackage`) and channels where it is a usable member and a commit is due (`needCommit`), paged by workspace `cursor` |
| `GET /api/channels/:id/mls/epochs/:version` | signed protocol-3 epoch envelope for history, for a version this device received or that its received versions link back to, and the active version before a channel's first group; any other version, including group protocol 4 versions (read through the commit log), is 404 |
| `GET/POST /api/channels/:id/mls/packages`, `POST .../mls/epochs`, `POST .../mls/epochs/fresh-start` | retired protocol-3 write routes: `410 UPDATE_REQUIRED`, so tabs from before the upgrade reload |

Commit and fresh-start bodies have their own 2 MiB parser allowance; other JSON stays at 512 KiB. Encrypted message, edit, delete, forum and attachment-finalization refusals keep HTTP 400 and add a `code`: `KEY_VERSION_STALE` with `currentVersion` (catch up and seal again), `KEY_ROTATION_REQUIRED` (a removal or refresh commit is needed first) or `INVALID_KEY_VERSION` (stop).

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

Client-to-server admission includes `channel:join`, `channel:leave`, `message:send/edit/delete`, `presence:update`, `typing:start/stop`, and `voice:join/leave/state/signal`. Server-to-client delivery includes durable message events, authorization/channel/key change events (`channel:key-rotation-required {channelId}` goes to the channel room and to the user rooms of current viewers with an eligible device after an accepted commit, a new or changed package, a viewer gain or a device revocation, and to the user's own room for every channel it sees after device or recovery approval), presence/typing changes, voice participant/state/signal events, `member:profile-updated`, `workspace:profile-flags-changed`, `attention:new` (including `profile-appeal` to workspace managers; forum mentions and replies name the post), `forum:post-updated`, `forum:post-removed`, `forum:tags-updated`, `forum:post-read` (to the reader's own sessions) and `operation:error`. `message:send` accepts `postId` for forum replies; posts are started over HTTP.

Socket handshake is source/global bounded before token DB work, then binds a live session and active device. Joins and server-driven grants are reauthorized under workspace locks. Presence/typing/voice state is ephemeral; durable messages remain in PostgreSQL. Voice signaling is exact-schema/device-signed/sequence-checked by recipients, while audio is peer-to-peer DTLS-SRTP and never passes through the application server.

## Reliability contract

- Pagination is cursor/limit bounded where history may grow; fixed product collections have transactional hard caps and invariant checks.
- The official browser client applies a 60-second total-response deadline to every API call and propagates scope cancellation to in-flight fetch/body consumption.
- The official browser client bounds durable outbox entries to 100/device, authorization/voice work to 64 queued operations at each documented scope, and active attachment runtimes to 16.
- Capacity/invariant/dependency errors return 503 with `Retry-After` where retry may later succeed; validation/authorization/quota conflicts use stable 4xx responses.
- Clients must not retry an ambiguous mutation without its stable idempotency key.
- There is no generic server retry, public admin endpoint, API key bypass, GraphQL interface, webhook/bot API, or persistent background queue.

The OCI artifact also contains non-HTTP operator entry points at `dist/scripts/migrate-runtime.js` and `dist/scripts/initialize-audit-checkpoint.js`, and `dist/scripts/initialize-audit-head.js` (existing-checkpoint upgrade). The migrator deliberately loads only database configuration and should use a separate migration identity; the checkpoint initializer requires the normal audit/database configuration. Both run only while the app is stopped and must never be exposed as network endpoints.
