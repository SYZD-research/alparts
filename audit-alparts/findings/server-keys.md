# Server-side channel key management findings — alparts

Audit area: packages/server/src/services/key.service.ts, key-epoch-state.ts,
routes/keys.ts, device.service.ts, authorization.service.ts viewer-diff paths,
schema for channel_keys / channel_key_epochs / channel_key_epoch_recipients /
devices, websocket key-state notifications.

## F-KEY-001: Deliveries for retired epochs are unreachable for recipients that never acknowledged before retirement

- File: packages/server/src/services/key.service.ts:263-289 (delivery predicate), 660 (retired epochs reject delivery-add)
- Severity: Medium | Status: Confirmed
- Description: `getDeviceChannelKeys` returns a device's wraps only for
  (a) mutable (active/pending) versions, (b) the exact `acceptedDeliveryId` on its
  recipient row, or (c) confirmed protocol-v1 rows. A *non-required* recipient —
  a fresh-start epoch's non-initiator recipient, or a backfill recipient added to
  an active epoch with `requiredForActivation=false` (line 714) — that never
  fetched/acked before the epoch retired can never retrieve its wrap again. The
  signed delivery row persists in `channel_keys` (retirement deletes nothing) but
  no API path returns it, and delivery-add into a retired epoch is rejected
  (`INVALID_KEY_VERSION`). There is no recovery path.
- Impact: an authorized device permanently loses access to all ciphertext under
  that epoch. For a user's only device this is unrecoverable history loss for the
  epoch's whole lifetime (member joined/was offline for the entire epoch).
- Reproduction: (1) epoch N active; (2) user U registers device D; an accepted
  holder backfills D into epoch N via POST /channels/:id/keys; (3) D stays
  offline; (4) member removal triggers rotation, epoch N+1 activates, N retires;
  (5) D requests versions=[N] → receives no delivery → messages under N are
  permanently undecryptable for D.
- Remediation: extend the delivery predicate to include deliveries addressed to
  the device for versions where a recipient row exists (bounded, e.g. within
  requestedVersions / a retired-version cap), or delete such deliveries at
  retirement and document the boundary. Alternatively expose a signed
  re-delivery path for retired epochs limited to existing recipients.

## F-KEY-002: Viewer gain does not rotate; new/re-added members are backfilled into the current epoch covering pre-join ciphertext

- File: packages/server/src/services/authorization.service.ts:565-574;
  key.service.ts:704-717 (non-required recipient insert), 700 (accepted-holder gate);
  device.service.ts:236-238
- Severity: Medium (policy-dependent) | Status: Candidate (design decision — needs product confirmation)
- Description: `applyViewerEffectsAndRotation` forces rotation on viewer *loss*
  but only aborts pending epochs on viewer *gain*. Once joined, any of the new
  member's devices can receive a signed wrap for the *current active* epoch via
  delivery-add (the "standard Secure semantics permit backfilling" comment).
  That epoch key decrypts all ciphertext produced under it — including messages
  sent before the member gained access. A removed-then-re-added member similarly
  gets the post-removal epoch, which covers messages sent during their absence.
- Impact: joining a channel grants full history decryptability under the current
  epoch (which never rotates unless someone leaves/a device is revoked). If the
  product expectation is "members read from join forward," this is a
  confidentiality gap; if Slack-style "history follows the live key" is
  intended, document it explicitly.
- Remediation: confirm intent; if forward-only-on-join is required, treat viewer
  gain like loss (requireChannelKeyRotation) — cost: rotation churn — or gate
  backfill wraps to deliveries for epochs created after the membership grant.

## F-KEY-003: startFreshChannelKey bypasses the rotationRequired gate — healthy active epochs can be force-rotated

- File: packages/server/src/services/key.service.ts:576-593 (freshStart gates),
  606-614 (rotation gate skipped for freshStart), 578-580 (dm bypass);
  routes/keys.ts:71-75 (5/hr limit)
- Severity: Low–Medium | Status: Confirmed
- Description: `distributeChannelKeys` refuses a new epoch over a healthy active
  one (`KEY_ROTATION_NOT_REQUIRED`, line 607). `startFreshChannelKey` has no
  `effectiveRotationRequired` check: it only requires (i) some epoch history,
  (ii) the sender *device* lacks an accepted delivery for the active epoch
  (line 582-588 — trivially satisfied by any unsynced/secondary device),
  (iii) password + fresh-start signature, (iv) MANAGE_CHANNELS — or, for
  `channel.type === 'dm'`, any member. It also aborts any in-flight honest
  pending epoch (line 589-592), including one it is not a recipient of.
- Impact: a DM member (no permissions) or a manager can force rotation churn of
  a healthy channel ≤5/hour: brief write outage (keyRotationRequired set until
  sender-only activation), version burn, audit noise, and killing another's
  pending proposal. No confidentiality loss — all members still get wraps — but
  the asymmetry vs. the distribute path looks unintended.
- Remediation: require `effectiveRotationRequired || historyRecoveryRequired ||
  !activeEpoch` for fresh-start, or require the caller's *user* (not merely the
  calling device) to lack any accepted holder when an active epoch exists.

## F-KEY-004: acknowledge/abort mutate epoch status under workspace 'share' lock — interleaves with message-send epoch validation

- File: packages/server/src/services/key.service.ts:818 (ack, 'share'), 984
  (abort, 'share') vs services/message.service.ts:530 ('share'),
  file.service.ts:482,497 ('share')
- Severity: Low | Status: Candidate
- Description: `acknowledgeChannelKey` transitions pending→active and retires
  the old active epoch while holding only a SHARE workspace lock — the same mode
  message/attachment writes hold when validating `keyVersion` is the active
  epoch. SHARE does not conflict with SHARE, so a send can validate epoch N as
  active while a concurrent ack retires N and activates N+1, committing
  ciphertext under a just-retired version. Membership changes (UPDATE lock) and
  device revocation (device row UPDATE + key advisory lock) do serialize
  correctly; the anomaly is limited to the epoch-boundary transition.
- Impact: ordering anomaly only — the message remains decryptable by epoch-N
  holders; no confidentiality loss. Slightly weakens "send ⇒ epoch active at
  commit" reasoning for audit/ordering.
- Remediation: use 'update' in acknowledgeChannelKey/abortPendingChannelKey
  (all key ops already serialize on the global advisory lock, so added
  contention is bounded), or document the accepted interleaving.

## F-KEY-005: Accepted holders can submit alternative wraps per recipient — server verifies signature, cannot verify plaintext; ack is irrevocable

- File: packages/server/src/services/key.service.ts:544-552 (signature verify),
  684-717 (candidate insert + dedupe), 868-870 (ack immutability);
  mitigation: packages/client/src/services/crypto.service.ts:860-875
- Severity: Low | Status: Candidate (protocol limitation; mitigated client-side)
- Description: after accepting an epoch, any holder can delivery-add one
  candidate wrap per (recipient, version), signed under their own identity. The
  server verifies the ECDSA wrap signature but cannot verify the wrapped bytes
  match the epoch commitment (zero-knowledge). The official client unwraps,
  verifies the commitment, and skips bad candidates before signing an ack — but
  a non-conformant/buggy client that acks a poisoned wrap is permanently bound:
  `acceptedDeliveryId` cannot be changed (`KEY_ALREADY_ACKNOWLEDGED`) and there
  is no server-side reject/reset path.
- Impact: per-device epoch lockout for a faulty client; bounded candidate spam
  (≤ MAX_KEY_RECIPIENTS per device across distributors).
- Remediation: consider a recipient-signed "reject delivery" that permits
  re-acknowledging a different candidate, or document ack irrevocability +
  mandatory pre-ack commitment verification as a client contract.

## F-KEY-006: key-recipients / device-directory expose full member device directory and epoch acknowledgement state to any viewer

- File: packages/server/src/services/key.service.ts:174-197, 333-449;
  routes/keys.ts:77-152
- Severity: Low (informational) | Status: Candidate
- Description: any channel viewer — including read-only members and sessions
  with no bound device — receives every viewer device's identity key, the
  active-epoch accepted device set, pending-epoch required/acked device ids and
  rotation flags. This is needed for client-side fanout, but it is also a
  device/membership enumeration oracle (device counts, identity keys, ack
  progress). The legacy unscoped directory additionally returns up to 400
  identity keys including revoked/removed historical signers (intended for
  verification).
- Remediation: acceptable if the disclosure model is intentional; otherwise
  restrict the recipient directory to members with send capability and keep the
  verification-only directory strictly signer-scoped.

## F-KEY-007: Pending epoch wedging — writes block until every required recipient acks; abort needs a pending-recipient device

- File: packages/server/src/services/key.service.ts:643 (flag set at proposal),
  913-938 (all-required activation), 1018-1044 (abort eligibility);
  services/message.service.ts:552 (sends rejected)
- Severity: Low | Status: Candidate (availability trade-off)
- Description: proposing an epoch immediately sets `keyRotationRequired`, so all
  sends fail until activation — and activation requires *every* required
  recipient (every eligible device at proposal) to acknowledge. One offline/lost
  device wedges the channel. Unwedge paths: abort — requires the calling device
  to be a pending recipient (or `pendingInvalid` from a revoked recipient) plus
  MANAGE_CHANNELS/dm — or fresh-start (password). A manager whose device is not
  a pending recipient cannot directly abort a merely-stalled epoch. During a
  legitimately-required rotation window an insider can prolong outage by
  re-proposing after each abort (rate-limited: 60 proposals/min, 10 aborts/hr).
- Remediation: fresh-start is the intended escape — verify clients surface it
  for stalled epochs; consider an age-based manager override abort for pending
  epochs past a TTL.

## F-KEY-008: Wraps addressed to revoked devices are retained; stale recipient bookkeeping persists until epoch end

- File: packages/server/src/services/device.service.ts:244-298;
  key.service.ts:740-753
- Severity: Informational | Status: Confirmed (hygiene; adjacent to R-036)
- Description: `revokeDevice` tombstones the device and deletes its sessions but
  leaves `channel_keys` deliveries addressed to it. They are unreachable (all
  fetch/eligibility paths filter `isNull(revokedAt)`), become pendingInvalid on
  pending epochs (eventually aborted+cleaned), and persist on active epochs
  until retirement. Bounded storage only; no access path exists.
- Remediation: optional cleanup of revoked-device deliveries in
  abort/rotation paths; track under retention lifecycle work.

## Verified non-issues (checked, not reported elsewhere)

- Zero-knowledge holds: server stores only RSA-OAEP wraps + SHA-256 commitments;
  no plaintext key path found.
- Wraps are signature-verified server-side against the distributor's registered
  identity key (verifyChannelKeyWrapSignature); no trust-on-store. Candidate
  tuples immutable (KEY_CANDIDATE_IMMUTABLE), per-distributor unique.
- `getDeviceChannelKeys` is strictly device-scoped — a member can never fetch
  another device's wraps; retired versions expose only the device's own accepted
  delivery. Arbitrary `versions` requests leak nothing.
- Device enrollment: session-bound challenge proof (possession of the identity
  signing key) + password step-up for NEW identities; revoked identities
  tombstoned (IDENTITY_REVOKED); canonicalization + serialization advisory lock
  prevent duplicate-equivalent rows. Public-key substitution requires the
  private key — confirmed safe.
- Revocation blocks future deliveries and fetches (`isNull(revokedAt)` on every
  eligibility/fetch path), forces rotation via `hasRevokedEpochRecipient` on
  every send/finalize, disconnects sessions, emits `workspace:key-state-dirty`;
  bindDevice row locks serialize against revoke.
- Sends/attachments require `keyVersion` = the single *active* epoch AND the
  sender's accepted delivery — prevents publishing under stale epochs that
  removed members still hold, and under pending/aborted versions.
- Version arithmetic: 1..1,000,000, monotonic nextVersion computed under the
  global key advisory lock; one pending + one active enforced by partial unique
  indexes; no overflow path.
- Abort requires a device-signed statement from a pending recipient (or
  pendingInvalid) plus MANAGE_CHANNELS/dm, and non-key-holders cannot abort when
  eligible accepted holders remain (lines 1032-1044).
- Activation re-validates the frozen recipient snapshot against current
  eligibility — viewer gain/loss or device register/revoke between proposal and
  activation aborts the epoch (lines 914-918, 1118-1130).
- Lock ordering is consistent: global key advisory → workspace row → channel
  advisory; membership mutations hold workspace UPDATE which serializes against
  key ops' UPDATE/SHARE. All mutations additionally serialize through the
  single-slot audit commit gate.
