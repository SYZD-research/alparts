# ADR 0014: SFU calls encrypt every frame under per-call sender keys

- **Status:** Implemented; independent security acceptance pending
- **Date:** 2026-10-09
- **Context source:** formal model M8 (VE2, M8k; [re-verification record](../../formal-model/REVERIFICATION.ja.md)), [RISK_REGISTER](../RISK_REGISTER.md) R-052, SPECIFICATION `MEDIA-08`, `MEDIA-09`, `MEDIA-13`

## Context

Calls ran as a P2P mesh of up to eight participants: DTLS-SRTP between the browsers, with SDP signed by device keys. The server also had a mediasoup SFU (`VOICE_SFU_ENABLED`, off by default) that no client used. An SFU ends DTLS-SRTP in the server's media worker, so in an SFU call the server reads every audio frame (M8 VE2 was a FINDING). `MEDIA-08` requires that neither the SFU, the TURN relay nor the application server can decrypt media, and `MEDIA-09` that call keys change when participants change.

The earlier plan was to derive frame keys from the channel's MLS group. That does not fit: a `voice` channel has no MLS group (`mls-group.service.ts` skips them), and on a text channel the group holds every member who can view the channel, not the participants of the call. A key derived from it would be readable by members who never joined, and changing it per join or leave would need an MLS commit per call event.

## Decision

When the operator enables the SFU, every call of the deployment goes through it, and every audio frame is encrypted by its sender above SRTP. The keys belong to the call, not the channel.

- **Media mode.** The `voice:join` answer says `media: 'sfu'`. A client joins such a call only under a participant id it chose itself (a fresh random UUID per call), and only if it can encrypt frames (`RTCRtpScriptTransform`). Otherwise it does not join, and tells the user that this browser cannot keep the call private. P2P signaling is refused in SFU mode. The SFU session (`voice:sfu:join`) belongs to the socket's registered call participant under its id (M8 VP7), and media requests are rechecked against the live session, call registry entry and room.
- **Frames.** SFrame (RFC 9605) with `AES_128_GCM_SHA256_128` runs in a dedicated worker through `RTCRtpScriptTransform`. mediasoup-client sets it on each sender and receiver (`onRtpSender`, `onRtpReceiver`) before any media flows. Each consumer stays paused at the server until the client has its decrypting transform in place. Nothing is sent without a send key. A received frame reaches the decoder only if it decrypts under a key owned by the participant whose stream it arrived on, with a counter not seen before (128-frame window). Every other frame is dropped. The header encoding is checked against all 289 header vectors of the RFC, and encryption against its AES-GCM vector.
- **Keys.** Each participant makes its own random 32-byte base key with a random 32-bit key id, which is the SFrame KID. It sends the key to each other participant in a `voice:key` message, which is:
  - wrapped (RSA-OAEP-256) for the recipient device's encryption key, and signed (ECDSA P-256) by the sender device;
  - bound to the channel, the sender and target participant ids and device ids, the key id, and a sequence number per sender and target;
  - checked by the receiver against the device directory, also for which user owns each device;
  - accepted only from a current participant and only if its sequence is newer, and only under a key id that no other key of the call used.

  The server relays a key message only between the registered sockets of the two participants, in SFU mode, under a rate limit.
- **Rekeying (`MEDIA-09`).** A participant replaces its key whenever someone joins, so a newcomer gets no key that carried earlier audio. It also replaces its key whenever someone leaves, so a former participant holds no key for later audio.
  - After a join it starts sending under the new key 250 ms after the server relayed it, so receivers can install it first.
  - After a leave it switches at once.
  - A key is never used if someone it was sent to left before it came into use (while it was signed, sent, or waited for). The rotation queued by that leave replaces it.
  - A key message that arrives before the news that its sender joined is held (at most 16) and checked once the sender is in the call.
  - Receivers keep the newest three keys of each sender, for frames still in flight.
- **Self-hosting (`MEDIA-13`).** mediasoup runs in the application's own worker processes; each worker listens on its own fixed port from `VOICE_SFU_BASE_PORT`, and tries the same port again if it was busy. TURN stays operator-provided.

## Consequences

The server that runs the SFU and relays signaling and key messages sees only ciphertext. M8 VE2 now holds; VE2-ctl shows that it would read every frame without frame encryption.

- **Real media.** `conformance/voice-sfu-e2e.mts` runs real mediasoup and Chromium with three participants and a server that reads RTP and relabels and replays streams. It checks:
  - every participant hears the others;
  - every frame the server reads is SFrame ciphertext under an announced key, with unique counters;
  - a newcomer's keys were not used before it joined, and a former participant gets no key after it left;
  - a stream relabeled as another participant's is dropped, and replayed frames are dropped.

  With frame encryption replaced by a pass-through worker, five of the six checks fail as intended.
- **Model check.** M8k runs the real key manager for three clients under a server that chooses every delivery, repetition and notification order. In every explored schedule, KJ, KL, KR and KH hold, and each control breaks its property. It found a race, now fixed: a leave processed while the key for the departing participant was being signed still sent that key and then used it.

The limits are those of the device directory and of symmetric frame keys:

- **False device directory.** A server that serves a false device directory can receive a frame key (VE2-directory, as VE1-directory for P2P calls and F-E2E-001 for messages).
- **Server-chosen membership.** The server decides who is in a call. A device it adds receives every key, but it is shown in the call like every participant (VE2-members).
- **Shared frame keys.** Every receiver holds the sender's key. A participant, helped by the server relabeling streams, can pass off audio as another participant's (VE2-forge). Neither can do it alone (VE2-attribution).
- **Metadata.** The server sees who is in a call and, from packet timing and size, when each participant speaks (VE2-metadata).
- **Browser support.** Browsers without `RTCRtpScriptTransform` cannot join SFU calls.

P2P calls are unchanged when the SFU is off. Video, screen sharing and recording remain out of scope.
