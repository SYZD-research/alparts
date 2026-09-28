# Area: client message store performance

## F-PERF-001: addMessage is O(n²) per event burst — UI freeze under load
- Severity: medium
- Status: confirmed (code-traced + matching test failure)
- Location:
  - packages/client/src/stores/message.store.ts:512-524 (addMessage → channelUpdate)
  - packages/client/src/stores/message.store.ts:120-127 (channelUpdate → mergeMessageEvents + projectMessageEvents)
  - packages/client/src/stores/message-projector.ts:194-195 (projectMessageEvents re-invokes mergeMessageEvents internally)
- Description:
  - `addMessage` (message.store.ts:513) first calls `mergeMessageEvents(existing, [message])` — merge #1 over the full resident window (up to MAX_RESIDENT_MESSAGE_EVENTS_PER_CHANNEL = 1000).
  - It then calls `channelUpdate`, which runs `mergeMessageEvents(events)` — merge #2 over the same window (message.store.ts:121) — plus an O(n) `hasAuthenticatedEnvelopeConflict` scan and O(channels) object spreads.
  - `channelUpdate` then calls `projectMessageEvents(merged)`, which internally calls `mergeMessageEvents` AGAIN — merge #3 (message-projector.ts:195) — before the O(n) projection pass.
  - Per single incoming WS event: ~3×O(n log n) merge+sort + O(n) projection + O(n) conflict scan. During a burst of N events (reconnect backfill, rapid reactions/edits, system events) total cost is O(N·n log n) ≈ O(n²).
  - `applyAttachment` (line 526-541) has the same shape: full-array map + `channelUpdate` → merges #2/#3 again per attachment event.
  - Reproduced by the repo's own test: `packages/client/src/stores/message-channel-cleanup.test.ts` "retains only the newest bounded event window for a channel" exceeded the 5000 ms vitest timeout inserting 1001 events during the full-suite run (`pnpm test` on 2026-09-23, 1 of 136 tests failed, test phase ~8.69s).
  - Re-run in isolation on 2026-09-23 the same file passes in ~3.0s — the quadratic cost becomes fatal only under CPU contention (i.e., exactly when the client is busy: reconnect backfill, large bursts), which is the hostile-load scenario.
  - Any channel member can trigger reactions/edits that flow through the same path, so a hostile member can degrade every member's client responsiveness (DoS-adjacent UX impact).
- Impact: UI main-thread jank/freeze on busy channels; degraded availability of the client under adversarial message bursts; test suite flaky/failing.
- Remediation:
  - Cache projected state: apply single-event delta in addMessage instead of re-projecting the whole window (projectMessageEvents has an incremental path for edit/delete/reaction targets already).
  - At minimum, drop the redundant inner `mergeMessageEvents` inside `projectMessageEvents` when input is already merged, or pass a `preMerged` flag.
  - Consider amortized batching: coalesce WS events per animation frame / microtask into one channelUpdate.

## F-PERF-002: (resolved — not a bug) decryptMessages triggered per addMessage
- Severity: none
- Status: resolved — verified not a defect (2026-09-23 follow-up)
- Location: packages/client/src/stores/message.store.ts:705 (`decryptMessages: (channelId) => messageDecryptWorkers.run(channelId, ...)`), services/coalesced-channel-worker.ts
- Description: Every addMessage fires `decryptMessages(channelId)`, but the call is routed through `CoalescedChannelWorker` which guarantees at most one in-flight operation per channel plus a single boolean `pending` flag — never an attacker-sized queue. Repeated calls coalesce into one extra pass; the pass itself only processes messages with `cryptoVerificationState === undefined` (incremental, not full-window). Capacity overflow (`COALESCED_WORK_CAPACITY`) fails promptly so the caller can reconcile via REST. A 30s hard timeout aborts wedged work.
- Conclusion: decryption is already coalesced and incremental. The quadratic cost in F-PERF-001 is confined to the merge/project path, not decryption.
