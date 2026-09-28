# F-INPUT-001 — Display/name fields accept Unicode control & bidirectional override characters

**Status:** Confirmed (source-verified, static)
**Severity:** Low-Medium (invite-gated spoofing vector)
**Class:** Input validation / UI integrity
**Evidence level:** R1 (passive source review)

## Summary

User-controlled display strings — `displayName`, workspace `name`, channel `name`, role `name`, device `name` — are validated only by `trim().min(1).max(100)`. No filtering of C0/C1 control characters, Unicode bidirectional override characters (U+202A–U+202E), bidi isolates (U+2066–U+2069), or zero-width characters is applied at registration or any later point.

The codebase already treats this character class as dangerous in two other places — attachment filenames and large-paste previews both strip exactly these ranges — so the absence on identity/display fields is an inconsistent-application gap rather than an accepted design.

## Evidence

| Location | Handling |
|----------|----------|
| `packages/server/src/routes/auth.ts:20` | `displayName: z.string().trim().min(1).max(100)` — no char filter |
| `packages/server/src/routes/workspaces.ts:14`, `channels.ts:22,30,37,41`, `roles.ts:25,30`, `devices.ts:11` | same `trim().min(1).max(100)` pattern, no filter |
| `packages/client/src/services/attachment-crypto.service.ts:360-366` | `sanitizeAttachmentFilename` strips `[\\/:*?"<>|\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]` |
| `packages/client/src/stores/paste-preview-model.ts:34` | replaces `[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]` with `` |

`displayName` is set only at registration (invite-token-gated); no profile-update endpoint exists, so the value is immutable post-registration.

## Impact

- An invited member (or an attacker holding an invitation token) can register with names containing RLO/LRO overrides → visually reversed or reordered text in member lists, DM lists, mention autocomplete, message author headers, and audit-log panels across web/desktop/Android renderers.
- Zero-width characters (ZWSP/ZWNJ/ZWJ, U+200B–U+200D, U+FEFF) enable visually identical names to another member — impersonation in a UI that has no per-user visual distinguisher beyond displayName + avatar letter.
- Compounds F-E2E-001 (no device-verification UI): a spoofed display name is the primary social identifier users see.
- Lower-privilege vectors (channel/role/workspace names) require elevated permissions but share the same gap.

Not exploitable for injection (React escapes text nodes; no `dangerouslySetInnerHTML` exists; CSP `script-src 'self'`). The risk is purely deceptive rendering / spoofing.

## Recommendation

Apply the same character-class filter used by `sanitizeAttachmentFilename` (and paste-preview) to all user-controlled display strings at the server schema layer:

```ts
const SAFE_DISPLAY_TEXT = /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069\u200b-\u200d\ufeff]/;
displayName: z.string().trim().min(1).max(100).refine(v => !SAFE_DISPLAY_TEXT.test(v))
```

Apply uniformly to `displayName`, workspace/channel/role/device `name`, channel `topic`, and DM-visible strings. Client-side defense-in-depth rendering filter is optional; server rejection is the durable fix.

## Verification limits

- Static review only; no live render test performed.
- Does not cover grapheme-level spoofing (confusable homoglyphs like `а`/`a`) — that requires NFKC-confusable detection, a larger policy decision.
