# Alparts Security Audit — Triage Master Index

- **Repository**: `/home/nia/bc/alparts` @ `e4766f2277d7212d4de66a39df41eb3dcb6abd45` (clean tree)
- **Ledger**: Quus `engagement:alparts-audit-1` — 58 events, hash-chained, all artifacts anchored by sha256
- **Audit dir**: `/home/nia/bc/audit-alparts/findings/` — evidence files listed per finding
- **Date**: 2026-09-24 | **Mode**: passive source-level audit, every non-test production file read line-by-line

## How to triage

**Severity**: `Medium` = exploitable/data-loss under plausible conditions · `Low` = bounded impact or requires strong preconditions · `Info` = hygiene/documentation.

**Status**: `Confirmed` = code-verified · `Candidate` = logic-verified, needs runtime confirmation · `Design` = architectural gap, not a bug · `Rec` = hardening recommendation.

**Owner**: `server` `client` `crypto` `infra` `process` — suggested owning area.

**Naming**: `F-<AREA>-<n>` where AREA ∈ KEY, STORE, COORD, DEP, INPUT, NET, SUPPLY, TRUST, CONTAIN, MOBILE, E2E, PQC, PERF. `F-DEP-*` in dependency-vulns.md are indexed as `F-COORD-001`.

## Summary

**42 findings**: 9 Medium · 28 Low · 5 Info. **Zero High/Critical. Zero exploitable implementation vulnerabilities found** — all confirmed items are correctness/data-loss bugs or design-level trust-anchor placements. The codebase is exceptionally hardened; remaining risk concentrates in design decisions (key transparency, PQ migration, audit signing, web code delivery).

## Priority action queue

Order for remediation sprints. Items marked ★ fix data loss or have one-line fixes.

| # | ID | Why first |
|---|-----|-----------|
| 1 | **F-KEY-001** ★ | Permanent ciphertext loss for offline devices — worst confirmed user-facing bug |
| 2 | **F-STORE-002** ★ | Network blip destroys drafts + unsent outbox plaintext (data loss) |
| 3 | **F-STORE-001** ★ | Late login resurrection after logout — broken half-session |
| 4 | **F-COORD-001** ★ | 4 moderate dep advisories; qs reachable via `req.query` — one-line fix available (`app.set('query parser','simple')`) |
| 5 | **F-INPUT-001** | Unicode/bidi spoofing in display names — same char class already stripped elsewhere |
| 6 | **F-PERF-001** | O(n²) merge on every WS event — repo's own test timed out |
| 7 | **F-KEY-003/004/005/007** | Key-epoch edge cases (rotation churn, ordering, wrap injection, wedge) |
| 8 | **F-STORE-003–019** | Client store race/UI bugs — batch as one client-hardening sprint |
| 9 | **F-COORD-002/003/004** | Ops gaps: no account-disablement, unauth ready-probe, single-process limit |

## Design-level decisions (require owner sign-off, not bug fixes)

| ID | Decision required | Proposal in |
|----|-------------------|-------------|
| F-PQC-001 | HNDL: adopt `pqc-migration-design.md` (6-factor KEM, 3-family signatures, triple AEAD) | pqc-migration-design.md |
| F-TRUST-001 | Audit checkpoint signing: move to offline SLH-DSA cosigner | pqc-migration-design.md §4 |
| F-E2E-001 | Device-directory trust: master identity key certification + transparency anchor | pqc-migration-design.md §2 |
| F-E2E-002 | Forward secrecy: epoch auto-rotation now; DM ratchet is Phase C decision | pqc-migration-design.md §6.5 |
| F-E2E-003 | Metadata: power-of-2 padding adopted; timing/graph exposure needs explicit policy | pqc-migration-design.md §6.6 |
| F-NET-001 | TLS pinning on native clients + CAA/CT monitoring | nation-state-supply-chain.md |
| F-TRUST-002 | Signed commits + CODEOWNERS | nation-state-supply-chain.md |
| Web code delivery | Browser trust layer (signed SRI, WebAuthn-prf vault, integrity manifest) | pqc-migration-design.md §6.6 |
| F-PQC-003 | Backup `age` X25519 is HNDL-exposed → PQ age plugin or offline symmetric escrow | pqc-migration-design.md §4 |

## Complete findings register

### Medium

| ID | Owner | Status | Finding | Detail |
|----|-------|--------|---------|--------|
| F-KEY-001 | server | Confirmed | Retired-epoch key deliveries unreachable — offline device permanently loses that epoch's ciphertext | server-keys.md |
| F-PERF-001 | client | Confirmed | Message store 3× full merge+sort per WS event — O(n²) bursts; repo test timed out | client-store-perf.md |
| F-COORD-002 | server | Candidate | No account-disablement — compromised sessions persist until per-session revoke/JWT expiry (≤7d) | coordinator-notes.md |
| F-KEY-002 | server | Candidate | Viewer gain doesn't rotate epoch — new members can be backfilled wraps for pre-join ciphertext | server-keys.md |
| F-STORE-001 | client | Candidate | `login()` missing generation guard — late login resurrects auth UI after logout | client-store-audit.md |
| F-STORE-002 | client | Candidate | Transient `loadChannels` error = revocation → wipes drafts + unsent outbox plaintext | client-store-audit.md |
| F-E2E-001 | crypto | Confirmed | No device-verification/transparency — compromised server injects rogue device → silent MITM | crypto-agility-future-threats.md |
| F-PQC-001 | crypto | Confirmed | HNDL: RSA-OAEP wraps stored indefinitely → post-CRQC retroactive decryption | crypto-agility-future-threats.md |
| F-E2E-003 | crypto | Confirmed | Metadata exposure: social graph/timing/sizes/voice participation visible | crypto-agility-future-threats.md |

### Low

| ID | Owner | Status | Finding | Detail |
|----|-------|--------|---------|--------|
| F-KEY-003 | server | Confirmed | `startFreshChannelKey` bypasses rotationRequired gate — rotation churn ≤5/hr, aborts others' epochs | server-keys.md |
| F-KEY-004 | server | Candidate | Epoch mutations under SHARE lock — send can commit under just-retired epoch (ordering anomaly) | server-keys.md |
| F-KEY-005 | server | Candidate | Accepted holders can inject alternative wraps; poisoned-wrap ack irrevocable (client-mitigated) | server-keys.md |
| F-KEY-007 | server | Candidate | Pending epoch wedges writes until all required recipients ack | server-keys.md |
| F-COORD-003 | server | Confirmed | `/health/ready` runs unauthenticated multi-subsystem checks per request | coordinator-notes.md |
| F-COORD-001 | infra | Confirmed | 4 moderate dep advisories (qs×2 via express, stream-json + decode-uri-component via minio) | dependency-vulns.md |
| F-STORE-003 | client | Candidate | Outbox `enqueue` bypasses ordering — concurrent flush permanently reorders messages | client-store-audit.md |
| F-STORE-004 | client | Candidate | `draft.clearChannel` doesn't invalidate queued writes — LWW can resurrect draft post-revocation | client-store-audit.md |
| F-STORE-005 | client | Candidate | `loadMoreMessages` cursor race vs `loadMessages` — stale cursor overwrites fresh page-1 | client-store-audit.md |
| F-STORE-008 | client | Candidate | Voice: dropped-offer glare — mutual joins both drop offers, no repair | client-store-audit.md |
| F-STORE-009 | client | Candidate | Voice: sequence tracker reset on rejoin allows old-signal replay (bounded) | client-store-audit.md |
| F-STORE-010 | client | Candidate | Voice: device-directory race drops new joiner's first signals | client-store-audit.md |
| F-STORE-011 | client | Candidate | `rejoinActiveChannel` gives up after 3 tries — channel stops receiving events | client-store-audit.md |
| F-STORE-012 | client | Confirmed | `ChatArea` `channel:join` emit has no ack timeout | client-store-audit.md |
| F-STORE-013 | client | Confirmed | Typing indicators never expire — lost `typing:stop` = permanent indicator | client-store-audit.md |
| F-STORE-014 | client | Candidate | `noteBaseMessage` counts own messages as unread | client-store-audit.md |
| F-STORE-015 | client | Confirmed | `loadMessages` clobbers aggregate `isLoading` during concurrent loads | client-store-audit.md |
| F-STORE-016 | client | Candidate | `cancelUpload` retains runtime against 16-slot cap — cancelled uploads block new ones | client-store-audit.md |
| F-STORE-017 | client | Candidate | LRU eviction can evict actively-viewed channel → empty/frozen view | client-store-audit.md |
| F-STORE-019 | client | Candidate | `decryptMessages` all-or-nothing batch churns under large backlogs | client-store-audit.md |
| F-PQC-002 | crypto | Confirmed | ECDSA P-256 signatures quantum-vulnerable post-CRQC | crypto-agility-future-threats.md |
| F-E2E-002 | crypto | Design | Epoch-level keys only — no per-message FS/PCS | crypto-agility-future-threats.md |
| F-PQC-003 | crypto | Low | `age` backup uses X25519 — HNDL-exposed (ciphertext+wraps only) | crypto-agility-future-threats.md |
| F-INPUT-001 | client+server | Confirmed | Display/name fields accept control+bidi+zero-width chars — visual spoofing (invite-gated) | display-name-unicode.md |
| F-NET-001 | infra | Confirmed | No TLS cert pinning (Android/desktop) — CA-coercion MITM under APT model | nation-state-supply-chain.md |
| F-SUPPLY-001 | infra | Low | No `minimumReleaseAge` — fresh malicious deps enter on lockfile refresh | nation-state-supply-chain.md |
| F-TRUST-001 | crypto+infra | Confirmed | Audit checkpoint signature = server-resident `AUDIT_INTEGRITY_KEY` — full compromise rewrites post-anchor history | nation-state-supply-chain.md |
| F-TRUST-002 | process | Confirmed | No signed commits/CODEOWNERS — trust roots in repo write access | nation-state-supply-chain.md |
| F-CONTAIN-001 | infra | Rec | Unused containment: egress allowlist, Node `--permission`, `--disallow-code-generation-from-strings` | nation-state-supply-chain.md |

### Informational

| ID | Owner | Finding |
|----|-------|---------|
| F-KEY-006 | server | Device-directory endpoints expose member device/ack state (enumeration oracle; needed for fanout) |
| F-MOBILE-001 | client | Android lacks `filterTouchesWhenObscured` (bounded: WebView UI, typed creds) |
| F-KEY-008 | server | Wraps to revoked devices retained until epoch end (unreachable; hygiene) |
| F-COORD-004 | infra | Single-process in-memory rate limits/socket state (documented constraint) |
| — | client | `coalesceValueLoads` caches resolved promises forever; dead code |

## PQC migration design (selected algorithms)

Internal team selected: ML-KEM-1024 + HQC-256 + FrodoKEM-1344-SHAKE (KEM) · Falcon-1024 + SLH-DSA-256 + QR-UOV-Cat5 (signatures) · XChaCha20-Poly1305 + AEGIS-256-256bit (AEAD).

**Read `pqc-migration-design.md` first.** Summary:

- **KEM**: 6-factor AND combiner (ML-KEM+HQC+Frodo+X25519+RSA-OAEP+optional workspace-PSK), SHAKE256, full transcript binding, fail-closed, staged distribution (~38KB/device)
- **Signatures**: AND-tiered — T1 ECDSA+Falcon+QR-UOV · T2 +key-confirmation round · T3 +SLH-DSA (audit/release)
- **AEAD**: nested triple AES-256-GCM ⊂ XChaCha20-Poly1305 ⊂ AEGIS-256(256bit) + per-message key-commitment + power-of-2 padding
- **Trust anchors externalized**: SLH-DSA offline audit cosigner (F-TRUST-001), master identity key certifies device bundles (F-E2E-001), offline backup escrow (F-PQC-003)
- **Browser trust layer**: signature-based SRI + Integrity-Policy + Trusted Types + pinned SW + WebAuthn-prf vault keys + full Permissions-Policy + wasm-unsafe-eval for PQC WASM
- **Open questions** in design doc §9 (QR-UOV impl source, AES 3rd layer, DM ratchet, transparency log, SLH-DSA ops)

## Verified-strong areas (hostile-review checklist — no findings)

- Zero-knowledge holds end-to-end: server stores RSA-OAEP wraps + SHA-256 commitments only
- Every signed artifact: versioned domain-separated canonical serializer; verified server-side before persistence AND client-side before decryption
- Sessions: HttpOnly+SameSite=Strict+(__Host- prod) cookies, HS256-pinned JWT w/ iss+aud, server-side tokenHash, per-session room disconnect on revoke
- CSRF: origin+Sec-Fetch-Site enforcement; WS handshake origin check; session revalidation per op
- Authorization: deny-first bitmask, workspace-locked mutations w/ SHA-256 revision OCC, private-channel membership even for owner, uniform 404s, composite FKs
- Audit: HMAC-chained rows + externally signed checkpoint, fail-closed, startup-verified
- Rate limiting everywhere: HTTP global+per-route+credential-keyed, WS per-event buckets, bounded maps, handshake caps
- Client: Symbol verification markers (JSON-unforgeable), envelope-equivocation detection, generation/epoch guards on every async path, synchronous revocation erasure of plaintext+persisted keys, encrypted local drafts/outbox
- Attachments: per-file key + prefix-counter nonces, exhaustive manifest/chunk validation, verify-before-decrypt, magic-byte gating, MOTW/quarantine on desktop saves, nonce+key rotation on expiry
- Desktop: sandbox+contextIsolation+no nodeIntegration, setContentProtection, origin-restricted protocol proxy, path-traversal-safe resolver, OS-vault secrets, IPC sender verification, full fuse hardening
- Android: FLAG_SECURE, Keystore vault, device-auth gate, local-asset WebView, all navigation blocked, zero backup domains, cleartext disabled, fail-closed SSL
- Infra: CI SHA-pinned + minimal perms, backups quiesced+verified, credentials never on argv/env (LoadCredential), atomic publish, restore refuses production-like names, systemd full Protect* suite
- Config: *_FILE secrets w/ mode checks, exact-origin CORS, strict ICE grammar, migration fingerprinting + single-bundle enforcement
- Supply chain: digest-pinned base images, `--frozen-lockfile --ignore-scripts`, runtime image has **no package manager**, SLSA provenance for Android, air-gapped release signing, CycloneDX SBOM

## Methodology

- Threat model: hostile members, hostile network observers, compromised accounts, malicious server-adjacent input; nation-state APT (CA coercion, supply-chain, TLS MITM); single-node deployment per RISK_REGISTER
- Coverage: every non-test production file read line-by-line (8 passes, ~36K lines) — server 69 ts + migrations + scripts · shared · client all tsx/ts/services/stores/hooks · desktop 6 ts + cjs · android 5 java + res + gradle + verification-metadata · build/release/backup/deploy/CI
- Subagents: ≤10 limit respected; key-management area via subagent report, all else direct review
- Verification logs: `audit.log`, `lint.log`, `oxlint.log`, `secretlint.log`, `test.log`, `typecheck.log` (audit dir root)
- Quus ledger: 58 events, chain-valid; artifacts are sha256 anchors of findings files (no bulk secrets stored)
- **No production source modified**

## Detail files

| File | Contents |
|------|----------|
| server-keys.md | F-KEY-001..008 — channel key epoch lifecycle, evidence trace in evidence-f-key-001-trace.md |
| client-store-audit.md | F-STORE-001..019 — store/hook races, auth lifecycle, voice glare |
| client-store-perf.md | F-PERF-001 — message store O(n²) merge |
| coordinator-notes.md | F-COORD-001..004 + pass-by-pass review log (all 8 passes) |
| crypto-agility-future-threats.md | F-E2E-*, F-PQC-* — HNDL, forward secrecy, metadata, algorithm inventory |
| nation-state-supply-chain.md | F-NET/F-SUPPLY/F-TRUST/F-CONTAIN/F-MOBILE — APT assessment |
| dependency-vulns.md | F-DEP-001..003 (= F-COORD-001) — advisory details + reachability + remediation |
| display-name-unicode.md | F-INPUT-001 — Unicode/bidi spoofing evidence |
| crypto-hardening-roadmap.md | Prior PQC roadmap (superseded by pqc-migration-design.md) |
| pqc-migration-design.md | selected-algorithm hybrid design + browser trust layer |
| server-keys.md trace | evidence-f-key-001-trace.md |
