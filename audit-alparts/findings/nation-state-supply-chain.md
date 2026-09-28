# Nation-State Adversary & Supply-Chain Compromise Assessment

Passive source-level audit pass targeting APT-class techniques and supply-chain
compromise blast-radius minimization. Findings separated from verified-strong
controls. Alparts production source unchanged.

## New findings

### F-NET-001 — No TLS certificate pinning on native clients (Medium, nation-state model; Low otherwise)
- **Status**: confirmed-by-design (absence verified)
- **Locations**: `packages/android/app/src/main/AndroidManifest.xml` (no
  `networkSecurityConfig`, no `pin-set`); `packages/desktop/src/` (no
  `session.setCertificateVerifyProc`, no `certificate-error` handler → Electron
  default fails closed, but no pinning)
- **Description**: Both native clients rely solely on the public Web PKI. A
  nation-state attacker able to coerce or compromise a trusted CA (DigiNotar
  class; state-compelled issuance has been attempted in practice) can MITM the
  TLS transport. E2EE ciphertext content remains protected, but the attacker
  gains: (a) plaintext metadata — connection timing, volume, endpoint identity;
  (b) connection manipulation — selective drop/delay/censor of channels and
  key-delivery traffic (epoch starvation, message suppression that looks like
  network failure); (c) for the **web** client only, delivery of modified
  application code on next load — the classic browser-E2EE integrity weakness
  (Android/desktop load bundled/local assets and are immune to that part).
- **Not exploitable for**: silent content decryption — device keys and channel
  keys never transit the TLS layer in plaintext; signature verification on all
  envelopes fails closed.
- **Remediation**: Android `networkSecurityConfig` with SPKI `pin-set` (+ backup
  pin + documented rotation); Electron `setCertificateVerifyProc` with pinned
  SPKI set; optionally Android CT enforcement (`<certificates
  requireCT="true">`-style trust config). Pinning is an operational commitment —
  pin-loss is self-DoS; rotate via app release cadence.

### F-SUPPLY-001 — No dependency age gate (`minimumReleaseAge`) (Low)
- **Status**: confirmed-absent
- **Location**: `pnpm-workspace.yaml` (has `allowBuilds` but no
  `minimumReleaseAge`); no `.npmrc` in repo.
- **Description**: Lockfile updates and `pnpm add/update` can install dependency
  versions published minutes earlier — the window in which a significant share
  of supply-chain attacks are caught and yanked. The runtime/prod path is well
  defended (frozen lockfile, `--ignore-scripts`, `allowBuilds` allowlist,
  digest-pinned base images), so exposure is limited to the dev/CI install path
  whenever the lockfile is refreshed.
- **Remediation**: `minimumReleaseAge: 10080` (7 days) in pnpm-workspace.yaml;
  keep the existing allowBuilds list.

### F-MOBILE-001 — No tapjacking protection on Android (Informational)
- **Status**: informational hardening note
- **Location**: `MainActivity` — no `android:filterTouchesWhenObscured` /
  `setFilterTouchesWhenObscured`.
- **Description**: A malicious overlay-capable app could trick taps on sensitive
  surfaces (password entry, device management). Impact is bounded because the UI
  is WebView-based and credentials are still typed, not single-tap actions; but
  the flag is free hardening.
- **Remediation**: `filterTouchesWhenObscured="true"` on the activity root.

## Verified-strong — nation-state-relevant controls already present

Transport & network:
- `perMessageDeflate: false` — no WS compression side-channel (CRIME-class
  oracle impossible on the socket).
- `trust proxy` defaults to `false`; explicit allowlist required →
  X-Forwarded-For spoofing cannot bypass IP rate limits.
- `BIND_HOST=127.0.0.1` default in runtime image — cannot accidentally expose
  the app to the network without an explicit front proxy.
- DB: TLS with `rejectUnauthorized: true`, bounded pool, `statement_timeout`.
- Android: `usesCleartextTraffic=false`; no `onReceivedSslError` override →
  cert errors fail closed. Desktop likewise (no `certificate-error` suppressor).

Supply-chain minimization (blast radius):
- Root Dockerfile: base image pinned by sha256 digest; prod install uses
  `--frozen-lockfile --ignore-scripts`; runtime image has **all package-manager
  binaries deleted** (npm/npx/corepack/pnpm/yarn) → a running container cannot
  fetch new code; `apk` remains but `USER node` blocks `apk add`.
- pnpm `allowBuilds`: only `esbuild` may run build scripts;
  `electron-winstaller` explicitly denied — postinstall RCE surface is
  allowlisted.
- compose: postgres/minio/mc pinned by digest; production compose fails closed
  on unset `ALPARTS_IMAGE_TAG` (immutable identifier required).
- All GitHub Actions `uses:` pinned to full 40-char SHAs; no
  `pull_request_target`; no attacker-controlled context in `run:` steps.
- Release integrity: `release:prepare` produces unsigned manifest+SBOM and
  defers to an **offline/air-gapped signer**; Android CI emits SLSA provenance
  via `actions/attest-build-provenance` (SHA-pinned).
- Separate runtime vs migration DB credentials (`database_url` /
  `migration_database_url` secrets) — DDL rights not held by the serving role.

Endpoint / device resistance:
- Android: `allowBackup=false` + `data_extraction_rules` excludes **all** domains
  from cloud backup AND device transfer → keys cannot migrate off-device;
  `FLAG_SECURE`; Keystore-backed vault; no notification content surface
  (no notification code present at all).
- Desktop: `setContentProtection`, sandbox+contextIsolation+no nodeIntegration,
  `navigateOnDragDrop=false`, devTools only when unpackaged, `safeStorage` with
  backend check (rejects linux `basic_text`), custom-scheme CSP per response.
- No telemetry/analytics of any kind (zero Sentry/PostHog/etc.) — no third-party
  data egress path to compromise or subpoena.

Process / resilience:
- `MAX_ACTIVE_SESSIONS_PER_USER = 16` with invariant enforcement.
- No user-controlled `RegExp` construction (no ReDoS surface found).
- No user-controlled values in structured logs (no log-injection path found).
- bcrypt bounded worker pool — CPU-exhaustion DoS resisted at the admission gate.

## Residual exposure under a nation-state model (honest assessment)

Controls that cannot exist in this architecture or remain open:
1. **Web client code delivery** — browsers cannot pin; a TLS-MITM or a
   compromised server serves backdoored JS. Mitigated only by preferring the
   bundled desktop/Android clients for high-threat users. Inherent to all
   browser-delivered E2EE.
2. **Metadata** — F-E2E-003 stands: social graph, timing, sizes visible to
   server/network observers. No padding/mix layer exists.
3. **HNDL** — F-PQC-001 stands: recorded RSA-OAEP wraps + ciphertext are
   post-quantum decryptable.
4. **Server compromise persistence** — JWT secret + audit key are file/env
   secrets (documented in crypto-hardening-roadmap §2 P2); HSM/KMS not in code.
5. **Endpoint malware** — FLAG_SECURE/content-protection stop capture APIs, not
   compromised OS/hardware. Out of scope by design; non-extractable CryptoKey
   and Keystore/safeStorage raise the bar appropriately.
6. **Multi-instance deployment** — rate limits and room state are
   process-local (already noted in coordinator-notes); a second process sharing
   the DB would silently weaken them. Startup assertion recommended, not found.

## Blast-radius containment — future dependency RCE

Verified containment already in place (compose.production.yml + Dockerfile):
- read_only root filesystem; only writable space is tmpfs /tmp mounted
  noexec,nosuid,nodev (64MB) + the audit-checkpoint volume.
- cap_drop ALL + no-new-privileges → no raw sockets, no ptrace, no setuid
  escalation paths.
- pids_limit 256, mem/cpu limits, init reaping → fork/DoS contained.
- USER node; npm/pnpm/yarn/corepack binaries physically deleted from the
  runtime image → a compromised process cannot fetch or build new code.
- Zero legitimate internet egress paths in app code (no telemetry, no external
  API calls) → any outbound traffic is inherently anomalous.
- E2EE architecture: a fully RCE'd server still never holds channel keys or
  plaintext — content confidentiality survives server compromise by design.
- Audit chain is HMAC-chained + externally signed checkpoint (offline key) →
  DB tampering is detectable even under full app compromise.
- Separate migration credential → runtime role holds no DDL rights.
- ajv/ejs/lodash confirmed dev-only (secretlint/electron-builder chains) →
  no codegen dependency ships in the production image.

### F-CONTAIN-001 — Remaining containment levers not yet used (Recommendation)
1. **Egress allowlist (largest remaining gap)**: the app service has no
   network restriction beyond the loopback port publish; its only legitimate
   egress is DB + MinIO endpoints. A host firewall or egress-proxy allowlist
   to exactly those endpoints converts a dependency RCE into "runs but cannot
   exfiltrate or C2". Feasible precisely because no other egress exists.
2. **Node --permission model** (Node 24): server never uses child_process →
   `--permission` with explicit `--allow-fs-read=<app>`, `--allow-fs-write=
   <audit dir>`, and no child-process grant removes the spawn-reverse-shell
   primitive inside the container. Verify `--allow-worker` remains for the
   bcrypt worker pool.
3. **`--disallow-code-generation-from-strings`**: no prod dep uses
   eval/new Function (ajv/ejs/lodash are dev-only) → free removal of the
   whole string-codegen exploitation primitive class.
4. Custom seccomp profile tightening beyond Docker default (diminishing
   returns, optional).
5. gVisor/Kata runtime for kernel-boundary isolation (infra-level option).
6. Runtime anomaly detection (Falco/eBPF or audit-chain anomaly rules) —
   roadmap P2; currently detection relies on the integrity chain alone.
7. Incident-response note: SBOM + weekly dependabot + offline signer give fast
   exposure assessment, but an emergency patch release is gated on the offline
   signer's availability — document an emergency-signing runbook/SLA.

## Complete chain of trust — anchor-to-edge analysis

Trust anchors and the weakest link in each segment:

| Segment | Anchor | State |
|---|---|---|
| Source | Repo write access only — commits unsigned, no CODEOWNERS | GAP (F-TRUST-002) |
| Dependencies | Lockfile + allowBuilds + digest pins | Strong; F-SUPPLY-001 age gate |
| Build | SHA-pinned actions, no pull_request_target, SLSA provenance | Strong |
| Release | Unsigned manifest+SBOM -> offline signer | Strong; needs emergency-signing runbook |
| Deploy | Immutable image tag enforced; infra images digest-pinned | Strong |
| Boot | Startup schema fingerprint + migration journal + audit-checkpoint verification; fail-closed | Strong |
| Secrets | *_FILE docker secrets, non-root, read-only FS | Strong; HSM/KMS pending (roadmap P2) |
| Transport | TLS + exact-origin CORS; WS origin+session checks | F-NET-001: no pinning |
| Client code | Desktop/Android bundled; **web = TLS-delivered** | Weakest link (F-NET-001) |
| Device identity | PoP + step-up; server-mediated directory, no transparency | F-E2E-001 (primary gap) |
| Message authenticity | ECDSA envelopes, canonical serialization, verify-on-write+read | Strong |
| Storage | Manifest-bound signatures; MinIO bounded client | Strong |
| Audit | HMAC chain + checkpoint — **same server-resident key** | F-TRUST-001 (see below) |
| Session | JWT pinned + DB tokenHash + expiry disconnect | Strong; forgeable under server compromise (sessions only, never E2EE content) |
| Local state | Encrypted IndexedDB; Keystore/safeStorage vaults | Strong |
| Backup | age-encrypted + verified restore; production-name refusal | Strong |

### F-TRUST-001 — Audit checkpoint signature shares the server-resident chain key (Medium, APT model)
- **Status**: confirmed-by-design
- **Location**: `middleware/audit.ts` — `computeHash` (row chain) and
  `checkpointSignature` both use `config.audit.integrityKey`
  (AUDIT_INTEGRITY_KEY_FILE — a docker secret held by the server process).
- **Description**: The checkpoint file is "external" only in the filesystem
  sense (separate volume on the same host). Its HMAC signature proves
  "produced by a holder of the key" — and the server holds the key. Under full
  server compromise an attacker can (a) rewrite audit rows, (b) recompute the
  chain, and (c) mint a validly-signed checkpoint for the forged history.
  Residual guarantee: rewriting any row *before* an externally-archived
  checkpoint breaks that anchor — so tamper-evidence survives only relative to
  checkpoints the operator has already copied off-host. History after the last
  archived anchor is fully forgeable.
- **Remediation**: (a) external cosigner — server submits log-hash to an
  HSM/KMS/offline signer that signs checkpoints (server compromise then cannot
  mint signatures); (b) periodic checkpoint export to WORM storage (S3 Object
  Lock) or append-only remote log; (c) document the archival cadence as a
  required operational control — without it the guarantee is weakest-link only.

### F-TRUST-002 — Trust anchor starts at unsigned commits (Low-Med, process)
- **Status**: confirmed-absent (process level)
- **Description**: No signed commits, no CODEOWNERS file. The entire chain
  roots in repository write access + CI review discipline. A compromised
  maintainer account could land a single-commit backdoor.
- **Remediation**: require signed commits (SSH/GPG sigs), CODEOWNERS gating
  security-critical paths (crypto.service, security/, audit.ts, Dockerfile,
  workflows), branch protection with 2-person review on those paths.

## Chain verdict

The trust chain is well-formed and each segment is internally consistent, with
three deliberate weak links — device-directory transparency (F-E2E-001), client
code delivery for web (F-NET-001), and audit-signing residency (F-TRUST-001).
All three are *key-placement* problems, not implementation bugs: the fix in
each case is moving a trust anchor outside the server's compromise boundary.
