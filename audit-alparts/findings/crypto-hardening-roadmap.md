# Cryptographic Hardening Roadmap — Hybrid PQC & Extreme-Threat Defenses

Advisory for Alparts keyed to the stated threat model: top-secret data, highly capable
adversaries, continuous monitoring. Complements `crypto-agility-future-threats.md`
(F-PQC-*, F-E2E-* findings) with concrete construction details and a prioritized roadmap.

## 1. Hybrid PQC — answering "should PQC be composite/hybrid?"

Yes — and specifically **classical AND one-or-more PQ algorithms, combined so that either
algorithm alone suffices** (OR-security). Reasons this matters for Alparts:

- ML-KEM is ~1 decade of cryptanalysis vs ~4 decades for RSA/ECC. Precedent for parameter-level
  failure exists (SIKE broken in 2022; KyberSlash timing attacks on implementations in 2024).
- BSI (Germany) and ANSSI (France) currently *require* hybrid for high-assurance use; NCSC UK
  recommends hybrid KEMs; CNSA 2.0 permits pure-PQC only with its approved parameter sets.
- Hybrid = free insurance: if ML-KEM falls, RSA-3072 still protects; if RSA falls to a CRQC,
  ML-KEM still protects. Only breaking *both* compromises the key.

### Recommended wrap construction (extends — never replaces — RSA-OAEP-3072)

**Retention rule**: every algorithm in production stays. AES-256-GCM, SHA-256/HMAC, bcrypt,
HS256-JWT, RSA-OAEP-3072, ECDSA P-256 all remain mandatory components. Hybrid means
*additive*: the PQ half is added alongside the classical half, and both must hold for
security (OR-security — either primitive alone protects the key). The classical half is
load-bearing forever during transition; removing it is what creates the downgrade hole.

```
wrap_material = HKDF-SHA-512(
    salt = epoch_id || channel_id || recipient_device_id,          # context binding
    ikm  = rsa_oaep_shared_secret || mlkem_shared_secret,
    info = "alparts:wrap:v3" || rsa_ct_hash || mlkem_ct_hash       # transcript binding
)
channel_key_wrapped = AES-256-GCM(wrap_material, channel_key, aad = full manifest)
```

Critical properties:
- **Transcript binding**: both ciphertexts hashed into `info` — prevents an attacker from
  stripping the PQ half (downgrade) or swapping ciphertexts between wraps.
- **Both halves required**: no "classical-only" mode must be negotiable. The epoch's
  `protocol_version` (v3) must commit the algorithm suite; the signed epoch metadata must
  include the suite identifier so a malicious server cannot trick clients into v1/v2 wraps.
- Algorithm suite registry: `SUITE_V3 = RSA-OAEP-3072 + ML-KEM-1024` — RSA-3072 is kept as a
  required half (its ~128-bit classical security is unchanged; a CRQC breaks it but ML-KEM
  still holds). For a paranoid tier, `SUITE_V3P = RSA-OAEP-3072 + ML-KEM-1024 + HQC-256` —
  HQC is code-based (different mathematical family than lattices), hedging a catastrophic
  lattice break. Wrap cost rises (~KB per device per epoch) but wraps are rare events.
- Do NOT drop RSA-OAEP for a pure-PQ wrap: pure-PQ is what the hybrid design exists to
  avoid. If ML-KEM is later broken, RSA-3072 is the surviving protection; vice versa.
- Avoid Classic McEliece for per-device wraps: public keys are ~0.2–1 MB, fetched per device —
  bandwidth/storage blowup for marginal diversity gain over HQC.

### Signature transition (F-PQC-002)

- **Dual-sign every envelope**: ECDSA-P-256 *retained* + ML-DSA-65 *added*; verification
  requires BOTH to pass. ECDSA stays load-bearing — if a PQ implementation or parameter is
  later broken, classical signatures still authenticate. Serializer already versions
  envelopes — add a signature-array field rather than swapping the algorithm.
- **Audit-checkpoint and offline anchors → SLH-DSA-SHA2-256s**: hash-based, most conservative
  assumptions (only needs hash preimage/collision resistance), acceptable size/speed for
  low-frequency signing. This makes the long-term integrity anchor the strongest piece.
- Device identity keys become pairs {ECDSA, ML-DSA}; device directory carries both.

### Implementation maturity caveats (do not skip)

- **Decapsulation side-channels**: a malicious server is *inside* the threat model (F-E2E-001)
  and can feed crafted wrap ciphertexts to clients → decapsulation-oracle / timing attacks
  (KyberSlash class). Requirements for the client impl:
  - Verified constant-time, CCA-correct FO-transform implementation (implicit rejection must
    actually run; re-encryption comparison must be constant-time).
  - Prefer WASM builds of audited libraries (liboqs) or @noble/post-quantum — plain-JS
    bigint code is hard to keep constant-time.
  - Keep the classical RSA half as the outer wrap so a PQ-implementation bug alone cannot
    leak the channel key.
- **Browser reality**: WebCrypto does not broadly expose ML-KEM yet. Node 24 (server) already
  supports ML-KEM/ML-DSA/SLH-DSA via OpenSSL 3.5 — the audit-checkpoint signature is a viable
  *server-side first* PQ deployment. Client interim: audited WASM, or gate hybrid unwrap to
  desktop/Android clients first, web when WebCrypto lands.
- **Size budget**: ML-KEM-1024 pk 1568B / ct 1568B; ML-DSA-65 sig ~3.3KB; dual-signature
  envelopes grow ~4KB — fine for messages, review the 32KB SDP cap and attachment manifests.
- Keep the versioned-serializer discipline: every new field must be inside the signed region
  (the codebase already does this correctly — preserve the pattern).

### Migration sequencing (uses the existing `protocol_version` seam)

1. v3 epoch = hybrid wrap + dual signatures, `rotationRequired` semantics unchanged.
2. All *new* epochs are v3. Old epochs stay readable (v1/v2 wrap fetch path preserved).
3. Forced re-wrap sweep: rotate every active channel to v3 over a defined window;
   retroactive HNDL exposure then only covers ciphertext under v1/v2 epochs — acceptable
   documented residue, or expire those epochs by policy.
4. TLS: require hybrid key exchange (X25519MLKEM768) at the reverse proxy — protects wrap
   transit immediately, before the app-layer migration lands.

## 2. Deeper hardening for extreme threat levels

Ordered by leverage for this codebase.

### A. Key transparency / device authenticity (fixes F-E2E-001 — highest priority)

1. **Append-only device-key transparency log** (server-side): Merkle-tree log over
   (user_id, device_id, identity_keys, registered_at). Server publishes signed tree heads;
   clients verify inclusion proofs and gossip tree heads to detect split-views. The existing
   HMAC-chained audit log + signed checkpoints is the right substrate to extend.
2. **Cross-device approval**: new device becomes *visible-but-unprovisioned* until an existing
   device signs an approval statement (carries the new device's public keys). Channel key
   distribution refuses unapproved devices. Converts server MITM into a visible event.
3. **Safety numbers**: per-user aggregate fingerprint = hash of sorted device-key set, shown
   in member profile for out-of-band comparison (QR/verbal). Cheap, high value.

### B. Forward secrecy & post-compromise security (extends F-E2E-002)

1. **Hash-ratchet on channel keys** (cheap, big win): within an epoch, derive per-period keys
   `k_{t} = SHA-256(k_{t-1} || domain)`; clients delete `k_{t-1}` after advancing. Compromise
   of current key material cannot decrypt earlier periods. Works with existing wrap
   distribution (no per-message key exchange needed in group chat).
2. **Time-based epoch rotation cadence** in addition to membership-change rotation
   (e.g., rotate on 30d even without membership events) — bounds passive collection windows.
3. **Pre-key bundles / asynchronous onboarding** (Sender-Keys or one-time-prekey pattern):
   fixes F-KEY-001 availability *and* removes the "online window" attack surface.
4. Consider double-ratchet only for 1:1 DMs if maximal secrecy is required — disproportionate
   complexity for group channels; hash-ratchet + epochs is the right group design.

### C. Metadata resistance (F-E2E-003 — the hardest, be honest about limits)

Cheap wins:
1. **Size bucketing**: pad ciphertexts to bucket boundaries (e.g., next power of two or fixed
   4KB/16KB/64KB classes) before encryption — removes fine-grained length channel.
   Attachments already chunked; pad the *manifest* so chunk count doesn't leak exact size.
2. **Batching + jitter** on WS event fan-out timing where tolerable.
3. **Cover traffic toggle** for high-sensitivity channels (constant-rate keepalive events).

Hard floor (document as accepted or mitigated elsewhere):
- Server necessarily sees social graph, presence, device inventory. Mitigations are
  architectural: private deployment, Tor/i2p transport guidance for clients, per-workspace
  pseudonymous identifiers (display names are already client-side renderable — user table
  stores email+displayName plaintext; consider encrypting display_name with a workspace key
  or profile key at the cost of server-side search).
- Full mix-net anonymity is out of scope; say so explicitly in the threat model.

### D. Compromise detection & response (an adversary *will* get in eventually)

1. **Anomaly detection on the audit chain itself**: alert rules for wrap-fetch bursts,
   epoch-churn (F-KEY-003-style abuse), mass device registration, first-seen device
   fingerprints per user, unusual attachment volume. Cheap — the audit log already has the data.
2. **Two-person integrity for catastrophic ops**: workspace ownership transfer, mass member
   removal, audit-checkpoint re-provisioning, invitation-secret rotation → require a second
   administrator's signed approval (the signed-envelope infra is reusable).
3. **Account disablement** (F-COORD-002) is a prerequisite for incident response — implement
   with `disabled_at` + session sweep + socket disconnect.
4. **Key ceremony + HSM/KMS for server secrets**: JWT secret and AUDIT_INTEGRITY_KEY currently
   live as Docker-secret files. Move signing keys (checkpoint signer especially) into a TPM,
   YubiHSM, or cloud KMS so file-level access ≠ forgery capability. Document a ceremony for
   generation/rotation/destruction.
5. **Remote wipe + lockout**: revocation already erases client plaintext scope; add a
   device-initiated "report lost" flow that propagates `revoked` + triggers remote local-state
   wipe on next contact, plus an idle auto-lock timer (desktop unlock flow already exists).

### E. Runtime & supply chain (mostly already strong — fill the gaps)

Already done: SHA-pinned CI actions, minimal GITHUB_TOKEN perms, SBOM (CycloneDX via anchore),
Android build-provenance attestation, secretlint, disposable CI credentials, lockfile,
hardened container (read-only, cap_drop ALL, no-new-privileges, noexec tmpfs).

Gaps worth adding:
1. **Dependency minimum-release-age** (pnpm supports `minimumReleaseAge`) + dependency-review
   gate on lockfile changes; the 4 moderate advisories show the value of a standing policy.
2. **Release signing**: cosign/signstore on container image + desktop/mobile artifacts,
   verified in deploy docs; extend provenance attestation to server image (Android has it).
3. **Reproducible build** for desktop/mobile binaries so third parties can verify the
   distributed artifact equals source.
4. **DB least-privilege split**: separate roles for migrations (DDL) vs runtime (DML only) —
   currently not separated; runtime creds shouldn't be able to ALTER TABLE.
5. **MinIO bucket policy**: deny public access explicitly, enable object-lock/WORM for the
   attachment bucket if storage cost allows, SSE for defense-in-depth.
6. **Egress filtering** on the app container (it should only reach DB/MinIO/DNS) — a
   compromised process then can't exfiltrate to arbitrary hosts.

### F. Verification engineering for the crypto layer

1. **Wycheproof-style vectors** + property tests for every serializer/verifier; mutation tests
   asserting "flip any envelope byte → verification fails" (domain-separation coverage).
2. **TLA+ (or equivalent) model of the key-epoch state machine** — two-phase propose/commit/
   abort with required-recipient sets is exactly the class of protocol where model checking
   finds wedges (F-KEY-004/F-KEY-007 smell like reachable edge states).
3. **Negative-path fuzzing** on all `parse*` functions (they're strict — fuzz them anyway) and
   on the wrap/ack/decrypt paths via crafted ciphertexts.
4. **Timing-harness CI** for the PQ decapsulation path once it exists.

### G. Data-at-rest & memory (residual JS limitations)

- Private keys are already non-extractable CryptoKeys / OS-vault / Keystore-backed. Good.
- JS strings can't be zeroized — plaintext message strings persist until GC. Accept + document;
  where feasible, keep plaintext in `Uint8Array` (already done for attachment chunks) and
  consider a WASM scratch arena for high-value plaintext paths.
- Server: encrypt the DB volume (LUKS/managed-disk encryption) and enable TLS to Postgres +
  MinIO (config already supports `DB_SSL`/`MINIO_USE_SSL` — require them in prod profile).

## 3. Symmetric-layer assessment (AES-256-GCM vs ChaCha20/Serpent/Twofish)

### Quantum status of symmetric ciphers

Grover gives a quadratic — not exponential — speedup: an n-bit key needs ~2^(n/2) sequential
quantum operations, and Grover parallelizes poorly (p quantum processors yield only √p
speedup). All 256-bit-key ciphers land at ~128-bit post-quantum security:

| Cipher | Key | Post-Grover | Verdict for Alparts |
|--------|-----|-------------|---------------------|
| AES-256-GCM | 256 | ~128-bit | Keep — current choice, correct |
| ChaCha20-Poly1305 | 256 | ~128-bit | Viable secondary (see below) |
| Serpent-256 | 256 | ~128-bit | Not recommended (see below) |
| Twofish-256 | 256 | ~128-bit | Not recommended |

Grover is a *generic* attack — switching ciphers does not change the ~128-bit outcome.
The choice is therefore about classical margins and implementation risk, not quantum.

### ChaCha20-Poly1305 — legitimate alternative, ecosystem-blocked

- Advantages: constant-time in pure software (AES needs AES-NI/ARM CE to be safe);
  XChaCha20's 192-bit nonce makes random nonces safe at any scale — eliminates the
  nonce-management burden GCM carries (random 96-bit nonces become risky beyond ~2^32
  messages; Alparts is far below that, and chunks use deterministic prefix+counter).
- Blocker: **Web Crypto has no ChaCha20-Poly1305**. Browser clients would need WASM
  (libsodium.js) — pulling the AEAD core out of the browser's audited primitive is a real
  trade: non-extractable-key guarantees and constant-time discipline both weaken in WASM.
- Verdict: keep AES-256-GCM for web; XChaCha20-Poly1305 is a reasonable secondary on
  Electron (Node crypto) and Android (Conscrypt) if cipher diversity is wanted.

### Serpent / Twofish — sound math, wrong trade

- AES finalists (1998-2000). Serpent has the largest security margin ever standardized in
  spirit (32 rounds); 25 years unbroken. Twofish likewise unbroken.
- Why not deploy: no WebCrypto/OpenSSL path, no hardware acceleration, no standardized AEAD
  mode (would require a non-standard GCM adaptation — the composition risk exceeds the
  diversity benefit), Serpent ~3× slower in software, Twofish's key-dependent S-boxes raise
  side-channel surface. And the scrutiny argument cuts both ways: AES's record is strong
  *because* everyone attacks it; Serpent's "unbroken" partly means fewer eyes.
- If the goal is hedging a surprise AES break, the correct construction is **dual
  encryption** — AES-256-GCM(inner) then ChaCha20-Poly1305(outer) with independent keys —
  giving OR-security identical in spirit to the hybrid PQC wrap. Not a cipher swap.

### Higher-value symmetric-layer hardening than cipher choice

1. **Key-committing AEAD**: AES-GCM is non-committing (a ciphertext can verify under more
   than one key). Alparts mitigates via manifest binding + signatures, but adding a 32-byte
   key-commitment tag (`HKDF(key, "commit")` in the AAD/manifest) closes the class cheaply.
   Relevant scenario: substituted attachment chunk + attacker-influenced key derivation.
2. **AES-GCM-SIV** where available: nonce-misuse *resistant* (leaks equality, not the key).
   WebCrypto lacks it; same WASM caveat as ChaCha.
3. Keep the existing nonce discipline — it's already correct (random per message;
   deterministic prefix+counter per chunk; key+nonce rotation on reservation expiry).
4. Hash layer: SHA-256 → ~128-bit post-Grover preimage resistance, adequate. SHA-384/SHA-3
   diversity is optional polish, not a gap.

## 4. Priority order (impact × feasibility)

| Priority | Item | Effort | Fixes |
|----------|------|--------|-------|
| P0 | Key transparency + cross-device approval + safety numbers | Medium | F-E2E-001 |
| P0 | Account disablement (prereq for incident response) | Small | F-COORD-002 |
| P1 | Hybrid wrap suite v3 (RSA-OAEP+ML-KEM-1024, HKDF combiner w/ transcript binding) | Medium | F-PQC-001 |
| P1 | Hybrid TLS at proxy (X25519MLKEM768) | Small | F-PQC-001 transit leg |
| P1 | Hash-ratchet on epoch keys + wrap-retention pruning | Medium | F-E2E-002, F-PQC-001 |
| P2 | Dual signatures (P-256+ML-DSA-65); SLH-DSA for checkpoints | Medium | F-PQC-002 |
| P2 | Audit-chain anomaly detection + two-person ops | Small-Med | detection/insider |
| P2 | Server secrets → HSM/TPM; DB role split; egress filter | Small-Med | persistence/blast radius |
| P3 | Metadata padding/bucketing; PQ-hybrid `age` when stable | Medium | F-E2E-003, F-PQC-003 |
| P3 | TLA+ epoch model; crypto mutation/fuzz suite | Medium | F-KEY-004/007 class |
