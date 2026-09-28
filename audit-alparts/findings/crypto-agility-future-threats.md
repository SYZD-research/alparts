# Cryptographic Agility / Post-Quantum / Future-Threat Assessment

Assessment of Alparts' cryptographic posture against future threats (post-quantum,
harvest-now-decrypt-later, crypto-agility, protocol evolution) and E2EE design limits.

## Algorithm inventory

| Use | Algorithm | Quantum status | Notes |
|-----|-----------|----------------|-------|
| Message/attachment content | AES-256-GCM | Grover-resistant (~128-bit effective) | Random nonce per message; chunk nonce = prefix+counter |
| Channel-key wrap | RSA-OAEP-256 (RSA-4096/2048?) | **Shor-vulnerable** | Per-device wraps stored server-side |
| Signatures (message/attachment/voice/audit-checkpoint) | ECDSA P-256 (ES256) | **Shor-vulnerable** | Domain-separated canonical serializers |
| Session token | JWT HS256 | Grover-resistant | iss+aud pinned, server-side tokenHash |
| Password hash | bcrypt | Not quantum-sensitive | 72-byte cap explicit |
| Integrity/MAC | SHA-256, HMAC-SHA-256, AES-GCM tags | Grover-resistant | |
| Voice transport | WebRTC DTLS-SRTP | Classical (no PQC in browsers) | SDP fingerprint signed inside envelope |
| Backup encryption | `age` (X25519+ChaCha20-Poly1305) | X25519 is Shor-vulnerable | Recipient-encrypted, never plaintext |
| Transport | TLS via reverse proxy (deployment-dependent) | Deployment-dependent | compose.production documents proxy-terminated TLS |

## Findings

### F-PQC-001 — Harvest-now-decrypt-later exposure on channel-key wraps (Medium, confirmed design gap)
- RSA-OAEP-256 wraps for every channel-key epoch are stored server-side indefinitely and
  transit the wire. An adversary recording ciphertext + wraps today can unwrap all epoch keys
  once a cryptographically-relevant quantum computer exists → full retroactive decryption of
  every message/attachment that device was provisioned for.
- AES-256-GCM content itself is fine (256-bit symmetric ≈ 128-bit post-Grover); the weak link
  is exclusively the RSA wrap.
- `channel_key_epochs.protocol_version` exists (v1→v2 migration precedent) — there is a
  versioned hook to introduce a hybrid or PQ wrap without schema redesign.
- Remediation paths:
  1. Hybrid wrap: RSA-OAEP + ML-KEM-768 (or X25519+ML-KEM-768 for future ECDH-style wraps).
     Both must be broken to recover the key. Web Crypto lacks ML-KEM today → WASM/native
     implementation needed for web; Electron/Android can ship native libs sooner.
  2. Short-term partial mitigation: epoch wrap retention policies (delete retired-epoch
     deliveries once acked) reduce the recorded-wrap window — interacts with F-KEY-001.
  3. Track CFRG/NIST hybrid guidance; require TLS hybrid key exchange at the reverse proxy
     (e.g., X25519+ML-KEM-768 in nginx/openssl 3.5+) to protect wrap transit at least.

### F-PQC-002 — ECDSA P-256 signatures quantum-vulnerable (Low-Medium, confirmed)
- Forgery becomes possible post-CRQC: forged message envelopes, attachment manifests,
  voice signaling, audit checkpoints. Lower urgency than F-PQC-001 (signatures are about
  future authenticity, not retroactive confidentiality), but protocol_version migration
  path should plan a hybrid signature (e.g., P-256+ML-DSA or dual-signature envelope).

### F-E2E-001 — No device-verification ceremony / key transparency (Medium-High, confirmed gap)
- The device directory is fully server-mediated: clients fetch member device lists and wrap
  channel keys to whatever the server returns. There is **no** fingerprint comparison,
  safety-number, cross-signing, or transparency log (`grep` confirms no such UI/mechanism).
- Consequence: a compromised/malicious server (or DB write access) can inject a rogue device
  for a target user; other members' clients will wrap the channel key to it → silent MITM on
  all future ciphertext. Password step-up at enrollment protects the *stolen-session* path
  only; it does not protect the directory from the server itself.
- This is the canonical residual risk of server-mediated E2EE without key transparency
  (cf. Signal's safety numbers, WhatsApp key transparency, Matrix cross-signing).
- Remediation: (a) user-visible device list with out-of-band fingerprint comparison of device
  identity keys; (b) cross-device approval for new devices (existing device signs the new
  device's key); (c) server append-only device-key transparency log with client-side
  consistency proofs. Minimum viable: (a)+(b).

### F-E2E-002 — Epoch-level keys only; no per-message forward secrecy / PCS (Low-Medium, design note)
- Channel keys rotate per membership-change epoch, not per message. Compromise of a device
  yields every epoch wrap it received → retroactive decryption of stored ciphertext for those
  epochs. No ratcheted healing after compromise (PCS) beyond rotation-on-removal.
- Reasonable for multi-device team chat (vs. Signal 1:1 ratchet complexity), but should be a
  documented threat-model decision, not an accident. Consider shortening wrap retention +
  proactive rotation cadence for high-sensitivity channels.

### F-E2E-003 — Metadata exposure to server/network observers (Medium, inherent design limit)
- Server sees: social graph (who talks where), timestamps, message/attachment sizes,
  attachment counts, voice participation, device inventory, IP-level presence. No padding,
  traffic shaping, or mix defenses. For the stated threat model ("continuously monitored by
  highly capable adversaries"), this is a real residual leak.
- Partial mitigations possible: padded/bucketed message sizes, attachment size bucketing,
  constant-rate heartbeat traffic, Tor/VPN guidance for transport. Worth an explicit
  documented decision rather than silence.

### F-PQC-003 — `age` backup encryption uses X25519 (Low)
- Backup tarballs are recipient-encrypted with `age` (X25519 + ChaCha20-Poly1305). X25519 is
  Shor-vulnerable → recorded backups are HNDL-exposed the same way as wraps. Backups contain
  ciphertext+wraps+metadata+password hashes, not plaintext — so the exposure is the same data
  class as the live DB, not worse. Low urgency; consider `age` plugin with PQ-hybrid recipient
  (e.g., `age-plugin-mlkem`/`pqclean` variants) when stable.

## Verified strengths (agility-positive)

- `protocol_version` on key epochs + versioned domain-separated serializers on every envelope
  = clean versioning seams for algorithm migration.
- Backups are recipient-encrypted, never plaintext, never overwritten.
- No server-side outbound fetches → SSRF surface ≈ zero; MinIO endpoint is operator-configured.
- TLS is proxy-terminated by documented design; app binds loopback-only in production profile.
- Voice SDP fingerprints are inside the signed envelope → voice E2E authenticated to device keys.
- Container hardening: read-only rootfs, cap_drop ALL, no-new-privileges, tmpfs noexec,
  pids/mem/cpu limits — limits blast radius of future vulnerabilities.
