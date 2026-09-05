# Phase 2 implementation status

Phase 2 is **not complete or suitable for formal release**. The starting tree also
lacks Phase 1 security prerequisites (MLS-equivalent group security, approved device
enrollment/key transparency, Passkey/OIDC and complete encrypted history recovery).
The existing confidentiality warning and release gates still apply.

| Specification scope | Implemented in this change | Remaining acceptance work |
| --- | --- | --- |
| Android | Bundled client, Keystore wrapping, native lock, mobile navigation, attachment document chooser, Gradle build | Device E2E/MASVS, background sync/Push, share sheet |
| iOS | Excluded by request | Apple build environment |
| HA | Dependency analysis recorded below | Shared coordination, fencing, revocation/room ordering, failure tests |
| Single-node to cluster | Read-only database fingerprints and comparison | Cluster runtime, schema/constraint and object checks at cutover, rollback rehearsal |
| Restricted | No policy implementation claimed | Approved native devices, history boundary, policy enforcement on all REST/WS/key routes |
| Organization-assisted recovery | No recovery implementation claimed | User-visible trustee policy, threshold cryptography, approval, audit and client recovery |
| Bot/Webhook | No integration implementation claimed | Explicit participant identity, limited channel rights, encrypted delivery, revocation, restricted defaults |
| External security audit | Existing audits remain historical evidence | Independent reviewer engagement and remediation; cannot be self-certified |
| SLSA/SBOM/signed updates | Combined runtime inventory, CI provenance workflow, offline signed manifest and artifact verification | Run protected CI, sign final APK/distribution, protect trust state, integrate automatic installers; no SLSA level claimed |
| DR exercise | Existing restore verifier wrapped with private outcome/timing report | Run real isolated restore and application smoke checks, off-site/PITR/site exercise |

## HA blockers confirmed in code

`security/device-challenge.ts` keeps one-use challenges in a process-local Map;
`middleware/rate-limit.ts`, socket leases, voice presence and upload admission are
also process local. Room grants/revocation depend on synchronous in-process changes
while workspace authorization locks are held. A generic cross-node adapter does not
preserve that contract. `middleware/audit.ts` serializes local checkpoint publication;
independent processes need a shared witness protocol and failure fencing.

The accepted [HA ADR](adr/0004-deployment-and-ha.md) remains in force. No replica
configuration is added that would silently weaken those controls.

## Migration evidence

With writers stopped, use the same PostgreSQL major version for both environments:

```sh
pnpm --filter @alparts/server db:fingerprint capture /secure/source.json
# Configure the isolated destination database connection, then:
pnpm --filter @alparts/server db:fingerprint capture /secure/target.json
pnpm --filter @alparts/server db:fingerprint compare /secure/source.json /secure/target.json
```

Capture opens a repeatable-read read-only transaction and streams canonically ordered
rows through SHA-256. Reports contain table/column metadata, counts and hashes, never
row contents. Equal fingerprints cover IDs and stored contents, not availability,
foreign-key definitions, object storage or events committed after the snapshot.
Protect reports as operational metadata. Retain the source read-only for rollback.

The migration command was exercised against a disposable PostgreSQL 16 instance:
two identical snapshots of parent/child tables compared successfully; changing a
stored value caused `MIGRATION_FINGERPRINT_MISMATCH` with a nonzero exit status.
This was a verifier regression check, not a completed cluster migration.

## Release evidence and offline verification

The Android workflow builds without production signing credentials. Manual workflow
execution prepares an unsigned artifact/SBOM and requests GitHub build provenance.
Nothing is published to users automatically. Review provenance identity using
`gh attestation verify` and the intended repository/workflow/ref before signing.
The generated inventory covers npm and Android runtime components; it does not
inventory a server container's OS packages or certify the completeness of native
Electron dependencies. A production SBOM still needs those artifact-specific inputs.

After final platform signing, place artifacts in a directory ignored by Git, from
a clean committed source tree:

```sh
pnpm release:prepare dist/release stable 1 dist/release/alparts.apk
node scripts/release/update-manifest.mjs sign dist/release/manifest.json /secure/update-private.pem release-2026 dist/release/signed.json
node scripts/release/update-manifest.mjs verify dist/release/signed.json /secure/trust.json dist/release stable 0
```

The Ed25519 private key file must be mode 0600, generated/held by the authorized
release signer. `trust.json` is independently provisioned, never taken from the
downloaded release. Its schema is:

```json
{"keys":{"release-2026":{"publicKey":"<PEM public key>","channels":["stable"],"revoked":false}}}
```

The last CLI argument is the locally trusted highest **installed** sequence. Persist
the new sequence only after successful installation; this verifier does not install
or persist it. Reject unknown/revoked keys, channel changes, replay, expired metadata,
unsafe filenames and mismatched sizes/digests. Key replacement is an out-of-band
trust-store operation reviewed by release owners, not a field accepted from a server.
Do not silently roll back sequence protection to recover from a failed release.

## Restore drill

Configure the existing [backup verifier](BACKUP.md), including its explicit isolated
target acknowledgement. Then:

```sh
pnpm dr:drill /secure/alparts-backup.tar.age /secure/new-drill.json
```

The report and adjacent private log are created exclusively, so existing reports
are not overwritten. Failure returns nonzero and is recorded as failure. Duration
measures the restore/check operation only; it is not an RPO measurement or proof of
the four-hour complete service RTO. The script cannot supply production backups,
recovery identities or an independent audit on the operator's behalf.
