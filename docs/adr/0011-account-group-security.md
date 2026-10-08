# ADR 0011: Approved devices, verifiable directories and MLS-based epochs

- **Status:** Implemented; independent security acceptance pending
- **Date:** 2026-09-16
- **Supersedes:** ADR 0007's password-only/device-enrollment limitations and the earlier RSA epoch design for new writes.
- **Superseded in part (2026-10-07):** the group-protocol decision below (fresh RFC 9420 groups per application epoch, the preserved exact-delivery/all-recipient activation barrier, and offline participants blocking fresh epochs) is replaced by [ADR 0012](./0012-continuous-mls-groups.md). Device approval, transparency, passkeys and recovery remain in force.

## Decision

Separate account authentication from approved messaging endpoints. Require an approved-device signature or user recovery proof for additional devices. Append signed decisions to an account hash chain, pin and compare checkpoints on clients, and carry them in signed group rosters.

Use pinned ts-mls for fresh RFC 9420 groups per application epoch, with a fixed suite and exporter-derived channel key. Preserve the existing exact-delivery/all-recipient activation barrier and transactional authorization boundary. Keep old history keys separately encrypted and recoverable only through user-confirmed recovery material.

Support discoverable WebAuthn with mandatory user verification and exact-request, one-use step-up. Refuse password fallback after passkey enrollment. Preserve the account login boundary when restoring history.

## Consequences

Offline participants may block fresh epochs. Archive retention intentionally limits forward-secrecy claims. First-contact/migration trust still requires TOFU or external verification; there is no independent witness. Native packaged origins need additional WebAuthn integration. No organization escrow, threshold recovery or Restricted policy is implied.

The [protocol and migration document](../security/ACCOUNT_AND_GROUP_SECURITY.md) defines bounds, failure behavior, specification mapping, configuration and verification. Independent cryptographic review remains a release gate.
