# ADR 0007: Invite-gated password sessions and device binding

- **Status:** Amended by [0011](./0011-account-group-security.md)
- **Date:** 2026-08-30

## Context

Phase 1 has no email provider, IdP or Passkey infrastructure. Public self-registration and unbounded password work would increase abuse. E2EE operations require binding a live account session to an active device identity.

## Decision

Require a bootstrap/workspace invitation, normalize emails, store bcrypt cost 12–15 results protected by a DB-external HMAC pepper, issue signed random session capabilities whose hashes/liveness/expiry are stored in PostgreSQL, and bind sensitive crypto operations to active devices. Use challenge/device proof and password step-up for new identity enrollment. Run cheap invite preflight before bounded public authentication admission with separate public/authenticated bcrypt workers. Deliver browser sessions through secure HttpOnly/SameSite cookies and enforce exact Origin.

## Consequences

- Safe prototype enrollment/session revocation without external IdP.
- Web passkeys, approved-device enrollment and sensitive-action step-up are implemented in ADR 0011. OIDC, native WebAuthn and independent assurance remain open.
- Rate/password gates are process-local and prohibit replicas until shared.

2026-09-17: [Audit 2](../../SECURITY_AUDIT_2.md) adds pepper migration, keyed failed-login attribution and expiring one-use work challenges instead of an account-wide hard login lockout. Account creation and invitation validity remain distinct outcomes.
