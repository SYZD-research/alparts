# ADR 0007: Invite-gated password sessions and device binding

- **Status:** Accepted interim
- **Date:** 2026-08-30

## Context

Phase 1 has no email provider, IdP or Passkey infrastructure. Public self-registration and unbounded password work would increase abuse. E2EE operations require binding a live account session to an active device identity.

## Decision

Require a bootstrap/workspace invitation, normalize emails, store bcrypt hashes, issue signed random session capabilities whose hashes/liveness/expiry are stored in PostgreSQL, and bind sensitive crypto operations to active devices. Use challenge/device proof and password step-up for new identity enrollment. Run cheap invite preflight before a bounded shared bcrypt gate. Deliver browser sessions through secure HttpOnly/SameSite cookies and enforce exact Origin.

## Consequences

- Safe prototype enrollment/session revocation without external IdP.
- Password phishing/recovery/admin compromise remain risks; Passkey/OIDC/MFA/general step-up are release blockers.
- Rate/password gates are process-local and prohibit replicas until shared.
