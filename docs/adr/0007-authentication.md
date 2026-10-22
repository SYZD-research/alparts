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

2026-10-22: Solved work no longer buys unlimited guesses ([GHSA-8c53-h6x7-82gm](https://github.com/SYZD-research/alparts/security/advisories/GHSA-8c53-h6x7-82gm)): an account takes at most 60 failed password checks per 15 minutes from all sources together. Requests stopped by the work challenge never count, so they still cannot lock an account. Filling the cap takes solved work for each failed guess past the challenge threshold; it then closes password login, not passkey login, for the rest of the window.

2026-10-22: An invitation is honoured only while its creator may still hand it out. Using one checks, under the workspace lock, that its creator is still a member and is the owner, or still holds MANAGE_MEMBERS and may grant the invitation's role by the rules creation applies (the default role needs only the permissions it carries; a named role also needs MANAGE_ROLES and a role below the creator's highest). Otherwise the answer is the same as for any invalid invitation. Removing a member also revokes the invitations they made that are still active, so a member who comes back does not revive them. A demotion revokes nothing: the invitations work again if the authority returns.
