# Security policy

## Supported versions and status

Only the current default-branch source, frozen lockfile, and an immutable image built from that exact tree receive security fixes. There is no security backport or support promise for older commits, images, browser bundles, or database schemas.

This repository is a Phase 1, single-process prototype. It must not be presented as approved for embargoed vulnerabilities, credentials, regulated data, or other high-impact secrets. Canonical trust boundaries and unresolved risks are documented in [the threat model](../security/THREAT_MODEL.md), [LIMITATIONS.md](./LIMITATIONS.md), and [the risk register](../RISK_REGISTER.md).

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, message content, private keys, access tokens, personal data, or tenant identifiers. Contact the repository owner through a private security channel and include:

- affected commit/image and component;
- reproduction steps using synthetic data and an isolated deployment;
- required privileges, attack path, impact, and affected security property;
- relevant logs with secrets and content removed;
- suggested remediation, if available.

Do not test against a deployment without its operator's authorization, access data belonging to another user or tenant, persist access, or degrade availability. Operators must publish a deployment-specific security contact and response process before exposing the service to users; this repository does not invent an address or response-time commitment.

## Repository security-review scope

Security review covers all first-party server, browser, shared protocol, migration, backup/restore, configuration, CI, container, Compose, and systemd paths. Give particular attention to:

- authentication, live-session/device binding, authorization, tenant isolation, and administration;
- E2EE envelope/key state, identity binding, replay/idempotency, and browser key handling;
- audit admission/integrity, secret handling, logging, metrics, and request/trace context;
- injection, unsafe parsing, path/object-key confusion, SSRF, XSS/CSRF, and active content;
- bounded work, deadlines, retry behavior, concurrency, transaction and migration safety;
- backup/restore, deployment defaults, artifact dependencies, and supply-chain controls.

Future features listed only in `SPECIFICATION.md`, general product completeness, accessibility, and licensing are not implemented security guarantees. However, any code path that violates a property below remains in scope even if the feature is incomplete.

## Required security properties

- Missing, stale, or ambiguous identity, session, device, tenant, membership, or authorization context fails closed. A missing tenant ID never grants global access.
- Message and attachment content plaintext remains at authorized endpoints. Logs, metrics, audit details, and error responses exclude plaintext, ciphertext-adjacent secrets, passwords, tokens, private keys, and raw request bodies.
- In the supported one-process topology, security/administration and other authoritative mutations use audited or guarded bounded admission. After required checkpoint persistence fails, readiness and later authoritative writes fail closed; advisory presence/activity cannot grant authority.
- Request bodies, queues, fan-out, histories, retries, dependency calls, browser work, DB connections, and file/object operations have explicit finite limits or deadlines. Ambiguous mutation retries reuse the identical idempotency key and signed/encrypted request.
- Production configuration requires explicit origins, strong independent secrets, a required audit checkpoint, safe bind behavior, and authenticated certificate-verified TLS for remote dependencies. Plaintext dependency transport is permitted only for an explicitly acknowledged loopback or Unix-socket deployment.
- The running code accepts only its exact ordered migration bundle and supported PostgreSQL catalog fingerprint. Migration and restore operations use separate least-privilege identities and never silently repair or downgrade schema state.

## Supported security baseline

- Install from the frozen lockfile, run the repository and final-image security gates, and resolve every Critical and every unaccepted High finding before release.
- Generate unique high-entropy values for every secret shown in `.env.example`; inject them through protected files or a secret provider, rotate them independently, and never commit or log them.
- Terminate public traffic with a modern TLS policy and use certificate-verified TLS for remote PostgreSQL and object-storage connections.
- Keep PostgreSQL, object storage, metrics, probes, and operator interfaces off public interfaces and behind least-privilege network policy.
- Serve the exact production web bundle through the application or reproduce all Helmet/CSP/cache headers at the trusted reverse proxy. Do not inject unreviewed third-party runtime scripts.
- Apply the image-bundled migration as a separate pre-deploy step, initialize the audit checkpoint explicitly on first deployment, and require startup/readiness gates before traffic.
- Protect `AUDIT_INTEGRITY_KEY` and the checkpoint under authority independent from PostgreSQL where possible. Losing or silently changing either breaks the stated audit guarantee.
- Configure encrypted off-host backup custody, retention, monitoring, and scheduled isolated restore tests. A local backup file alone is not a durability claim.

Device approval, client-verified directory chains, continuous per-channel MLS groups, web passkeys, step-up and user-controlled archive recovery are documented in [the account/group security update](../security/ACCOUNT_AND_GROUP_SECURITY.md).

## Explicitly unsupported security claims

The current tree does not claim horizontally safe application replicas, automatic HA/failover, multi-region writes, PITR/WORM/off-site custody, independent transparency witnesses, per-message archive forward secrecy, native WebAuthn integration, endpoint compromise resistance, formal cryptographic review, or independent penetration-test approval. These are release/deployment blockers or intentional boundaries in the risk register, not capabilities inferred from configuration.

## Release gate

Before a production or mission-critical claim, complete the applicable MUST items in `SPECIFICATION.md`, close or explicitly accept deployment-specific blockers through the owner's risk process, commission independent architecture/cryptography/application/operations review, resolve every Critical and every unaccepted High finding, generate and retain an SBOM plus provenance, sign immutable artifacts, and pass migration, malicious-input, load/soak, backup/restore, and full disaster-recovery exercises on the intended topology.
