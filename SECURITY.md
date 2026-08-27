# Security policy

This repository is a Phase 1 prototype. It must not be presented as production-ready for embargoed vulnerabilities, credentials, or other high-impact secrets. The remaining architectural limits are documented in [LIMITATIONS.md](./LIMITATIONS.md).

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, message content, private keys, or access tokens. Contact the repository owner through a private security channel and include:

- affected commit and component;
- reproduction steps with synthetic data;
- expected impact and prerequisites;
- suggested remediation, if available.

Operators must publish a deployment-specific security contact before exposing the service to users.

## Supported security baseline

- Run only the current source and lockfile; `pnpm audit` must report no known vulnerabilities.
- Set unique high-entropy values for every variable shown in `.env.example`.
- Terminate public traffic with TLS 1.3 and use TLS for remote PostgreSQL and MinIO connections.
- Keep PostgreSQL, MinIO, metrics, and administration endpoints off public interfaces.
- Serve the production web bundle through the application or reproduce all Helmet headers at the reverse proxy.
- Apply migrations before accepting traffic. Startup intentionally fails if the audit chain cannot be verified.
- Back up `AUDIT_INTEGRITY_KEY` separately; losing or silently changing it makes existing audit records unverifiable.

## Release gate

Before a production claim, complete the MUST items in `SPECIFICATION.md`, commission an independent review, resolve all Critical findings and all unaccepted High findings, generate an SBOM and provenance, sign artifacts, and pass backup/restore and malicious-attachment tests.
