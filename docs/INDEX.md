# Documentation index

English | [日本語](INDEX.ja.md)

Last verified: 2026-09-29 against the current working tree.

[Account, group security and migration](./security/ACCOUNT_AND_GROUP_SECURITY.md) documents the 2026-09-16 device approval, transparency, MLS epoch, passkey and history-recovery implementation.

This is the navigation root for implementation, architecture, security, operations, and recovery material. Statements marked **implemented** are backed by the linked code or tests. Statements marked **target** are not current guarantees.

The README and the guides for users and operators (desktop, Android, operations, backup and deployment) are available in English and Japanese; the Japanese versions end in `.ja.md`. Design records, audits and other developer material are kept in the language they were written in.

## Start here

- [Repository overview](../README.md)
- [System inventory](./SYSTEM_INVENTORY.md)
- [Desktop client](./DESKTOP.md)
- [Android client](./ANDROID.md)
- [Architecture](./policies/ARCHITECTURE.md)
- [Known limitations](./policies/LIMITATIONS.md)
- [Risk register](./RISK_REGISTER.md)
- [Verification record](./VERIFICATION.md)

## Security

- [audit-alparts remediation and deployment settings (2026-09-26)](./security/AUDIT_ALPARTS_REMEDIATION.md)
- [Security policy](./policies/SECURITY.md)
- [Threat model](./security/THREAT_MODEL.md)
- [Security audit and Deep Security Scan record](./policies/SECURITY_AUDIT.md)
- [Legacy top-level threat-model link](./policies/THREAT_MODEL.md)

## Reliability and operations

- [Reliability model](./policies/RELIABILITY.md)
- [Failure-mode analysis](./reliability/FAILURE_MODES.md)
- [SLI/SLO baseline](./reliability/SLO.md)
- [Operations](./policies/OPERATIONS.md)
- [Detailed operator guide](./OPERATIONS.md)
- [Backup and restore](./BACKUP.md)
- [Disaster recovery](./policies/DISASTER_RECOVERY.md)
- [Incident runbook](./runbooks/INCIDENT_RESPONSE.md)

## Deployment

- [Deployment guide](./policies/DEPLOYMENT.md)
- [Capability levels](./deployment/CAPABILITY_LEVELS.md)
- [Single-host production Compose](../compose.production.yml)
- [Container build](../Dockerfile)
- [Application systemd unit](../deploy/alparts.service)
- [Backup service and timer](../deploy/alparts-backup.service)
- [Development-only dependencies](../docker-compose.yml)

## Design decisions

- [ADR index](./adr/README.md)
- [Storage](./adr/0001-storage.md)
- [Consistency](./adr/0002-consistency.md)
- [Tenancy](./adr/0003-tenancy.md)
- [Deployment and HA](./adr/0004-deployment-and-ha.md)
- [Backup and recovery](./adr/0005-backup-and-recovery.md)
- [Observability](./adr/0006-observability.md)
- [Authentication](./adr/0007-authentication.md)
- [Authorization](./adr/0008-authorization.md)
- [Audit witness](./adr/0009-audit-witness.md)
- [Schema/image coupling](./adr/0010-schema-image-coupling.md)

## Interfaces and source

- [API and WebSocket inventory](./api/README.md)
- [Server entry point](../packages/server/src/index.ts)
- [HTTP composition](../packages/server/src/app.ts)
- [Database schema](../packages/server/src/db/schema.ts)
- [Runtime schema catalog gate](../packages/server/src/db/schema-catalog.ts)
- [Shared protocol types and canonical serialization](../packages/shared/src)
- [Web client](../packages/client/src)
- [Electron desktop client](../packages/desktop/src)
- [Database migrations](../packages/server/src/db/migrations)
- [Backup/restore scripts](../scripts)

## Engineering

- [Contributing and release gates](./policies/CONTRIBUTING.md)
- [Product specification (aspirational where not implemented)](./policies/SPECIFICATION.md)
- [Implementation backlog](./policies/IMPLEMENTATION_TODO.md)

`SPECIFICATION.md` describes a larger intended product. It is not an implementation or compliance claim. In a conflict, executable code/tests plus the current limitations and risk register describe the shipped boundary.
