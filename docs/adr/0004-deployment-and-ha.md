# ADR 0004: Explicit single-process support boundary

- **Status:** Accepted
- **Date:** 2026-08-30

## Context

Socket rooms, rate/bulkhead state, upload serialization and audit admission are process-local. Running replicas without shared coordination could silently weaken security and consistency. Conversely, requiring a distributed platform would make a single appliance unnecessarily fragile.

## Decision

Support one supervised application process as Level 1. Permit durable/HA PostgreSQL and object storage behind it, but do not call that application HA. Document Levels 0–6 and require explicit shared coordination, fencing, partition testing and external audit CAS before replicas. Do not auto-disable controls based on environment detection and do not ship a misleading multi-replica Kubernetes template.

## Consequences

- A single VPS can run with strong local durability, safe restart and backup.
- Process/host outage causes downtime; zero-downtime rolling/canary deployment is unavailable.
- Future HA is an additive redesign with measured failover, not a configuration switch.
