# ADR 0006: Safe structured observability

- **Status:** Accepted
- **Date:** 2026-08-30

## Context

Incidents need correlation, outcome, latency and saturation evidence, but communication systems can leak severe secrets through logs/metrics. Public diagnostic endpoints also expose operational state.

## Decision

Emit structured JSON with UTC time, severity, component/operation/outcome and validated/generated request/trace context; add actor/tenant IDs only after authentication/authorization. Never log bodies, credentials, keys or plaintext. Provide an optional Prometheus endpoint disabled by default, requiring a strong bearer secret and private routing. Separate live/startup/ready probes. Propagate W3C trace IDs now; defer a full exporter until distributed topology needs it.

## Consequences

- Useful request/dependency/saturation diagnosis with lower leakage risk.
- Metrics and log state are per-process and externally retained/alerted.
- Operators must add disk/certificate/storage/backup/synthetic alerts.
