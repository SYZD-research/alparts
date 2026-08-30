# ADR 0003: Shared-schema workspace tenancy

- **Status:** Accepted for Phase 1
- **Date:** 2026-08-30

## Context

Phase 1 needs small-team workspaces and private channels without the operational complexity of a database/schema per tenant. Shared rows increase the consequence of missing tenant predicates and allow one tenant to consume shared capacity.

## Decision

Use shared PostgreSQL tables keyed through workspace/resource relationships. Every protected operation derives tenant context from current membership and denies missing context. Private membership and role/override policy are additive checks. Apply transactional per-user/workspace quotas, bounded list materialization, common locks across membership-creating paths, and tenant/actor fields in logs/audit.

## Consequences

- Operational simplicity and atomic cross-resource policy inside one DB.
- A predicate/authorization bug could cross tenants, so centralized policy, integration matrices and fail-closed routes are mandatory.
- Storage/cache/queue/log isolation is logical, not physical. No cache/queue exists today.
- Dedicated-database tenancy and cross-tenant federation are not implemented.
