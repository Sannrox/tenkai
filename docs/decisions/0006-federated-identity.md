# ADR 0006: Federated identity across Tenkai and external planes

- Status: Accepted
- Date: 2026-07-25
- Issue: [#40](https://github.com/Sannrox/tenkai/issues/40)
- Related: [#18](https://github.com/Sannrox/tenkai/issues/18),
  [#20](https://github.com/Sannrox/tenkai/issues/20),
  [#36](https://github.com/Sannrox/tenkai/issues/36) (ADR 0004),
  [#39](https://github.com/Sannrox/tenkai/issues/39) (ADR 0005)

## Context

A managed installation may compose Tenkai with a browser-facing enterprise
identity plane and optional governance providers (policy, evaluation, audit,
learning). Without explicit federation rules, products share tables, invent
tenant ids from caller headers, or make recovery depend on optional provider
availability—creating confused-deputy and cross-tenant risks.

ADR 0001 keeps Tenkai authoritative for delivery state. ADR 0004 defines
authenticated request context. ADR 0005 separates the enterprise plane from
Tenkai’s delivery authority. This decision defines how identities are named and
mapped across those systems.

## Decision

### Authority by identity kind

| Kind | Authoritative system | Notes |
| --- | --- | --- |
| Tenant, principal, service (session/membership) | Enterprise identity plane | Minted only by that plane |
| Environment, agent, product, plan, deployment history | **Tenkai** | Never federated away |
| Policy / evaluation / evidence records | Governance provider that issued them | Bound by provider contracts |

No component performs direct reads of another product’s tenant or operational
database. Correlation uses **exported identifiers and signed context only**.

### Stable opaque identifiers

Every external identity is a `FederatedIdentifier`:

- `issuer` — who mints/owns the subject  
- `audience` — who may consume it (for Tenkai hosts, typically the server audience)  
- `subject` — opaque stable string  
- `kind` — tenant, principal, service, evidence, etc.  
- contract version  

Tenkai-local handles (environment ids, plan ids, …) remain Tenkai-owned strings.
Enterprise tenant subjects are never used as Tenkai environment ids.

### Signed context and mapping

1. The enterprise auth extension verifies short-lived, audience-bound assertions
   (ADR 0004).
2. Verified claims populate a `SignedIdentityContext` (issuer, audience,
   assertion id, principal, optional tenant/service).
3. Tenkai may store **local correlation mappings** (`IdentityMapping`) from
   external identifiers to Tenkai-local handles.
4. Writes require a `MappingAuthority` granted only for the configured issuer
   and audience after verification—not from caller headers or query parameters.
5. Assertion ids are tracked for **replay protection**. Expired or revoked
   mappings fail closed. Rotation uses a monotonic **generation**; stale
   generations cannot overwrite current mappings.

### Caller metadata

Tenant (and other) mappings **cannot** be selected or overwritten by ordinary
caller metadata (`X-Tenant-Id`, body fields, etc.). Such attempts are rejected
as `CallerMetadataForbidden`.

### Provider unavailability

| Decision class | Behavior when provider is down |
| --- | --- |
| Required (policy/gate evidence required by plan or config) | **Fail closed** |
| Optional (audit/outcome export) | **Degrade** with durable retry; operational recovery continues |

Authentication and recovery for Tenkai **do not require** a governance provider.
Standalone enterprise Tenkai requires only its configured identity-plane issuer
(when enterprise auth is enabled), not an external governance service.

### Community mode

Community embedded/server operation uses no required enterprise issuer and no
tenant federation surface. Capability negotiation (ADR / runtime capabilities)
keeps tenant mode off for community SQLite.

### Audit correlation

Logs may record `issuer:kind:subject` correlation tokens. They must not include
bearer secrets, passwords, or raw assertion material.

## Consequences

- Clear ownership prevents dual authority over environments and plans.
- Federation is testable via `src/federated_identity.rs` without shared DBs.
- Enterprise hosts configure an issuer/audience; misconfiguration fails closed.
- Governance remains optional for recovery and authentication.

## Alternatives

- **Shared tenant tables across products:** rejected; couples recovery and
  creates dual writers.
- **Trust caller-selected tenant headers after any authn:** rejected; forges
  tenant authority.
- **Require governance provider for all enterprise installs:** rejected;
  violates standalone enterprise operation and optional-provider model.
