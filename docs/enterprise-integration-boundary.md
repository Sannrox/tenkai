# Enterprise integration boundary

This document summarizes the public Tenkai-side boundary for enterprise
composition. The durable decision is
[ADR 0005](decisions/0005-enterprise-integration-boundary.md).

It does **not** implement identity providers, tenant lifecycle, billing, or a
console, and it does not name a specific commercial product.

## Roles

| Role | Owns |
| --- | --- |
| Browser-facing enterprise plane | Tenant identity, sessions, entitlements, billing evidence, commercial UX |
| Tenkai | Releases, channels, environments, plans, leases, receipts, rollback, recovery, delivery-domain authorization |
| Optional governance providers | Policy/eval/audit/learning evidence when required—not recovery state |

Tenkai is an independently authoritative **delivery** service. It is not a
second browser-facing backend. The enterprise plane is not authoritative for
deployment objects.

## Authority (short form)

| Concern | Authority |
| --- | --- |
| Tenant identity | Enterprise identity plane |
| Sessions / login | Enterprise identity plane |
| Entitlements / billing evidence | Commercial / identity plane |
| Deployment data | **Tenkai** |
| Delivery authorization | **Tenkai** (after authenticated context) |
| Runtime credentials | **Tenkai** (one environment each) |
| Recovery | **Tenkai** operational store alone |

## Public vs private

**Public (this repo):** application core, ADR 0001–0005 contracts, auth context
port, capability negotiation, isolation harness, community SQLite, versioned
protocols.

**Private (optional separate repository):** concrete IdP adapters, tenant
admin, console, billing, managed multi-tenant store adapters, host wiring that
loads enterprise extensions.

Private code depends on public contracts only. Public Tenkai must not depend on
private crates.

## Community mode

- Embedded and community server profiles remain **tenant-free**.
- Community SQLite does not advertise tenant isolation or enterprise
  authentication capabilities.
- Requesting tenant mode without a capable store fails at startup.

## How enterprise hosts compose Tenkai

1. Verify short-lived, audience-bound credentials in an auth extension
   ([auth request context](auth-request-context.md)).
2. Advertise capabilities honestly
   ([runtime capabilities](runtime-capabilities.md)).
3. Enable tenant mode only after
   [isolation conformance](tenant-isolation-conformance.md) passes.
4. Keep enterprise identity databases separate from Tenkai operational state.
5. Pin private builds to published Tenkai contract versions.

## Failure behavior

| Situation | Behavior |
| --- | --- |
| Missing / forged / expired enterprise credential | Authentication fails; no tenant invented |
| Cross-tenant access | Non-disclosing deny (`resource not found`) |
| Required enterprise auth or tenant isolation not provided | Startup fails (capability negotiation) |
| Optional provider down | Durable retry / degraded enrichment; recovery still uses Tenkai state |
| Enterprise plane down, no required enterprise evidence | Tenkai recovery continues from its store |

## Version pinning and drift

- Auth context, capabilities, schema, and runtime protocol versions are
  explicit constants or negotiated contracts.
- Private extensions pin a Tenkai release and re-run public contract tests on
  upgrade.
- Authority or tenant-derivation changes require a new public contract version—no
  silent reinterpretation.

## Cross-repository rules

1. Dependency direction: private → public only.
2. Disclosure: public docs describe contracts, not private commercial detail.
3. Release: private artifacts pin Tenkai tags/crate versions.
4. Security: public defects follow this project’s process; private defects follow
   the private product’s process; isolation/authority bugs in public contracts
   are fixed publicly.
5. Superseding ADR required before another backend claims delivery-domain
   authority or shared operational databases are introduced.

## Related documents

- [ADR 0001 — Standalone core](decisions/0001-standalone-core-and-service-evolution.md)
- [ADR 0004 — Authenticated request context](decisions/0004-authenticated-request-context.md)
- [ADR 0005 — Enterprise integration boundary](decisions/0005-enterprise-integration-boundary.md)
- [ADR 0006 — Federated identity](decisions/0006-federated-identity.md)
- [Authenticated request context](auth-request-context.md)
- [Federated identity](federated-identity.md)
- [Runtime capabilities](runtime-capabilities.md)
- [Tenant isolation conformance](tenant-isolation-conformance.md)
- [Provider contracts](provider-contracts.md)
