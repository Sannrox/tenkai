# ADR 0005: Enterprise integration boundary

- Status: Accepted
- Date: 2026-07-25
- Issue: [#39](https://github.com/Sannrox/tenkai/issues/39)
- Related: [#16](https://github.com/Sannrox/tenkai/issues/16) (ADR 0001),
  [#36](https://github.com/Sannrox/tenkai/issues/36) (ADR 0004),
  [#37](https://github.com/Sannrox/tenkai/issues/37),
  [#38](https://github.com/Sannrox/tenkai/issues/38)

## Context

Tenkai is a standalone delivery control plane with tenant-free community
embedded and server modes. Enterprise products may place a browser-facing
identity and tenant plane in front of Tenkai and may host commercial behavior
outside this public repository. Without an explicit boundary, implementers risk:

- duplicating authorization authority between the identity plane and Tenkai;
- coupling community SQLite operation to private commercial components;
- sharing databases across product boundaries;
- treating Tenkai as a second browser-facing backend or treating the identity
  plane as operational recovery material.

ADR 0001 already assigns delivery-domain ownership to Tenkai. ADR 0004 defines
authenticated request context and optional tenant derivation. This decision
records the product composition boundary and the public vs private split.

Earlier draft wording that required one process for the full enterprise product
is **superseded**. Tenkai remains an independently authoritative delivery
service; the browser-facing enterprise API is a separate product surface that
supplies authenticated context to Tenkai.

## Decision

### Product roles

| Role | Responsibility |
| --- | --- |
| **Browser-facing enterprise plane** | Tenant identity, sessions, entitlements, billing evidence, operator console UX, and commercial product assembly. Issues short-lived, audience-bound credentials that Tenkai can verify through an extension. |
| **Tenkai delivery service** | Releases, channels, environments, plans, leases, receipts, rollback, recovery, and delivery-domain authorization. Owns its operational persistence. Never depends on the enterprise plane for recovery. |
| **Optional governance providers** | Policy, evaluation, audit export, and learning as defined in provider contracts. Never own operational recovery state. |

Tenkai is **not** a second browser-facing backend. The enterprise plane is **not**
authoritative for delivery-domain objects. Adding another backend that claims
authority over the same delivery objects requires a superseding ADR.

### Authority matrix

| Concern | Authoritative owner | Tenkai obligation |
| --- | --- | --- |
| Tenant identity and membership | Enterprise identity plane | Consume verified principal + optional tenant via ADR 0004 context only |
| Browser sessions and login UX | Enterprise identity plane | None |
| Entitlements and commercial product rights | Enterprise identity plane / commercial control plane | May receive entitlement evidence as external policy input; must not own billing |
| Billing evidence | Commercial systems | None; never store payment secrets in Tenkai operational state |
| Deployment data (releases, channels, plans, leases, receipts, rollback) | **Tenkai** | Sole operational source of truth |
| Delivery-domain authorization (who may publish, promote, apply, unlock) | **Tenkai** | Enforce after authentication; identity plane cannot mint plans or leases |
| Environment runtime credentials | **Tenkai** | Scoped to exactly one environment |
| Operator fleet operations for delivery | **Tenkai** (APIs, reconciler, recovery) | Enterprise console may call Tenkai APIs with authenticated context |
| Governance eval / policy evidence | Optional providers when required by plan/policy | Fail closed when required evidence is missing |

### Public reusable contracts vs private concrete behavior

**Public (this repository and its versioned contracts):**

- Application core and embedded/server hosts (ADR 0001)
- Authenticated request context and enterprise auth extension port (ADR 0004)
- Tenant isolation conformance harness
- Runtime capability negotiation
- Catalog, plan, runtime protocol, offline bundle, provider, and storage contracts
- Community SQLite operational store (tenant-free)

**Private (may live in a separate private repository or product tree):**

- Concrete identity-provider integration (OIDC/SAML adapters, key material handling)
- Tenant lifecycle, org admin, and commercial console
- Entitlement and billing implementation
- Managed multi-tenant operational store adapters (for example PostgreSQL with
  tenant isolation) that implement public store and capability contracts
- Host wiring that loads enterprise extensions into a Tenkai server process

Private code **consumes** public contracts. It does not redefine release, plan,
lease, or recovery ownership. Linking a private extension into a Tenkai server
host is allowed; forking a second authoritative delivery backend is not.

### Persistence and databases

- Community SQLite remains **tenant-free** and sufficient for solo/embedded use.
- Tenkai operational state is **not** shared with the enterprise identity plane
  database. No shared tables, dual writers, or cross-product foreign keys.
- Enterprise multi-tenant stores are separate adapters behind
  `OperationalStore` and capability advertisement. They must pass tenant
  isolation conformance before tenant mode is enabled.
- Artifact bytes remain in external content stores addressed by digest.

### Version pinning and contract drift

| Interface | Pinning rule |
| --- | --- |
| Auth context contract | `AUTH_CONTEXT_CONTRACT_VERSION`; incompatible extensions fail at startup |
| Runtime capabilities | `RUNTIME_CAPABILITY_CONTRACT_VERSION`; missing required capabilities fail at startup |
| Operational schema | `SCHEMA_VERSION` / migration level; unsupported newer schemas fail closed |
| Runtime protocol | Versioned protobuf / HTTP contracts with explicit negotiation |
| Private enterprise extensions | Pin to published Tenkai crate/protocol versions; CI must run public contract and isolation tests against the pin |
| Drift | Contract changes that alter authority, tenant derivation, or recovery require a new public contract version and a coordinated extension release. Silent reinterpretation is forbidden. |

### API and event failure behavior

- Missing, expired, wrong-audience, forged, suspended, or revoked enterprise
  credentials fail authentication; Tenkai does not invent a tenant.
- Cross-tenant access uses the non-disclosing deny posture from the isolation
  harness.
- Optional provider failure degrades enrichment and retries durably; it never
  becomes recovery authority.
- Enterprise plane unavailability must not prevent Tenkai from completing
  recovery from its own operational store when no enterprise evidence is
  required by policy.
- When policy or configuration **requires** enterprise authentication or tenant
  isolation, hosts fail at **startup** (capability negotiation) rather than
  mid-deployment.

### Cross-repository dependency, disclosure, release, and security reporting

When enterprise concrete behavior lives outside this repository:

1. **Dependency direction:** private → public only. Public Tenkai must not
   import private crates or private APIs.
2. **Disclosure:** public docs and ADRs describe contracts and ownership, not
   private commercial implementation details or customer data.
3. **Release:** private builds pin a released Tenkai version (tag or crate
   version). Breaking contract bumps require a private release train.
4. **Security reporting:** vulnerabilities in public Tenkai contracts and code
   are reported through this project’s security process. Vulnerabilities in
   private enterprise components are handled by the private product’s process;
   boundary bugs that weaken Tenkai isolation or authority must be fixed on the
   public side when the defect is in a public contract or default host.
5. **Testing:** private assemblies that enable tenant mode must run the public
   tenant isolation conformance harness and capability negotiation checks.

### Supersession

A new ADR is required before:

- introducing another system that claims authority over Tenkai delivery-domain
  objects;
- requiring the enterprise identity plane for community recovery;
- sharing an operational database between Tenkai and the identity plane;
- making tenant mode the default for community embedded SQLite.

## Consequences

- Community users keep a one-binary, tenant-free path.
- Enterprise products can compose a browser-facing plane with a standalone
  Tenkai delivery service without duplicating deployment authority.
- Private repositories may implement extensions and multi-tenant stores against
  public contracts with explicit version pins.
- Operators and integrators have a single ownership matrix for identity vs
  delivery vs commercial concerns.

## Alternatives

- **Hard-link identity into Tenkai:** rejected; forces enterprise identity on
  community mode and blurs process/product boundaries.
- **Shared database for tenants and deployments:** rejected; couples recovery
  and commercial data, creates dual-write risk.
- **Tenkai as browser-facing multi-tenant SaaS core:** rejected for this ADR;
  public Tenkai remains the delivery control plane, not the commercial console.
- **Second delivery backend for enterprise only:** rejected; splits authority
  and breaks embedded/server equivalence (ADR 0001).
