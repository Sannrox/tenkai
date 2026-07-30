# Runtime capability negotiation

Tenkai hosts validate the composed runtime capability set **before** accepting
traffic. Configuration may request tenant isolation, multi-replica operation,
high availability, or enterprise authentication only when storage and
extensions actually provide those guarantees.

Source of truth: `src/runtime_capabilities.rs`. Related contracts:

- [Authenticated request context](auth-request-context.md)
- [Tenant isolation conformance](tenant-isolation-conformance.md)
- [Enterprise integration boundary](enterprise-integration-boundary.md)
- [Operational storage](operational-storage.md)
- [ADR 0010: supported operating profiles](decisions/0010-supported-operating-profiles.md)

## Why this exists

Discovering that SQLite cannot provide tenant isolation or shared replica-safe
state during a deployment is unsafe. Capability negotiation fails closed at
startup with an actionable error naming the missing capability and what the
runtime currently provides.

## Capability names

| Name | Meaning |
| --- | --- |
| `tenant_isolation` | Store/host can enforce tenant boundaries |
| `shared_replica_state` | Operational state is safe for concurrent writer replicas |
| `high_availability` | HA semantics beyond a single process |
| `enterprise_authentication` | Host can verify enterprise authentication assertions |
| `operational_store_migration` | Supported operational schema / migration level |

Each capability is versioned. Migration also carries a numeric `level` (the
store schema version).

## Diagnostic identifiers versus operating profiles

The current `profile` field in runtime diagnostics describes a low-level
composition, not an operator support contract:

- `community-sqlite` is the current diagnostic identifier for SQLite-backed
  hosts. It underlies the stable default `local` profile and the experimental
  single-server `fleet` profile.
- `enterprise-tenant-postgres` identifies the current mixed composition:
  PostgreSQL owns tenant-store state while SQLite still owns non-tenant
  application state. It is a test-only integration surface, not the gated
  `enterprise-experimental` operating profile.

ADR 0010 defines complete operating profiles. The mixed-store composition
cannot activate `enterprise-experimental` until PostgreSQL is the sole
authoritative operational store and the ADR's startup, conformance, migration,
backup, restore, and usability evidence exists. Capability negotiation remains
useful component evidence, but a set of component claims is not by itself a
support, failover, or recovery promise.

## Community SQLite diagnostic composition

Embedded SQLite and the default `tenkai-server` profile advertise:

```text
profile: community-sqlite
capabilities:
  - operational_store_migration:v1:levelN   # N = SCHEMA_VERSION
```

They do **not** advertise tenant isolation, shared replica state, high
availability, or enterprise authentication. Community operation is
intentionally tenant-free. `local` remains the stable default operating
profile. `fleet` remains experimental, single-server, and tenant-free; it does
not gain shared-server or HA guarantees from the diagnostic identifier.

**HA profile:** single-replica operation means process restart + backup/restore
only — not multi-writer reconcile. Multi-replica and HA flags fail closed until
a store honestly advertises the matching capabilities. Decision:
[ADR 0009](decisions/0009-multi-replica-reconcile-and-ha-profile.md).

The optional Postgres tenant-store component (`--features postgres`) advertises
`shared_replica_state` under a **single-active-writer** model (failover on
the shared tenant-state database). Multi-host conformance uses tick fencing;
neither claim covers SQLite-backed application state or establishes product
failover, HA, backup, or recovery. See
[postgres-tenant-store.md](postgres-tenant-store.md#shared-replica-state-128)
and [multi-replica-hub-runbook.md](multi-replica-hub-runbook.md).

## Host requirements

`RuntimeRequirements` captures what the operator configured:

| Field | Default | Effect when set |
| --- | --- | --- |
| `tenant_mode` | false | Requires `tenant_isolation` |
| `replica_count` | 1 | Values `> 1` require `shared_replica_state` |
| `require_high_availability` | false | Requires `high_availability` |
| `require_enterprise_authentication` | false | Requires `enterprise_authentication` |
| `min_migration_level` | 1 | Requires migration level ≥ value |

`validate_runtime_capabilities(provided, required)` is the single negotiation
entry point used by the server router and the `tenkai-server` binary.

## Server flags

```sh
tenkai-server \
  --tenant-mode \
  --replica-count 2 \
  --require-high-availability \
  --require-enterprise-auth \
  --min-migration-level 1 \
  --with-enterprise-auth
```

- Requesting tenant mode against community SQLite **fails startup**.
- Requesting `--replica-count 2` without a shared-replica-capable store **fails
  startup**.
- Enterprise JWT authentication requires
  `TENKAI_JWT_VERIFIER_CONFIG=/path/to/public-trust.toml`. The server advertises
  `enterprise_authentication` only after loading a usable
  `JwtEnterpriseAuthExtension`; `--with-enterprise-auth` cannot make an
  unsupported capability claim.
- `--require-enterprise-auth` fails before listen unless the verifier is
  configured and usable. This static Ed25519 verifier is an Aldunis integration
  contract, not an OIDC or browser-session implementation.

## Health and diagnostics

`/healthz` and `/readyz` include:

```json
{
  "status": "ready",
  "profile": "community-sqlite",
  "capabilities": ["operational_store_migration:v1:level6"]
}
```

Capability diagnostics never include tokens, secrets, or tenant identifiers.
Until profile selection is implemented, operators must not interpret the
diagnostic `profile` value as activation of an ADR 0010 operating profile.

## Compatibility matrix

Automated coverage lives in `community_sqlite_compatibility_matrix()` and the
`runtime_capabilities` unit tests. Negative rows include:

- tenant mode on tenant-free store
- multi-replica without shared replica state
- HA without HA capability
- enterprise auth required without enterprise auth capability
- migration floor above the store schema level

## Non-goals

This contract does **not** implement complete PostgreSQL authority, tenant
lifecycle, high availability, or operating-profile activation. Future adapters
add component capabilities by implementing
`OperationalStore::runtime_capabilities` and composing auth extension claims;
ADR 0010 separately governs when a complete profile may be selected.
