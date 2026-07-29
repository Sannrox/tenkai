# Tenant isolation conformance

Enterprise hosts that enable tenant mode must pass Tenkai's deterministic
two-tenant isolation harness before release. Community embedded and server
modes remain tenant-free and do not load this surface in production.

Source of truth: `src/tenant_isolation.rs`. Authenticated request context:
[auth-request-context.md](auth-request-context.md) and
[ADR 0004](decisions/0004-authenticated-request-context.md).

## Purpose

Tenant isolation cannot depend on each endpoint remembering ad-hoc checks.
Catalog, environment, plan, agent, event, aggregate, and runtime-agent surfaces
can leak identifiers even when direct object reads are protected. This harness:

1. Builds two isolated tenants with distinct products, environments, agents,
   plans, deployments, and credentials.
2. Exercises valid, missing, mismatched, forged, expired, wrong-audience,
   suspended, and revoked contexts.
3. Verifies list/count/status/event/metric-label/cache/audit responses never
   reveal foreign tenant markers.
4. Ensures runtime agent credentials cannot poll, acknowledge, or heartbeat
   for another tenant or environment.
5. Requires every tenant-visible RPC to register isolation cases so CI fails
   when a new surface is added without coverage.

The harness runs in-process without external policy, evaluation, or identity
providers.

## Non-disclosing error posture

Cross-tenant or unauthorized resource access returns:

```text
resource not found
```

(`NON_DISCLOSING_DENY`)

Rules:

- Do not distinguish "missing" from "exists in another tenant".
- Do not echo foreign tenant ids, product ids, plan ids, or tokens in the
  public error body.
- Authentication failures may say `unauthenticated` or `invalid credential`
  without naming foreign resources.

## Registry and CI coverage

| Symbol | Role |
| --- | --- |
| `tenant_visible_rpcs()` | Canonical list of tenant-visible public operations |
| `required_isolation_cases()` | Cases every RPC must cover |
| `conformance_case_matrix()` | Per-RPC case registration |
| `assert_conformance_coverage()` | Fails when a registered RPC lacks a required case |

When adding a tenant-visible RPC or HTTP route that can return tenant-scoped
data:

1. Append a `TenantVisibleRpc` entry to `tenant_visible_rpcs()`.
2. Ensure `conformance_case_matrix()` includes every required isolation case
   for that id (today the matrix assigns the full required set to each RPC).
3. Extend `TenantIsolationHarness::run_conformance` (or surface methods) so the
   case is actually exercised.
4. Run `cargo test --lib tenant_isolation`.

Unauthenticated health probes (`/healthz`, `/readyz`) are not tenant-visible
and are not registered.

### HTTP exposure vs registry (#112)

| Set | Meaning |
| --- | --- |
| `tenant_visible_rpcs()` | Full isolation matrix (harness + future routes) |
| `http_exposed_tenant_rpc_ids()` | Subset that is **live on management/runtime HTTP** and enforced in `src/server.rs` |

**HTTP-enforced today**

| RPC id | Route | Tenant-mode enforcement |
| --- | --- | --- |
| `management.reconcile` | `POST /v1/reconcile` | Require tenant context; resolve tenant envs before bounded work selection |
| `management.fleet_status` | `GET /v1/fleet/status` | Filter rows to tenant envs |
| `environment.list` | `GET /v1/environments` | List only tenant partition ids |
| `environment.get` | `GET /v1/environments/{env}` | Non-disclosing deny on cross-tenant |
| `environment.status` | `GET /v1/environments/{env}/status` | Same as get |
| `runtime.work` / `complete` / `heartbeat` | `/v1/runtime/environments/{env}/…` | Runtime credential scoped to exactly one environment |

**Registered but not exposed on HTTP** (harness / in-process enterprise surfaces only; not advertised as public routes):

- `catalog.list_products`, `catalog.get_product`
- `plan.list`, `plan.get`
- `deployment.list`, `agent.list`, `event.list`
- `aggregate.status`, `aggregate.counts`, `aggregate.metric_labels`,
  `aggregate.cache_lookup`, `aggregate.audit_list`

Adding a new HTTP route that returns tenant-scoped data requires both registry
registration and an `http_exposed_tenant_rpc_ids` entry plus server enforcement
tests. Community tenant-free profile remains the default.

## Fixture shape

`TwoTenantFixture` creates `tenant-a` and `tenant-b`, each with distinct:

- product, environment, agent, plan, deployment identifiers
- runtime credentials
- event, audit, cache, and metric-label values

## Reference surface

`InMemoryTenantSurface` is a **conformance model**, not a production multi-tenant
database. Enterprise implementations must satisfy the same isolation outcomes
when wiring real persistence. Commercial quotas and noisy-neighbor performance
isolation are out of scope.

## Tenant-isolating operational store adapter

`src/tenant_store.rs` provides the enterprise store port used when hosts enable
tenant mode:

| Type | Role |
| --- | --- |
| `InMemoryTenantOperationalStore` | Multi-tenant factory; one isolated in-memory SQLite partition per tenant |
| `TenantPartition` | `OperationalStore` for a single authenticated tenant |
| `tenant_memory_store_capabilities()` | Advertises `tenant_isolation` and an honest migration level |

Rules:

- Community `SqliteStore` remains tenant-free and must not claim `tenant_isolation`.
- Partitions are opened only through `AuthenticatedRequestContext` tenant
  membership derived by the auth stack — never from caller-selected headers.
- Cross-tenant environment get/list uses the non-disclosing deny posture.
- The adapter does **not** share a database with an identity plane (ADR 0005).
- Production PostgreSQL remains out of scope for this public repository surface.

Run `InMemoryTenantOperationalStore::run_conformance` (or
`cargo test tenant_store`) to exercise harness coverage plus store-partition
isolation.

## Live management HTTP (tenant mode)

When `ServerConfig.requirements.tenant_mode` is true and a
`tenant_store` (`InMemoryTenantOperationalStore` or equivalent) is configured:

| Route | Isolation |
| --- | --- |
| `GET /v1/environments` | Lists only the authenticated tenant's environments |
| `GET /v1/environments/{environment}` | Cross-tenant ids → non-disclosing `resource not found` |
| `GET /v1/environments/{environment}/status` | Same non-disclosing deny |

Community tenant-free hosts leave `tenant_mode` false and `tenant_store` unset.
Startup fails closed if tenant mode is requested without store + capability.

## Relationship to community mode

Community hosts use `AuthHostConfig::community()` and never attach tenant
context. They are not expected to pass the enterprise harness surface; the
harness itself starts in enterprise auth mode and fails closed without a
required extension.
