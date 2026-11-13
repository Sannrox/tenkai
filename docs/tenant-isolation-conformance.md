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
can leak identifiers even when direct object reads are protected. Environment
names are partition-local: tenant fleet, inspect, and status must not join
process-global reconciler rows by bare environment id. Package-migration
records are keyed by caller partition plus name, not by environment id
visibility alone. This harness:

1. Builds two isolated tenants with distinct products, environments, agents,
   plans, deployments, and credentials.
2. Exercises valid, missing, mismatched, forged, expired, wrong-audience,
   suspended, and revoked contexts.
3. Verifies list/count/status/event/metric-label/cache/audit responses never
   reveal foreign tenant markers.
4. Ensures runtime agent credentials cannot poll, acknowledge, or heartbeat
   for another tenant or environment.
5. Pairs with a route guard in `tenkai-http` that fails CI when a published
   HTTP route serves tenant mode without a registration, or returns tenant A's
   identifiers to tenant B.

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

`tenant_visible_rpcs()` is the canonical list of tenant-visible operations.
HTTP entries use `METHOD /v1/...` templates that match the published contract
(`api/tenkai-http-v1.schema.json`). Harness and in-process entries use other
templates (`LIST plans`, `GET status`).

The tenant route guard (`crates/tenkai-http/src/tests/tenant_routes.rs`) checks
the registry against the real router. It builds a tenant-mode hub where tenant
A owns an environment, a release, and a channel, then calls every published
route as tenant B, once with tenant B's identifiers and once with tenant A's.
It fails when:

- a route succeeds for tenant B but is neither registered nor listed as
  tenant-free (health, OIDC discovery, `GET /v1/auth/me`, `GET /v1/trust`);
- any response contains a tenant A identifier that tenant B did not send;
- a registered `/v1/` template is no longer a published route (the pull
  runtime and development fixtures sit outside the published contract and are
  skipped).

Mutating routes receive an empty JSON body, so a route that rejects the body
before its tenant check passes the success check. The leak check still applies
to its response. Per-route isolation behavior is proven by the tenant tests in
`crates/tenkai-http/src/tests/` and by `TenantIsolationHarness::run_conformance`.

When adding a tenant-visible RPC or HTTP route that can return tenant-scoped
data:

1. Append a `TenantVisibleRpc` entry to `tenant_visible_rpcs()`.
2. Add server enforcement tests for the route (missing context, cross-tenant
   identifier, list leakage), or extend `TenantIsolationHarness` for an
   in-process surface.
3. Run `cargo test --locked -p tenkai-http tenant_routes` and
   `cargo test --locked --lib tenant_isolation`.

Unauthenticated health probes (`/healthz`, `/readyz`) are not tenant-visible
and are not registered.

### Tenant-mode HTTP routes

| RPC id | Route | Tenant-mode enforcement |
| --- | --- | --- |
| `management.reconcile` | `POST /v1/reconcile` | Require tenant context; resolve tenant envs before bounded work selection |
| `management.fleet_status` | `GET /v1/fleet/status` | Filter rows to tenant envs |
| `management.package_migration_preview` | `POST /v1/migrations/{name}/preview` | Require tenant context; non-disclosing deny on cross-tenant env |
| `management.package_migration_apply` | `POST /v1/migrations/{name}/apply` | Same as preview; mutating verb |
| `management.package_migration_status` | `GET /v1/migrations/{name}` | Non-disclosing deny when the stored env is not visible |
| `management.package_migration_list` | `GET /v1/migrations` | List only migrations whose environment is visible to the tenant |
| `management.package_migration_resume` | `POST /v1/migrations/{name}/resume` | Same as apply |
| `management.package_migration_rollback` | `POST /v1/migrations/{name}/rollback` | Same as apply |
| `environment.list` | `GET /v1/environments` | List only tenant partition ids |
| `environment.get` | `GET /v1/environments/{env}` | Non-disclosing deny on cross-tenant |
| `environment.status` | `GET /v1/environments/{env}/status` | Same as get |
| `environment.dependencies` | `GET /v1/environments/{env}/dependencies` | Same as get |
| `environment.history` | `GET /v1/environments/{env}/history` | Same as get |
| `environment.runtime` | `GET /v1/environments/{env}/runtime` | Same as get |
| `environment.retire` | `POST /v1/environments/{env}/retire` | Require management capability and tenant visibility; preserve tenant retirement evidence |
| `environment.delivery_hold` | `GET /v1/environments/{env}/hold` | Read from the caller's tenant-bound catalog; a foreign id reads as empty |
| `catalog.list_releases` | `GET /v1/releases` | List the caller's tenant-bound hub catalog (ADR 0038) |
| `catalog.list_channels` | `GET /v1/channels` | Same as releases |
| `catalog.advisory_feed` | `GET /v1/advisory-feed` | Match against the caller's tenant-bound catalog |
| `catalog.product_criticality` | `GET /v1/products/{product}/criticality` | Same as releases |
| `catalog.product_owner` | `GET /v1/products/{product}/owner` | Same as releases |
| `catalog.product_webhooks` | `GET /v1/products/{product}/webhooks` | Same as releases |
| `catalog.channel_hold` | `GET /v1/products/{product}/channels/{channel}/hold` | Same as releases |
| `event.list` | `GET /v1/events` | Page the caller tenant's change events; other partitions stay invisible |
| `runtime.work` / `complete` / `heartbeat` / `inventory` | `/v1/runtime/environments/{env}/…` | Runtime credential scoped to exactly one environment |
| `development.fixture_import` | `POST /v1/development/fixtures/import` | Require tenant context and an allowlisted fixture principal; mounted only when fixtures are enabled |
| `development.fixture_reset` | `DELETE /v1/development/fixtures/{fixture_id}` | Same as import; non-disclosing deny on cross-tenant |

Remote management lifecycle routes (`POST /v1/releases`,
`POST /v1/channels/{channel}/promote`, `POST /v1/releases/{release}/recall`,
`POST /v1/products/{product}/recall-range`,
`POST /v1/products/{product}/recall-range/close`,
`POST /v1/environments/{environment}/subscriptions`,
`POST /v1/environments/{environment}/plans`, `POST /v1/plans/{plan_id}/approve`,
`POST /v1/plans/{plan_id}/apply`, `POST /v1/environments/{environment}/apply/cancel`,
`POST /v1/environments/{environment}/rollback`) are not tenant HTTP RPCs.
Tenant-mode hosts refuse them rather than writing a shared catalog.

**Registered but not exposed on HTTP** (harness / in-process enterprise surfaces only):

- `catalog.list_products`, `catalog.get_product`
- `plan.list`, `plan.get`
- `deployment.list`, `agent.list`
- `aggregate.status`, `aggregate.counts`, `aggregate.metric_labels`,
  `aggregate.cache_lookup`, `aggregate.audit_list`

Community tenant-free profile remains the default.

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
- Optional in-tree PostgreSQL (`crates/tenkai-postgres`, Cargo feature
  `postgres`) is documented in [postgres-tenant-store.md](postgres-tenant-store.md).
  Community default remains SQLite; the adapter is not a supported operating
  profile until ADR 0010 readiness passes.

Run `InMemoryTenantOperationalStore::run_conformance` (or
`cargo test --locked tenant_store`) to exercise harness coverage plus store-partition
isolation.

## Live management HTTP (tenant mode)

When `ServerConfig.requirements.tenant_mode` is true and a
`tenant_store` (`InMemoryTenantOperationalStore` or equivalent) is configured:

| Route | Isolation |
| --- | --- |
| `GET /v1/environments` | Lists only the authenticated tenant's environments |
| `GET /v1/environments/{environment}` | Cross-tenant ids → non-disclosing `resource not found` |
| `GET /v1/environments/{environment}/status` | Same non-disclosing deny |
| `GET /v1/environments/{environment}/dependencies` | Same non-disclosing deny |
| `GET /v1/environments/{environment}/history` | Same non-disclosing deny |
| `GET /v1/events` | Pages only the caller tenant's change events |
| `POST /v1/environments/{environment}/retire` | Authenticated tenant management capability; retirement is isolated to that tenant |

Community tenant-free hosts leave `tenant_mode` false and `tenant_store` unset.
Startup fails closed if tenant mode is requested without store + capability.

## Relationship to community mode

Community hosts use `AuthHostConfig::community()` and never attach tenant
context. They are not expected to pass the enterprise harness surface; the
harness itself starts in enterprise auth mode and fails closed without a
required extension.
