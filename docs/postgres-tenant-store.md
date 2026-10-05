# Optional PostgreSQL tenant OperationalStore integration

Postgres is an **optional**, component-level multi-tenant store adapter for the
**Tenkai hub** (`tenkai-server` / control plane), not for remote environment
agents. The current server composition keeps non-tenant application state in
SQLite, so this adapter is test-only integration evidence rather than a
supported operating profile or complete recovery backend.

[ADR 0010](decisions/0010-supported-operating-profiles.md) defines the supported
profiles. The default `local` profile and experimental single-server `fleet`
profile use SQLite. The gated `enterprise-experimental` profile cannot activate
until PostgreSQL is the sole authoritative store and every ADR 0010 readiness
requirement passes.

| Role | Store |
| --- | --- |
| Community / solo | SQLite (`SqliteStore`) — default |
| Tenant-store integration and conformance | Optional Postgres (`PostgresTenantOperationalStore`) |
| Conformance without Postgres | In-memory tenant partitions (`InMemoryTenantOperationalStore`) |

Source: `crates/tenkai-postgres`. Decision: [ADR 0008](decisions/0008-production-tenant-operational-store.md).
HA multi-replica: [ADR 0009](decisions/0009-multi-replica-reconcile-and-ha-profile.md).
Operating profiles: [ADR 0010](decisions/0010-supported-operating-profiles.md).

## Shared replica state (#128)

This adapter advertises:

```text
store.tenant_postgres:
  - tenant_isolation:v1
  - shared_replica_state:v1
  - operational_store_migration:v1:levelN
```

**Writer model (locked first slice):** `SingleActiveWriter` — one active
control-plane writer against the shared PostgreSQL tenant-state component, with
a cold lab peer available for conformance drills. It does **not** mean
multi-active concurrent reconcile without tick fencing (#129), a complete
shared application store, or supported failover. It does **not** advertise
`high_availability` (product HA remains separate per ADR 0009).

| Claim | Meaning |
| --- | --- |
| `shared_replica_state` | Shared durable state for this adapter; sufficient for single-active-writer component tests |
| Tick fence table | `tenkai_reconcile_tick_claims` for multi-host reconcile (#135); not a HA product claim |
| Not claimed yet | Complete PostgreSQL authority, product `high_availability`, supported failover or recovery |

Community SQLite never advertises `shared_replica_state`.
The two-connection mutation and lease-handoff proof is documented in
[fenced delivery-effect conformance](delivery-effect-conformance.md).

## Isolation model

**Schema-per-tenant** inside one Tenkai-owned database:

```text
database tenkai
  tenkai_meta              # adapter schema version
  tenkai_t_tenant_a.*      # full operational tables
  tenkai_t_tenant_b.*
```

Cross-tenant reads use non-disclosing deny (`resource not found`). Never put
identity-plane tables in this database (ADR 0005).

## Build and configure

```bash
# Compile with the optional adapter (add `ui` to embed the console)
cargo build -p tenkai-server --features postgres

# Connection string via env only (not argv)
export TENKAI_POSTGRES_URL='postgres://tenkai:tenkai@127.0.0.1:5432/tenkai'
```

Without `--features postgres`, `PostgresTenantConfig::open` fails closed with an
actionable rebuild message. Community binaries stay SQLite-only.

### Transport security

Tenant data and store credentials leave the host only over verified TLS:

| URL hosts | Result |
| --- | --- |
| Every host (and `hostaddr`) is loopback or a unix socket | The URL's `sslmode` applies; `sslmode=disable` is allowed |
| Any other host, `sslmode` unset, `prefer`, or `require` | TLS is required |
| Any other host, `sslmode=disable` | Connect fails closed before dialing |

Server certificates are always verified against the Mozilla roots plus the
platform trust store. Point `SSL_CERT_FILE` or `SSL_CERT_DIR` at a private CA
bundle (for example a managed database provider's CA) to trust it. There is no
option that skips verification.

Each Postgres store connection owns one handle-free worker thread. Connection
setup, transactions, health checks, and reconcile fencing all run on that
thread, so the synchronous `postgres` client never starts its runtime inside a
Tokio runtime. Calls are serialized through a zero-capacity channel, preserving
the adapter's single-connection serialization without creating a thread for
each operation.

## Local Postgres for drills

```bash
docker run --rm -e POSTGRES_PASSWORD=tenkai -e POSTGRES_USER=tenkai \
  -e POSTGRES_DB=tenkai -p 5432:5432 postgres:16

export TENKAI_POSTGRES_URL='postgres://tenkai:tenkai@127.0.0.1:5432/tenkai'
cargo test --locked -p tenkai-postgres --features postgres live_postgres_tenant_isolation -- --ignored --nocapture
```

Default CI does **not** require a Postgres service. Live tests are `#[ignore]`.

## Component backup notes

- Use Postgres-native backup (`pg_dump` / continuous archiving) to exercise
  backup of the adapter's tenant schemas.
- Document tenant schema names (`tenkai_t_*`) in ops runbooks.
- A lab restore stops writers, restores the PostgreSQL component, starts one
  server, and verifies `/readyz`.
- This does not restore SQLite-backed releases, channels, environments, plans,
  execution, receipts, rollback, or other non-tenant application state. It is
  therefore not an enterprise backup, cutover, or recovery contract.
- Do not confuse with environment runtime state or identity-plane backups.

## `tenkai-server` wiring (#127)

```bash
cargo build -p tenkai-server --features postgres,ui

export TENKAI_MANAGEMENT_TOKEN=…
export TENKAI_POSTGRES_URL='postgres://tenkai:tenkai@127.0.0.1:5432/tenkai'

# Tenant mode selects Postgres hub store (fails closed without URL/feature)
tenkai-server --tenant-mode --listen 127.0.0.1:8080
```

Published GitHub Releases attach this host as `tenkai-server-postgres-<platform>`
([release binaries](release-binaries.md#hub-postgres)). `tenkai-server --help`
reports `Compiled features: postgres, ui`.

Rules:

| Condition | Result |
| --- | --- |
| No `--tenant-mode` on a community host (no `postgres` feature) | Community path; `tenant_store` unset |
| No `--tenant-mode` on a `postgres`-feature hub host | Startup fails: this is not the community SQLite host |
| `--tenant-mode` without feature | Startup fails: rebuild with `--features postgres` |
| `--tenant-mode` without `TENKAI_POSTGRES_URL` | Startup fails closed |
| `--tenant-mode` + feature + URL | Wires `PostgresTenantOperationalStore`; diagnostic composition `enterprise-tenant-postgres` |

In-memory adapter remains for unit tests (`ServerConfig.tenant_store = Some(Arc::new(InMemory…))`).

`--replica-count > 1` passes capability negotiation when the Postgres hub store
is composed (#128). Multi-active reconcile uses tick fencing (#129). These
component claims do not activate `enterprise-experimental`; the mixed-store
path must remain a diagnostic/conformance composition until PostgreSQL owns
every authoritative surface and ADR 0010 readiness evidence exists. Lab steps:
[multi-replica-hub-runbook.md](multi-replica-hub-runbook.md) (#130).
