# Optional PostgreSQL tenant OperationalStore integration

Postgres is the **sole authoritative store** for tenant-mode `tenkai-server`
hubs compiled with `--features postgres`. Community and spoke hosts keep
SQLite. Supplying both `--database` / `TENKAI_DATABASE` and
`TENKAI_POSTGRES_URL` is refused (ADR 0010). This adapter is for the
**Tenkai hub** (control plane), not for remote environment agents.

[ADR 0010](decisions/0010-supported-operating-profiles.md) defines the supported
profiles. The default `local` profile and experimental single-server `fleet`
profile use SQLite. Tenant-mode hubs assemble diagnostic profile
`enterprise-experimental` from PostgreSQL plus authentication. Catalog
object-graph lifecycle lives in each tenant schema (ADR 0038). Terminal-outcome
export enqueues `provider_events` in that same tenant schema with the catalog
write.

| Role | Store |
| --- | --- |
| Community / solo | SQLite (`SqliteStore`) — default |
| Enterprise hub (`--tenant-mode`) | PostgreSQL sole store (`tenkai_hub` plus `tenkai_t_*`) |
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
| Not claimed yet | Product `high_availability` |

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

- Use Postgres-native backup (`pg_dump` / continuous archiving) of the hub
  database. The dump includes hub schema `tenkai_hub` and tenant schemas
  `tenkai_t_*`.
- A lab restore stops writers, restores that database, starts one server, and
  verifies `/readyz`.
- In tenant mode `TENKAI_BACKUP_DIR` holds recorded backup evidence only
  ([PostgreSQL backup evidence](backup-restore.md#postgresql-backup-evidence));
  SQLite `tenkaictl backup` is the community path.
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
| `--tenant-mode` + `--database` / `TENKAI_DATABASE` | Startup fails: mixed SQLite and PostgreSQL configuration is refused |
| `--tenant-mode` + feature + URL | Opens PostgreSQL as the sole store; diagnostic profile `enterprise-experimental` |

In-memory adapter remains for unit tests (`ServerConfig.tenant_store = Some(Arc::new(InMemory…))`).

`--replica-count > 1` passes capability negotiation when the Postgres hub store
is composed (#128). Multi-active reconcile uses tick fencing (#129). Catalog
lifecycle and terminal-outcome export share one tenant-schema transaction.
`--outcome-provider chisei` starts on a tenant-mode hub and drains each tenant
outbox, allocating `source_sequence` from the hub producer identity. Catalog
enqueue stamps the tenant into the outcome payload so exported event IDs stay
distinct across tenants. Product
`high_availability` remains unclaimed. Lab steps:
[multi-replica-hub-runbook.md](multi-replica-hub-runbook.md) (#130).
