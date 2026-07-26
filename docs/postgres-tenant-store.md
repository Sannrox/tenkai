# Optional PostgreSQL tenant OperationalStore (control-plane hub)

Postgres is an **optional** durable multi-tenant store for the **Tenkai hub**
(`tenkai-server` / control plane), not for remote environment agents.

| Role | Store |
| --- | --- |
| Community / solo | SQLite (`SqliteStore`) — default |
| Enterprise multi-tenant recovery | Optional Postgres (`PostgresTenantOperationalStore`) |
| Conformance without Postgres | In-memory tenant partitions (`InMemoryTenantOperationalStore`) |

Source: `src/postgres_tenant.rs`. Decision: [ADR 0008](decisions/0008-production-tenant-operational-store.md).
HA multi-replica: [ADR 0009](decisions/0009-multi-replica-reconcile-and-ha-profile.md) —
this adapter advertises **`tenant_isolation` only**, not `shared_replica_state`
or `high_availability`.

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
# Compile with the optional adapter
cargo build --features postgres

# Connection string via env only (not argv)
export TENKAI_POSTGRES_URL='postgres://tenkai:tenkai@127.0.0.1:5432/tenkai'
```

Without `--features postgres`, `PostgresTenantConfig::open` fails closed with an
actionable rebuild message. Community binaries stay SQLite-only.

## Local Postgres for drills

```bash
docker run --rm -e POSTGRES_PASSWORD=tenkai -e POSTGRES_USER=tenkai \
  -e POSTGRES_DB=tenkai -p 5432:5432 postgres:16

export TENKAI_POSTGRES_URL='postgres://tenkai:tenkai@127.0.0.1:5432/tenkai'
cargo test --features postgres live_postgres_tenant_isolation -- --ignored --nocapture
```

Default CI does **not** require a Postgres service. Live tests are `#[ignore]`.

## Backup notes

- Use Postgres-native backup (`pg_dump` / continuous archiving) for the hub DB.
- Document tenant schema names (`tenkai_t_*`) in ops runbooks.
- Restore is a hub cutover: stop writers, restore DB, start server, verify
  `/readyz` — same operational discipline as SQLite cutover, different tools.
- Do not confuse with environment runtime state or identity-plane backups.

## Capability advertisement

```text
store.tenant_postgres:
  - tenant_isolation:v1
  - operational_store_migration:v1:levelN
```

## `tenkai-server` wiring (#127)

```bash
cargo build --features postgres --bin tenkai-server

export TENKAI_MANAGEMENT_TOKEN=…
export TENKAI_POSTGRES_URL='postgres://tenkai:tenkai@127.0.0.1:5432/tenkai'

# Tenant mode selects Postgres hub store (fails closed without URL/feature)
tenkai-server --tenant-mode --listen 127.0.0.1:8080
```

Rules:

| Condition | Result |
| --- | --- |
| No `--tenant-mode` | Community path; `tenant_store` unset |
| `--tenant-mode` without feature | Startup fails: rebuild with `--features postgres` |
| `--tenant-mode` without `TENKAI_POSTGRES_URL` | Startup fails closed |
| `--tenant-mode` + feature + URL | Wires `PostgresTenantOperationalStore`; profile `enterprise-tenant-postgres` |

In-memory adapter remains for unit tests (`ServerConfig.tenant_store = Some(Arc::new(InMemory…))`).
Multi-replica reconcile remains blocked until a store claims `shared_replica_state`
with fencing (ADR 0009 / #128–#129).
