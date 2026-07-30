# Multi-replica PostgreSQL integration lab (#130)

This runbook exercises component-level PostgreSQL tenant isolation, shared
replica state, and reconcile fencing for the **Tenkai hub** (`tenkai-server`),
not environment runtimes. It is a conformance lab, not a supported operating
profile, product HA claim, failover procedure, or complete backup and recovery
contract.

The commands compose PostgreSQL tenant state with SQLite-backed non-tenant
application state. That mixed-store diagnostic composition cannot activate the
gated `enterprise-experimental` profile until PostgreSQL is the sole
authoritative store and all readiness evidence in
[ADR 0010](decisions/0010-supported-operating-profiles.md) exists. The supported
profile contract remains `local` by default and experimental single-server
`fleet` for remote runtime operation.

The lab assumes:

| Prerequisite | Reference |
| --- | --- |
| Postgres multi-tenant hub store | [postgres-tenant-store.md](postgres-tenant-store.md), #111 |
| Server wires tenant mode → Postgres | #127 |
| `shared_replica_state` (single-active writer) | #128 |
| Reconcile tick fencing | [reconcile-tick-fencing.md](reconcile-tick-fencing.md), #129 |
| Replica and HA capability semantics | [ADR 0009](decisions/0009-multi-replica-reconcile-and-ha-profile.md) |
| Supported operating-profile contract | [ADR 0010](decisions/0010-supported-operating-profiles.md) |

## Component guarantees and limits

| Component evidence exercised by this lab | **Not** guaranteed |
| --- | --- |
| Shared durable tenant state in Postgres | One complete authoritative operational store |
| Capability gate for `--replica-count > 1` | Multi-active concurrent writers without fencing |
| Tick fence so two hosts do not double-reconcile the same env | Automatic multi-AZ product packaging |
| Manual role-switch and PostgreSQL dump/restore exercises | Supported failover, backup, or recovery profile |
| Tenant isolation conformance | Product HA inside canary/stage/prod |

**Single-active writer component model:** at most one control-plane process
should actively reconcile and mutate the tested tenant state. Lab peers share
`TENKAI_POSTGRES_URL`. Tick fencing (`SharedReconcileFence` /
`ReconcileTickFence`) reduces double-reconcile races when more than one process
is live. SQLite still owns other authoritative state, so this composition has
no single transaction, backup, restore, or cutover boundary.

## Prerequisites

```bash
# Build with Postgres adapter
cargo build --features postgres --bin tenkai-server

# Required secrets (env only — never argv)
export TENKAI_MANAGEMENT_TOKEN='…'          # management bearer
export TENKAI_POSTGRES_URL='postgres://tenkai:tenkai@127.0.0.1:5432/tenkai'
# Optional stable instance id (defaults to random UUID)
export TENKAI_INSTANCE_ID='hub-1'
# Optional runtime credentials JSON
export TENKAI_RUNTIME_TOKENS='{}'
```

Flags:

| Flag | Role |
| --- | --- |
| `--tenant-mode` | Requires Postgres hub store (#127) |
| `--replica-count N` (`N > 1`) | Requires `shared_replica_state` (#128); enables shared tick fence (#129) |
| `--listen 127.0.0.1:PORT` | Plaintext HTTP remains loopback-only |

## Local lab (docker Postgres + two hubs)

### 1. Start Postgres

```bash
docker run --rm --name tenkai-pg \
  -e POSTGRES_PASSWORD=tenkai -e POSTGRES_USER=tenkai -e POSTGRES_DB=tenkai \
  -p 5432:5432 postgres:16
```

### 2. Start primary hub

```bash
export TENKAI_INSTANCE_ID=hub-1
export TENKAI_MANAGEMENT_TOKEN=lab-management-token
export TENKAI_POSTGRES_URL='postgres://tenkai:tenkai@127.0.0.1:5432/tenkai'

cargo run --features postgres --bin tenkai-server -- \
  --tenant-mode \
  --replica-count 2 \
  --listen 127.0.0.1:8080 \
  --database .tenkai-state/hub-1.db
```

Expect diagnostic composition identifier `enterprise-tenant-postgres` and
capabilities including `tenant_isolation` and `shared_replica_state`. That
identifier reports the current low-level composition; it is not the
`enterprise-experimental` operating profile defined by ADR 0010.

### 3. Start secondary lab peer

```bash
export TENKAI_INSTANCE_ID=hub-2
# same TENKAI_POSTGRES_URL and TENKAI_MANAGEMENT_TOKEN

cargo run --features postgres --bin tenkai-server -- \
  --tenant-mode \
  --replica-count 2 \
  --listen 127.0.0.1:8081 \
  --database .tenkai-state/hub-2.db
```

Notes:

- Local SQLite paths may still be used for non-tenant application paths; tenant
  isolation uses Postgres schemas `tenkai_t_*`.
- With `--features postgres`, `TENKAI_POSTGRES_URL`, and `replica_count > 1`,
  both hosts use the durable Postgres `ReconcileTickFence`. Distinct
  `TENKAI_INSTANCE_ID` values are required.

### 4. Verify management plane

```bash
curl -sS -H "Authorization: Bearer lab-management-token" \
  http://127.0.0.1:8080/readyz
curl -sS -H "Authorization: Bearer lab-management-token" \
  http://127.0.0.1:8080/v1/fleet/status
```

Do not print tokens in logs or commit them.

## Manual role-switch conformance drill

This drill tests shared tenant state and fencing only. It is not evidence for a
supported failover or recovery profile because each host still has independent
SQLite-backed application state.

1. Confirm primary (`hub-1`) is healthy (`/readyz`, reconcile log lines).
2. Stop primary (`Ctrl+C` or kill the process).
3. Ensure the second peer (`hub-2`) is running with the **same** `TENKAI_POSTGRES_URL`.
4. Point the reverse proxy / operator `TENKAI_SERVER_URL` at the secondary listen
   address.
5. Re-check `/readyz`, `fleet status`, and one `reconcile` tick.
6. Confirm tenant isolation still holds (cross-tenant list/get non-disclosing).

If both hubs were left running, tick fencing reduces double-reconcile risk for
the same environment when both share a fence; with per-process fences only,
**stop the old writer** before treating the standby as sole active.

## PostgreSQL component dump and restore exercise

This exercise covers the PostgreSQL tenant schemas used by the lab. It does not
capture the SQLite-backed application state and therefore is not a complete
Tenkai backup, restore, or enterprise recovery procedure.

### Backup

```bash
# Logical dump (includes all tenant schemas tenkai_t_*)
pg_dump "$TENKAI_POSTGRES_URL" -Fc -f tenkai-hub-$(date +%Y%m%d).dump
```

Treat dumps as sensitive (environment topology, operational metadata).

### Restore

1. Stop all hub writers using this database.
2. Restore into an empty database:

```bash
pg_restore -d "$TENKAI_POSTGRES_URL" --clean --if-exists tenkai-hub-YYYYMMDD.dump
```

3. Start a single hub first; verify `/readyz` and inspect.
4. Re-inject management/runtime tokens from the secret store (never stored in DB).
5. Only then start additional lab peers.

SQLite `tenkaictl backup` / `restore` remains the community embedded path; it is
**not** a substitute for a complete enterprise PostgreSQL backend. Conversely,
the PostgreSQL dump above is not a substitute for backing up the mixed
composition's SQLite state.

## Durable tick fence (#135)

With `--features postgres` and `TENKAI_POSTGRES_URL`, multi-replica hosts use
hub table `tenkai_reconcile_tick_claims` for environment tick ownership. Claims
survive process restart; another host only takes over after TTL expiry or an
explicit release. Without Postgres, fencing is process-memory only and is not
safe across machines.

See [reconcile-tick-fencing.md](reconcile-tick-fencing.md).
Mutation-level replay and stale-generation evidence:
[fenced delivery-effect conformance](delivery-effect-conformance.md).

## Explicit non-guarantees

- Community SQLite is not multi-replica safe; `--replica-count > 1` fails closed
  without `shared_replica_state`.
- Environment runtime HA (k8s pods, VMs) is outside this runbook.
- Identity-plane / IdP databases must never be co-located with Tenkai ops DB
  (ADR 0005 / 0008).
- `high_availability` product flag is separate from `shared_replica_state` and
  is not claimed by the Postgres adapter by default.
- No complete operating profile currently admits multiple server replicas;
  `enterprise-experimental` remains gated by ADR 0010's single-store parity and
  readiness evidence.

## Related docs

- [postgres-tenant-store.md](postgres-tenant-store.md)
- [reconcile-tick-fencing.md](reconcile-tick-fencing.md)
- [runtime-capabilities.md](runtime-capabilities.md)
- [backup-restore.md](backup-restore.md) (SQLite embedded)
- [ADR 0009](decisions/0009-multi-replica-reconcile-and-ha-profile.md)
- [ADR 0010](decisions/0010-supported-operating-profiles.md)
