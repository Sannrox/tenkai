# Multi-replica PostgreSQL integration lab (#130)

This runbook exercises component-level PostgreSQL tenant isolation, shared
replica state, and reconcile fencing for the **Tenkai hub** (`tenkai-server`),
not environment runtimes. It is a conformance lab, not a supported operating
profile, product HA claim, failover procedure, or complete backup and recovery
contract.

The commands open PostgreSQL as the sole hub store (`tenkai_hub` plus
`tenkai_t_*`). Mixed `--database` / `TENKAI_DATABASE` with `TENKAI_POSTGRES_URL`
is refused. Catalog object-graph lifecycle (#764) and terminal-outcome export
(#765) remain unavailable. The supported profile contract remains `local` by
default and experimental single-server `fleet` for remote runtime operation.
`--require-enterprise-profile` (with `--tenant-mode`) asks for the supported
`enterprise-experimental` profile instead of this lab. It refuses to start
while PostgreSQL does not own every authoritative surface, and names each
missing one.

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
| Shared durable hub and tenant state in Postgres | Catalog object-graph lifecycle |
| Capability gate for `--replica-count > 1` | Multi-active concurrent writers without fencing |
| Tick fence so two hosts do not double-reconcile the same env | Automatic multi-AZ product packaging |
| Manual role-switch and PostgreSQL dump/restore exercises | Product HA or automatic failover |
| Tenant isolation conformance | Terminal-outcome export |

**Single-active writer component model:** at most one control-plane process
should actively reconcile and mutate the tested tenant state. Lab peers share
`TENKAI_POSTGRES_URL`. Tick fencing (`SharedReconcileFence` /
`ReconcileTickFence`) reduces double-reconcile races when more than one process
is live. PostgreSQL dump/restore is the hub recovery path.

## Prerequisites

```bash
# Build with Postgres adapter and the pinned console
cargo build -p tenkai-server --features postgres,ui

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

cargo run -p tenkai-server --features postgres,ui -- \
  --tenant-mode \
  --replica-count 2 \
  --listen 127.0.0.1:8080
```

Expect diagnostic profile `enterprise-experimental` and capabilities including
`tenant_isolation` and `shared_replica_state`. Catalog lifecycle stays
unavailable. Product `high_availability` is not claimed.

### 3. Start secondary lab peer

```bash
export TENKAI_INSTANCE_ID=hub-2
# same TENKAI_POSTGRES_URL and TENKAI_MANAGEMENT_TOKEN

cargo run -p tenkai-server --features postgres,ui -- \
  --tenant-mode \
  --replica-count 2 \
  --listen 127.0.0.1:8081
```

Notes:

- Both hosts open the same PostgreSQL database. Hub records live in
  `tenkai_hub`; tenant isolation uses schemas `tenkai_t_*`.
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

This drill tests shared hub state and fencing. It is a lab role-switch, not
product HA.

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

This exercise dumps the hub PostgreSQL database (`tenkai_hub` and
`tenkai_t_*`). Tokens are re-injected from the secret store after restore.

### Backup

```bash
# Logical dump (includes hub schema tenkai_hub and tenant schemas tenkai_t_*)
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

SQLite `tenkaictl backup` / `restore` remains the community embedded path.
Tenant-mode hubs refuse `TENKAI_BACKUP_DIR`.

## Hub writer lease (#748)

A tenant-mode hub started with `--replica-count` above 1 takes part in one
hub writer lease, a single row in `tenkai_hub_writer_lease` (holder,
generation, expiry). The generation only grows.

- **One writer.** The replica holding the lease leads. Every other replica is
  a standby: `/readyz` answers `503` with
  `standby: another replica holds the hub writer lease`, `/healthz` stays
  `200`, and the reconcile, webhook, SMTP digest and host-watch loops skip
  their ticks.
- **Fenced writes.** Every authoritative write checks, inside its own
  transaction, that the lease still names this replica at the generation it
  writes with and has not expired. A replica whose lease lapsed or was taken
  over cannot commit, even before it notices (`not the active hub writer`).
  A standby's writes are refused before they reach the database.
- **Takeover.** The leader renews every five seconds; the lease lives 15
  seconds. A replica whose renewal fails becomes a standby at once, and so
  does one whose renewal stalls past the lease's lifetime. Before renewing,
  the leader checks its own store connections; if they answer with an
  error, it releases the lease and does not ask again until they can. A
  check still waiting behind store work counts as busy and the leader
  renews, until no check has passed for 15 seconds. A transaction holding
  the lease row that goes idle is ended by the database after five
  seconds, so a paused replica cannot block a takeover; its connections
  reconnect on their next use. When the
  leader stops renewing, the next standby to renew takes the lease at the
  next generation, at most 15 seconds later. A leader that shuts down keeps
  renewing until its requests and loops have drained, then releases the
  lease, so a standby takes over on its next renewal.
- **Clock.** Expiry is judged by the database clock, so replicas with skewed
  clocks agree on who leads.
- The lease is tried once before the store opens, so a replica never writes
  before it knows whether it leads. Lines `tenkai.writer_lease role=leader
  generation=<n>` and `role=standby` log each change of role.
- Single-replica hubs have no lease and write as before.

This replaces stopping the old writer by hand in the drill above: two hubs
may run at once, and only the lease holder writes.

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
  is not claimed by the Postgres adapter by default. The writer lease (#748)
  gives one active writer with fenced takeover; it does not make this a
  supported HA profile.
- Catalog object-graph lifecycle and terminal-outcome export remain unavailable
  in tenant mode.

## Related docs

- [postgres-tenant-store.md](postgres-tenant-store.md)
- [reconcile-tick-fencing.md](reconcile-tick-fencing.md)
- [runtime-capabilities.md](runtime-capabilities.md)
- [backup-restore.md](backup-restore.md) (SQLite embedded)
- [ADR 0009](decisions/0009-multi-replica-reconcile-and-ha-profile.md)
- [ADR 0010](decisions/0010-supported-operating-profiles.md)
