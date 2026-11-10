# Hub failover runbook (#750)

This is the failover procedure for a tenant-mode hub run as several replicas
over one PostgreSQL database (`--tenant-mode --replica-count N`, N > 1). One
replica leads and writes; the others stand by. Failover is the hub writer
lease ([#748](https://github.com/Sannrox/tenkai/issues/748)) moving to a
standby, which happens on its own. This runbook is how to see it, check it,
and undo it.

Status: the procedure is exercised by the kill-the-leader drill
([#749](https://github.com/Sannrox/tenkai/issues/749)) on every change, and
by the hub HA qualification drill ([#903](https://github.com/Sannrox/tenkai/issues/903)).
The `enterprise-experimental` profile it belongs to is selectable
(`--require-enterprise-profile`) and remains experimental (ADR 0010,
amendment of 2026-10-29, #647). Product `high_availability` is not claimed.
A release must pass the qualification drill before advertising it.

## Qualification criteria (#903)

The hub qualifies for a later `high_availability` claim only when all of
these hold on the current build:

1. Two replica processes share one PostgreSQL hub and apply two environments.
2. Killing the active writer mid-step, the standby takes the lease within
   the writer lifetime plus one renewal (the same bound as #749).
3. Each in-flight step finishes or rolls back exactly once: one receipt per
   step, no double-apply.
4. Replacing the replica processes on the same store and repeating the
   drill still passes. The automated drill uses the current binary; it
   proves the store remains usable after process replacement. Rolling a
   host back to a previous release binary is the operator procedure
   below, not this command.
5. A fenced stop/resume of the writer refuses the superseded commit as
   `not the active hub writer`. The same run with the writer fence left
   unset lets the stalled step commit.

CI runs this on every change (`Failover drill` job). One command, ephemeral
ports via `TENKAI_POSTGRES_URL`, and a per-run database:

```bash
TENKAI_POSTGRES_URL='postgresql://…?sslmode=disable' \
  bash scripts/hub-ha-qualification-drill.sh
```

The command writes signed evidence (`tenkai.hub-ha-qualification.v1`) and
the run's public key beside it (`<file>.pub`). The signature binds this
drill's statement; it is not a release-signing key. Verify offline,
without Postgres:

```bash
bash scripts/hub-ha-qualification-drill.sh --verify "$TENKAI_HA_DRILL_OUT"
```

Soft: #874 and #870 can make takeover timing noisy; record the measured
`takeover_ms` against `takeover_bound_ms` with those Issues open.

## Before you start

- Every replica runs the same binary with the same `TENKAI_POSTGRES_URL` and
  `--replica-count`, and its own `TENKAI_INSTANCE_ID`.
- The load balancer or proxy in front of the hub routes only to replicas
  whose `GET /readyz` answers `200`. A standby answers `503`
  (`standby: another replica holds the hub writer lease`) while `/healthz`
  stays `200`, so it is kept running but sent no traffic.
- Logs from every replica are collected; the lease writes one
  `tenkai.writer_lease role=…` line per change of role.

## Detection

| Signal | Leader | Standby |
| --- | --- | --- |
| `GET /readyz` | `200` | `503` standby |
| `GET /healthz` | `200` | `200` |
| Last `tenkai.writer_lease` line | `role=leader generation=<n>` | `role=standby` |
| Reconcile, webhook, digest and host-watch loops | run | skip their ticks |

Failover has happened when a different replica logs `role=leader` with a
higher generation and answers `/readyz` `200`. Exactly one replica answers
`200` at a time; two `200` answers, or none for longer than 20 seconds (the
lease lifetime plus one renewal), is the condition to act on.

## Lease takeover

Nothing needs to be done to fail over. The lease lives 15 seconds and the
leader renews it every five. A standby takes it at the next generation when:

- the leader process dies or its host goes away: within 15 seconds plus one
  renewal;
- the leader shuts down cleanly: on the standby's next renewal, because the
  leader releases the lease after draining;
- the leader's own store connections fail: on the standby's next renewal,
  because the leader steps down;
- the leader stalls (paused, partitioned): within 15 seconds plus one
  renewal; its writes are refused once its lease has lapsed, and any
  transaction it left open on the lease row is ended by the database after
  five seconds.

A leader that comes back after losing the lease cannot commit: every write
checks the lease holder and generation in its own transaction and is refused
as `not the active hub writer`.

## Verification after a failover

1. Exactly one replica answers `/readyz` `200`, and it logged
   `role=leader generation=<n>` with `n` greater than the previous leader's.
2. The former leader, if it is still running, logs `role=standby` and
   answers `/readyz` `503`.
3. `GET /v1/fleet/status` answers from the new leader and reconcile ticks
   appear in its log.
4. Work the old leader had in flight is picked up by the new leader once the
   old environment lease expires. Recorded receipts are not repeated: a step
   has at most one receipt, and steps the new leader applies carry a later
   environment lease generation.
5. Tenant isolation still holds: a cross-tenant list or get is not
   disclosed.

If step 1 fails, check that every replica reaches the same database and that
their clocks are not the issue: expiry is judged by the database clock, so
replica clock skew does not change who leads.

## Rollback

- **Return leadership to a replica.** Stop the current leader cleanly
  (`SIGTERM`). It drains, releases the lease, and the next standby to renew
  leads. There is no manual lease edit; do not write to
  `tenkai_hub_writer_lease` by hand.
- **Roll back a binary.** Replace standbys first, then stop the leader so a
  replica on the previous binary takes over. Both binaries must share the
  schema compatibility window (ADR 0010 upgrade path).
- **Restore the database.** Stop every replica, restore one PostgreSQL
  recovery point, start a single replica, verify readiness and fleet status,
  then start the others ([dump and restore](multi-replica-hub-runbook.md)).

## Evidence

| Evidence | Where |
| --- | --- |
| One fenced writer, takeover at the next generation, stale writes refused | `live_writer_lease` test (#748) |
| Leader killed, and stopped then resumed, inside a write; takeover within the bound; one receipt per step; the resumed commit refused | `live_failover_drill` (#749), CI job `Failover drill` |
| Two environments; kill the writer; takeover; exactly-once receipts; repeat after replacing current-binary replica processes; unfenced stall step commits | `live_ha_qualification_drill` (#903), `bash scripts/hub-ha-qualification-drill.sh` |
| Standby is live and not ready | `a_standby_replica_is_live_but_not_ready` (#748) |
| PostgreSQL is the sole store; catalog and terminal-outcome export live in each tenant schema; startup names any missing surface | `--require-enterprise-profile` (#747, #764, #765) |

Related: [multi-replica compose steps](multi-replica-hub-runbook.md),
[multi-host reconcile ticks](reconcile-tick-fencing.md),
[ADR 0010](decisions/0010-supported-operating-profiles.md).
