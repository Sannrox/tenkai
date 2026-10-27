# Hub failover runbook (#750)

This is the failover procedure for a tenant-mode hub run as several replicas
over one PostgreSQL database (`--tenant-mode --replica-count N`, N > 1). One
replica leads and writes; the others stand by. Failover is the hub writer
lease ([#748](https://github.com/Sannrox/tenkai/issues/748)) moving to a
standby, which happens on its own. This runbook is how to see it, check it,
and undo it.

Status: the procedure is exercised by the kill-the-leader drill
([#749](https://github.com/Sannrox/tenkai/issues/749)) on every change. The
`enterprise-experimental` profile it belongs to is still gated (ADR 0010,
amendment of 2026-10-27): until that gate passes, run multi-replica hubs as a
lab, not as a supported profile. Product `high_availability` is not claimed.

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
| Standby is live and not ready | `a_standby_replica_is_live_but_not_ready` (#748) |
| PostgreSQL is the sole store for the surfaces it owns; startup names the missing ones | `--require-enterprise-profile` (#747) |

Related: [multi-replica lab runbook](multi-replica-hub-runbook.md),
[reconcile tick fencing](reconcile-tick-fencing.md),
[ADR 0010](decisions/0010-supported-operating-profiles.md).
