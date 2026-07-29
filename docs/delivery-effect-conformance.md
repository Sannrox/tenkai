# Fenced delivery-effect conformance

Issue: [#180](https://github.com/Sannrox/tenkai/issues/180). Decision:
[ADR 0009](decisions/0009-multi-replica-reconcile-and-ha-profile.md).

Tenkai provides at-least-once command and work delivery. It does not claim
exactly-once transport. A repeated command is safe only when the authoritative
store or the environment target enforces the stable identity below.

| Path | Stable identity | Duplicate outcome | Fence |
| --- | --- | --- | --- |
| Release publication | release ID + immutable content | Same release is returned as already recorded; changed content conflicts | Immutable row |
| Channel promotion | channel ID + expected revision + target release | Concurrent identical promotion returns the recorded next revision | Revision compare-and-set |
| Plan creation | plan ID + immutable digest/body | Concurrent identical plan produces one row | Immutable row |
| Apply receipt | receipt ID + plan/step/payload | Replay returns the stored receipt, including after process loss | Environment lease generation |
| Rollback | rollback ID + immutable initial checkpoint/intent | Replay accepts only identical intent | Environment lease generation |
| Reconcile admission | environment + monotonically increasing generation | One live owner; another replica is busy | Durable tick claim and execution lease |

The PostgreSQL conformance test opens two independent store connections against
one tenant partition, races publication and promotion, replays a committed
receipt through a restarted connection, forces deterministic lease expiry,
hands work to a new owner, and rejects stale plan, receipt, and rollback
commits. It also asserts one durable channel, plan, receipt, and rollback:

```bash
export TENKAI_POSTGRES_URL='postgresql://127.0.0.1:5432/tenkai_test'
cargo test --features postgres \
  live_postgres_delivery_effects_are_idempotent_and_fenced \
  -- --ignored --nocapture
```

## Bounded operational evidence

- `env inspect` exposes the active execution lease and current generation
  without credentials.
- `fleet status` exposes bounded lease and unknown deployment posture.
- `GET /metrics` exposes low-cardinality reconcile busy/failure counters.
- PostgreSQL tick claims retain an expired tombstone so generation never resets
  after release. A stale generation cannot match a later owner.
- Immutable receipt and rollback conflicts are explicit store errors. The
  conformance test counts durable rows rather than logging tenant payloads.

## Unsupported claims

Tenkai cannot make a generic shell command or third-party target atomic with its
PostgreSQL commit. Environment executors must durably deduplicate the supplied
`--idempotency-key` before mutation. A lost executor response is an unknown
target outcome and must be reconciled; Tenkai does not blindly repeat it.

Consequently, the PostgreSQL adapter continues to advertise
`shared_replica_state` but not `high_availability`. Product HA requires
target-side conditional writes or a proven executor for every enabled mutation
path, plus operational failover evidence.
