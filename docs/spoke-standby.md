# Small-footprint dark-site spoke profile

A dark-site spoke runs SQLite with one writer ([ADR 0029](decisions/0029-hub-spoke-operational-store.md)).
The site often has one or two nodes. This profile says what happens when the
writer dies. It is not the hub profile ([ADR 0010](decisions/0010-supported-operating-profiles.md)
`enterprise-experimental`). Product `high_availability` stays unclaimed.

The lease vocabulary and the two-node rule come from the shared
`fencing-lease` crate.

## Static stability

Deployed workloads keep running on their last good release while the spoke
is down. New plans, applies and rollbacks pause until a writer is promoted.

## Warm standby

The second node restores [shipped backups](backup-restore.md) taken on the
stated interval (`backup_interval_ms`). That interval is the acknowledged-loss
bound: writes after the last shipped backup may be gone.

PostgreSQL on spokes and multi-writer SQLite are out of scope (ADR 0029).

## Promotion

Promotion is a signed operator action by default:

```bash
tenkaictl spoke-standby promote \
  --profile examples/spoke-standby/profile.toml \
  --holder spoke-b \
  --lease-dir .tenkai-state/spoke-lease \
  --state .tenkai-state/spoke \
  --signing-key "$PROMOTION_SEED"
```

Automatic promotion happens only with a witness vote or a storage-level
exclusive lock (a lock file every member mounts, a PostgreSQL row lock, or a
Kubernetes Lease). Two nodes and a timeout alone are refused.

On promotion the old generation is fenced. Site runtimes refuse work that
presents it. Receipts restored from the backup are not executed again.

## Published bounds

The profile publishes, and the drill measures:

| Bound | Source |
| --- | --- |
| Interruption window | Time from killing the writer until the standby holds the next generation |
| Acknowledged-loss bound | `backup_interval_ms` |
| Remaining single points of failure | The surviving node, its SQLite file, the backup set, the promotion key |

The word "available" is reserved until a drill has passed.

## Drill

Two nodes, egress blocked:

```bash
tenkaictl spoke-standby validate --profile examples/spoke-standby/profile.toml
tenkaictl spoke-standby drill \
  --profile examples/spoke-standby/profile.toml \
  --signing-key "$DRILL_SEED" \
  --out spoke-standby-drill.json
```

The drill kills the writer, promotes the standby through the signed action,
checks that the restored apply is not executed twice, and checks that the old
generation is refused when that spoke returns. The evidence is
`tenkai.spoke-standby-drill.v1`, signed the same way as other operator drills
([#691](https://github.com/Sannrox/tenkai/issues/691)).

## Profile

```toml
version = 1
members = 2
backup_interval_ms = 300000
promotion = "manual"
exclusive_lock = false
witness = false
```

`members` is 1 or 2. `promotion = "auto"` is valid only with `exclusive_lock`
or `witness`. See [`examples/spoke-standby`](../examples/spoke-standby).
