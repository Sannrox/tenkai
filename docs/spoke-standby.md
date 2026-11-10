# Small-footprint dark-site spoke profile

A dark-site spoke runs SQLite with one writer ([ADR 0029](decisions/0029-hub-spoke-operational-store.md)).
The site often has one or two nodes. This profile says what happens when the
writer dies. It is not the hub profile ([ADR 0010](decisions/0010-supported-operating-profiles.md)
`enterprise-experimental`). Product `high_availability` stays unclaimed.

The writer lease is the environment lease in the spoke's own SQLite
operational store, and the writer role is the same one the hub uses. Each
applied step is a receipt stamped with the lease generation. The two-node
promotion rule comes from the shared `fencing-lease` crate.

## Static stability

Deployed workloads keep running on their last good release while the spoke
is down. New plans, applies and rollbacks pause until a writer is promoted.

## Warm standby

The second node restores [shipped backups](backup-restore.md) taken on the
stated interval (`backup_interval_ms`). That interval is the acknowledged-loss
bound: writes after the last shipped backup may be gone.

PostgreSQL on spokes and multi-writer SQLite are out of scope (ADR 0029).

## Promotion

Promotion is a signed operator action by default. Restore the last shipped
backup on the standby, then promote it:

```bash
tenkaictl spoke-standby promote \
  --profile examples/spoke-standby/profile.toml \
  --holder spoke-b \
  --environment site \
  --state .tenkai-state/spoke/tenkai.db \
  --lease-dir /var/lib/tenkai/spoke-locks \
  --signing-key "$PROMOTION_SEED"
```

Promotion takes over the restored lease once the old writer's lease has
lapsed, so the standby writes at the next generation. It is refused while
that lease is still live. The signed statement is written next to the store
as `<store>.promotion.json`. To roll back, restore the same backup again.

Restoring a backup rewinds its lease, so the generation cannot come from the
store alone. `--lease-dir` is a lock directory kept outside the backup and
used by every member: storage both spokes mount, or a directory the
operator moves to the promoting member. Each promotion claims it and gets a
higher fencing token, and the promoted generation starts from that token.
Promoting a restored or rolled-back copy, on either member, therefore still
fences every earlier promotion. Keep the directory across restores. Two
members with separate fresh directories can issue the same generation, and
runtimes cannot tell those writers apart.

Site runtimes are the fence: once they see a later generation they refuse
every earlier writer, whichever copy it runs on.

The statement is signed before the store changes and is stored with the
lease takeover in one transaction. A promotion that fails on the key leaves
the restored lease untouched. `<store>.promotion.json` is a copy of the
stored statement. Promoting a store whose lease is still live is refused,
even for the same holder. After a crash, wait for the lease to lapse and
promote again; the new promotion gets a later epoch.

Automatic promotion happens only with a witness vote or a storage-level
exclusive lock (a lock file every member mounts, a PostgreSQL row lock, or a
Kubernetes Lease). Two nodes and a timeout alone are refused.

On promotion the old generation is fenced. Site runtimes refuse work that
presents it, and the store refuses a receipt stamped with it. Receipts
restored from the backup are not executed again.

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
