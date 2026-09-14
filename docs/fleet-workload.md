# Synthetic thousand-environment workload

Tenkai can materialize a **deterministic** fleet of one thousand environments
for scale evidence (#299). This is not a support claim and does not skip
signing, approval, gates, leases, receipts, or recovery.

```bash
tenkaictl fleet generate \
  --seed demo-seed \
  --product scale-app \
  --channel stable \
  --current-version 1.1.0 \
  --behind-version 1.0.0
```

The product/channel must already exist from a **signed** publish and promote.
The same seed regenerates the same environment identities and posture counts:

| Posture | Count | Planted operational state |
| --- | --- | --- |
| `current` | 200 | subscribed, deployed at the current version |
| `behind` | 200 | subscribed, deployed at the behind version |
| `unhealthy` | 200 | subscribed, current version, unhealthy health |
| `blocked` | 200 | subscribed, required fact constraint unmet |
| `disconnected` | 200 | isolated connectivity class, no subscription |

Unknown postures, credential-like seeds, duplicate identities, and an
all-healthy mix fail closed. Partial materialization is never reported as a
complete thousand-environment fleet. Recovery uses `tenkaictl backup` /
`restore` only.

Budget measurement uses the named `ci-embedded-sqlite` profile (#300). Gates stay
enabled (`skip_gates=false`). Two reconcile ticks are timed; a miss names the
limiting resource and fails closed.

```bash
tenkaictl fleet measure \
  --seed demo-seed \
  --product scale-app \
  --channel stable \
  --current-version 1.1.0 \
  --behind-version 1.0.0
```

Fairness under planted unhealthy/blocked targets (#301):

```bash
tenkaictl fleet fairness \
  --seed demo-seed \
  --product scale-app \
  --channel stable \
  --current-version 1.1.0 \
  --behind-version 1.0.0 \
  --backup /tmp/tenkai-fairness.db
```

The offline fifty-spoke drill (`crate::offline_fleet_drill`) exports one signed
release payload to fifty isolated environments, applies without treating the
hub as reachable, rolls twenty-five back after injected health failure, and
checks that hub inspect/fleet posture matches each spoke's local
`deployed.<product>` evidence. Re-binding the same bundle is a no-op.

The report counts **behind plan progress** (`AwaitingApproval`/`Applied`/
`AwaitingRuntime`), not mere tick membership. Success receipts bind only to a
healthy behind plan; they never complete Unhealthy or Blocked restarts.
Failing environments must enter bounded `Deferred` backoff, must not apply,
and must not starve healthy cohorts. A held fencing generation reports
`Busy`. Duplicate receipts are idempotent; conflicting receipts fail closed.
`tenkaictl restore` (`SqliteStore::restore`) of a damaged backup fails
closed while the live fleet stays intact. Rollback of a recorded previous
version that cannot be pinned fails closed without stalling the rest of the
fleet. Required-provider absence and a runtime timeout stay isolated to the
injected cohort.
