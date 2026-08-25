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

Fairness under injected failure is a separate issue (#301).
