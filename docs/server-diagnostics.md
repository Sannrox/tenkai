# Server reconcile diagnostics

`tenkai-server` emits a structured log line after each reconciliation tick:

```text
tenkai.reconcile outcome=ok environments_total=2 environments_failed=0 ...
```

## Fields

| Field | Meaning |
| --- | --- |
| `outcome` | `ok`, `degraded` (env failure), or `error` (tick failed) |
| `environments_total` | Environments considered this tick |
| `environments_failed` | Failed statuses |
| `environments_current` | Already up to date |
| `environments_applied` | Applied a plan this tick |
| `environments_busy` | Already in-flight |
| `environments_deferred` | Backed off after prior failure |
| `environments_awaiting_runtime` | Waiting for scoped runtime work |
| `environments_awaiting_approval` | Waiting for plan approval |

Cumulative counters are available from `Reconciler::diagnostics_snapshot()` for
host wiring. Logs never include bearer tokens or raw secrets.

## Optional OpenMetrics (`GET /metrics`) (#137)

When enabled, `tenkai-server` exposes Prometheus/OpenMetrics text at `/metrics`
**without** a bearer token. The binary still binds loopback-only in plaintext
mode; do not expose this port on an untrusted network without a proxy.

```bash
tenkai-server --enable-metrics
# or: TENKAI_ENABLE_METRICS=1
curl -s http://127.0.0.1:8080/metrics
```

Default: **disabled** (route returns 404).

| Series | Type | Meaning |
| --- | --- | --- |
| `tenkai_reconcile_ticks_total` | counter | Ticks attempted |
| `tenkai_reconcile_ticks_failed_total` | counter | Ticks with env failures or tick errors |
| `tenkai_reconcile_last_environments` | gauge | Envs on last tick |
| `tenkai_reconcile_last_environments_failed` | gauge | Failed envs on last tick |
| `tenkai_reconcile_last_outcome{outcome=…}` | gauge | Last outcome (`ok` / `degraded` / `error` / `none`) |
| `tenkai_reconcile_environments_busy_total` | counter | Cumulative Busy admissions (in-flight or fence) |

Labels are low-cardinality only. **No** `tenant_id`, environment names, tokens,
or plan bodies. Not a metrics TSDB; scrape and store externally.

## Fleet status (operator table)

Cross-environment delivery posture is **not** the same as tick counters above.
Use the fleet status report for drift/health/lease/plan at a glance:

```bash
# embedded
tenkaictl fleet status

# remote management (TLS or loopback; token from env)
export TENKAI_MANAGEMENT_TOKEN=…
tenkaictl --target remote --server-url http://127.0.0.1:8080 fleet status
```

HTTP: `GET /v1/fleet/status` (management bearer). Domain type:
`fleet::FleetStatusReport` (also re-exported as `plan::FleetStatusReport`). Complements `env list` / `env inspect` / per-env
`status`. Does not include reconcile tick counters (this page).

## Fleet drift watch

`tenkaictl fleet watch` repeatedly samples fleet posture (same rows as
`fleet status`), compares to a previous sample or optional JSON baseline file,
and prints a deterministic delta: which environments entered or left
`behind` / `unhealthy` / `empty` / `current`.

```bash
# one-shot vs empty baseline (embedded)
tenkaictl fleet watch --once

# continuous poll; write baseline for next automation run
tenkaictl fleet watch --interval 30 --write-baseline /var/tmp/tenkai-fleet-baseline.json

# compare to saved baseline; default exit non-zero only on *new* hard drift
tenkaictl fleet watch --once --baseline /var/tmp/tenkai-fleet-baseline.json

# fail if any environment is currently behind or unhealthy
tenkaictl fleet watch --once --exit-on-any-hard-drift

# fail on any posture change (including recoveries and empty↔current)
tenkaictl fleet watch --once --exit-on-any-posture-change

# remote (same management token as fleet status)
tenkaictl --target remote --server-url http://127.0.0.1:8080 fleet watch --once
```

**Exit codes (default):** non-zero when an environment *newly* becomes `behind`
or `unhealthy` relative to the baseline (or prior sample in a continuous run).
Existing hard drift that was already in the baseline does not fail by default.

**Baseline file:** optional JSON schema `tenkai.fleet-posture.v1` mapping
environment names to postures only. No SQLite persistence of samples; no
management or runtime tokens in output.

**Relation to other surfaces:**

| Surface | Role |
| --- | --- |
| `fleet status` / `GET /v1/fleet/status` | One-shot operator table |
| `fleet watch` | Delta / alert summary over time (this section) |
| Reconcile diagnostics (above) | Per-tick apply counters, not posture table |
| Rollout waves (`tenkaictl wave`) | Ordered cohort observation during a wave |
| Package migrations (`tenkaictl migrate`) | Source-to-target checkpoint receipts and recovery |

## Related

- Capability advertisement on `/healthz` and `/readyz` (runtime capabilities)
- Multi-env inspect via `tenkaictl env list` / `env inspect`
- Fleet status via `tenkaictl fleet status` / `GET /v1/fleet/status`
- Fleet drift watch via `tenkaictl fleet watch`
