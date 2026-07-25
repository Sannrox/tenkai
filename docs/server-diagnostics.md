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
`plan::FleetStatusReport`. Complements `env list` / `env inspect` / per-env
`status`. Does not include reconcile tick counters (this page).

## Related

- Capability advertisement on `/healthz` and `/readyz` (runtime capabilities)
- Multi-env inspect via `tenkaictl env list` / `env inspect`
- Fleet status via `tenkaictl fleet status` / `GET /v1/fleet/status`
