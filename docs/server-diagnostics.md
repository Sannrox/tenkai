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

## Related

- Capability advertisement on `/healthz` and `/readyz` (runtime capabilities)
- Multi-env inspect via `tenkaictl env list` / `env inspect`
