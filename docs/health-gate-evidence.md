# Health and SLO gate evidence

After activation succeeds and before the step is recorded as succeeded,
Tenkai evaluates optional health/SLO gates declared on the release manifest
or the subscribed channel. Process readiness (`deploy.health`) is unchanged.
This page is the operator contract for #590.

## Manifest

```toml
[gate]
bake_window_seconds = 60
on_fail = "halt"          # or "rollback"

[[gate.slo]]
name = "error_rate"
query = "sum(rate(http_requests_total{status=~\"5..\"}[5m])) / sum(rate(http_requests_total[5m]))"
op = "lte"
threshold = 0.01
```

`op` is `lt`, `lte` (default), `gt`, or `gte`. Queries are Prometheus instant
vectors. The executor samples through `bake_window_seconds` (zero means one
sample) and fails closed on the first breach or missing sample.

Channel overlay: JSON on the channel object `health_gates` property with the
same `slo`, `bake_window_seconds`, and `on_fail` fields. Same-name channel
gates replace release gates.

## Policy

| `on_fail` | Effect |
| --- | --- |
| `halt` | Plan fails. The new release stays deployed. Automatic retry of that target is held until an operator creates an explicit plan. |
| `rollback` | Restore the plan's previously signed restore pin. Unsigned-development previous pins are admitted only in `local`. |

Rollback steps do not re-evaluate SLO gates, so a gate-triggered restore
cannot loop. Ordinary same-version restarts skip the gates; an explicit retry
of a held failed target re-evaluates them. A metrics sample that does not
return within 10 seconds is unavailable and fails closed.

Releases without `[[gate.slo]]` and channels without `health_gates` behave as
today. `--skip-gates` skips SLO evaluation.

## Evidence record

Kind `tenkai.health_gate_evidence`. Schema `tenkai.health_gate_evidence.v1`.
The `evidence` property lists each gate, observed value, and verdict
(`pass` / `fail` / `unavailable`). The same payload is enqueued as a
`health_gate` provider event for webhook delivery.

Telemetry: span `tenkai.health_gate`, metric `tenkai.health_gate.outcomes`.
