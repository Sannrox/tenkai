# Multi-environment rollout waves

A **wave** is an ordered cohort of environments observed in sequence for
delivery posture. It does not invent a second control plane and does not
replace canary promotion evidence.

Related: [fleet status](server-diagnostics.md#fleet-status-operator-table),
[fleet drift watch](server-diagnostics.md#fleet-drift-watch),
canary promotion (`src/canary.rs`, closed #7), `src/wave.rs`.

## Happy path

```bash
# 1. Ensure environments exist and subscribe as needed
tenkaictl env add canary
tenkaictl env add stage
tenkaictl env add prod

# 2. Observe a wave (stop on first hard failure; remaining skipped)
tenkaictl wave run canary,stage,prod

# 3. Continue through failures if desired
tenkaictl wave run canary,stage,prod --continue-on-failure
```

Hard failures: environment missing or **unhealthy** posture.  
`behind` / `empty` are reported but do not stop the wave by default.

## Relation to canary

| Surface | Role |
| --- | --- |
| Wave | Ordered observe of env delivery posture |
| Canary policy | Gate **channel promotion** on complete cohort evidence |

Waves never authorize a wider channel promotion. Use canary configure /
promotion after canary envs are healthy. For `model_runtime` products, the same
canary evidence rules apply; see [model runtime canary path](model-runtime.md#canary-promotion-evidence-model_runtime).

The responsibility map across channels, canary, waves, maintenance, facts,
constraints, emergency start, and rollback is recorded in
[the rollout-control simplification research](research/rollout-control-simplification.md).

## Non-goals (this surface)

- Automatic multi-wave fleet scheduling
- Durable wave history store
- Remote `wave run` (embedded first)
- Graphical dashboards
