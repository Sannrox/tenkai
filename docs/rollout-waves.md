# Multi-environment rollout waves

A **wave** is an ordered cohort of environments. Observation (`wave run`)
reports delivery posture and never applies. Execution (`wave execute`) admits
one durable, content-bound coordinator that advances through existing Tenkai
plans, approvals, gates, leases, health, receipts, and rollback. It does not
invent a second control plane and does not replace canary promotion evidence.

Related: [ADR 0017](decisions/0017-executable-release-waves.md),
[fleet status](server-diagnostics.md#fleet-status-operator-table),
[fleet drift watch](server-diagnostics.md#fleet-drift-watch),
canary promotion (`src/canary.rs`, closed #7), `src/wave.rs`.

## Observe (non-mutating)

```bash
tenkaictl wave run canary,stage,prod
tenkaictl wave run canary,stage,prod --continue-on-failure
```

Hard failures: environment missing or **unhealthy** posture.
`behind` / `empty` are reported but do not stop the wave by default.
`wave run` does not persist a wave record and does not apply.

## Execute a durable release wave

```bash
# 1. Publish and promote the signed release, subscribe each cohort environment.
tenkaictl wave execute rollout-1 \
  --product hello --version 1.0.0 --channel stable \
  --cohort canary,stage,prod \
  --approval-dir ./approvals \
  --approval-trust-roots plan-approvers.toml

# 2. If a plan is waiting for approval, sign it as <plan-id>.json in that directory
#    and resume:
tenkaictl wave resume rollout-1 \
  --approval-dir ./approvals \
  --approval-trust-roots plan-approvers.toml

tenkaictl wave status rollout-1
tenkaictl wave stop rollout-1
tenkaictl wave rollback rollout-1 \
  --approval-dir ./approvals \
  --approval-trust-roots plan-approvers.toml
```

Local-only development bypass is restricted to the built-in `local`
environment, matching plan apply:

```bash
tenkaictl wave execute local-rollout \
  --product hello --version 0.1.0 --channel stable --cohort local \
  --allow-unapproved-development --development-reason "laptop dogfood"
```

Admission pins the exact release (id, manifest digest, artifact digest) and the
channel head that currently names it. Advancement revalidates signatures or
unsigned-local policy, channel head, recall, subscription, and plan approval
immediately before each environment executes. Retrying the same name, product,
version, channel, cohort, and fail policy is idempotent; any change is a
conflict. Stop-on-failure keeps completed cohorts and marks later work skipped.
Restart reloads the wave from Tenkai operational storage; optional providers
are not recovery material.

Databases created before this schema need `tenkaictl init` so `tenkai.wave` is
registered. Wave records store identifiers, digests, statuses, and bounded
detail only.

## Relation to canary

| Surface | Role |
| --- | --- |
| `wave run` | Ordered observe of env delivery posture |
| `wave execute` | Ordered apply of per-environment Tenkai plans for one pinned release |
| Canary policy | Gate **channel promotion** on complete cohort evidence |

Waves never authorize a wider channel promotion. Use canary configure /
promotion after canary envs are healthy. For `model_runtime` products, the same
canary evidence rules apply; see [model runtime canary path](model-runtime.md#canary-promotion-evidence-model_runtime).

The responsibility map across channels, canary, waves, maintenance, facts,
constraints, emergency start, and rollback is recorded in
[the rollout-control simplification research](research/rollout-control-simplification.md)
(historical observe-only wave row) and [ADR 0017](decisions/0017-executable-release-waves.md).

## Non-goals (this surface)

- Automatic multi-wave fleet scheduling
- Letting a wave promote a channel
- Remote-only observation (`wave run` remains embedded-first)
- Graphical dashboards
