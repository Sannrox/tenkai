# ADR 0033: Post-apply health and SLO gates

- Status: Accepted
- Date: 2026-10-13
- Issue: [#590](https://github.com/Sannrox/tenkai/issues/590)
- Owner: Tenkai maintainers
- Related: [ADR 0013](0013-evaluation-gate-evidence-projection.md),
  [ADR 0032](0032-model-release-evidence.md)

## Context

Apply already probes process readiness through `deploy.health` and blocks on
Chisei eval-suite evidence before mutation (ADR 0013). That is not a
service-level gate. A release that is ready but raising error rate or latency
keeps rolling. Operators need declared metric queries, a bake window, and a
halt-or-rollback policy that cannot loop (#549) and that restores only a
previously signed pin (#562).

## Decision

1. Releases declare optional `[[gate.slo]]` queries on the signed manifest.
   Channels may overlay the same JSON on the channel object `health_gates`
   property. Releases without SLO gates keep today's apply behavior.
2. After activation succeeds and before recording terminal `Succeeded`, the
   executor samples every declared query against an injected
   Prometheus-compatible instant-vector source for the bake window. The first
   failing or unavailable sample fails closed without waiting out the rest of
   the window. Zero seconds means a single sample. One sample batch that does
   not return within 10 seconds is `unavailable`.
3. `gate.on_fail = "halt"` (default) blocks the plan and leaves the new
   release deployed. `gate.on_fail = "rollback"` restores the plan's restore
   pin when that pin is a verified release, or unsigned-development content
   confined to `local`. Missing or unsigned previous pins halt instead.
4. Rollback steps skip SLO evaluation, so a gate-triggered restore cannot
   loop. Ordinary Restart steps skip it; an explicit Restart that retries a
   failed-target hold re-evaluates the same gates.
5. Each evaluation persists `tenkai.health_gate_evidence.v1` listing every
   gate name, query, threshold, value, and verdict, emits `tenkai.health_gate`
   traces/metrics (#380), and enqueues a `health_gate` provider event for
   later webhook delivery (#546).

## Consequences

- Hosts inject `HealthMetricsSource` on `Ctx`. Declared gates with no source
  fail closed as `unavailable`. `query_instant` must return in bounded time;
  Tenkai cannot cancel a hung blocking query, and it fail-closes the apply
  instead of holding the environment lease.
- `--skip-gates` skips SLO evaluation the same way it skips eval-suite gates.
- Automatic rollback reuses the approved plan's restore pin; it does not
  invent a new downgrade plan.

## Evidence

- Types and tests: `src/health_gate.rs`
- Operator docs: [health-gate-evidence.md](../health-gate-evidence.md)
