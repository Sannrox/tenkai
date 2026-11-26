# ADR 0064: Tenkai stands alone

- Status: Accepted
- Date: 2026-11-26
- Issue: [#1579](https://github.com/Sannrox/tenkai/issues/1579)
- Owner: Tenkai maintainers
- Supersedes: [ADR 0015](0015-governed-action-remote-migration.md)
- Amends: [ADR 0001](0001-standalone-core-and-service-evolution.md) (provider
  role), [ADR 0032](0032-model-release-evidence.md) (evaluation evidence
  source), [ADR 0062](0062-atomic-catalog-actions.md) §4 (obsolete)
- Related: [ADR 0013](0013-evaluation-gate-evidence-projection.md)

The issue draft numbered this decision 0063. That number already shipped as
[change-driven reconcile ticks](0063-change-driven-reconcile-ticks.md).

## Context

Tenkai treats the graph and governance provider as optional, yet depends on it
in five places: a provider-backed catalog (`--provider-mode remote`), governed
action admission, pulled evaluation-gate evidence, outcome and feedback export,
and the provider's wire types and key-provider crate. Each remote-only path
already diverges from the embedded and PostgreSQL hosts, which are atomic and
recover without the provider. Fixing the remote action path alone (#1566)
needs an unreleased provider RPC, a new idempotency rule, and vendored
protocol growth.

## Decision

1. Tenkai owns all of its state, types and contracts. It has no runtime,
   build or wire dependency on the provider.
2. Evidence flows in, not out: producers push signed evidence to Tenkai
   (the ADR 0032 ingest path). Tenkai never pulls evidence from, or exports
   delivery state to, an external graph.
3. The provider, if deployed, is a product Tenkai delivers like any other.
4. Stored formats stay readable: Tenkai-owned messages keep the field numbers
   and evidence schema identifiers already on disk.

This Issue retires `--provider-mode remote` and admits `[gate].eval_suite` from
stored signed evaluation evidence. Outcome and feedback export (#1580), wire
types (#1582), and key providers (#1581) land on the same decision.

## Consequences

- `--provider-mode remote` is refused at startup with an actionable error that
  names the embedded SQLite store and PostgreSQL. The `remote` value stays
  parseable for one release.
- `eval_suite` gates are satisfied by stored signed evaluation evidence for
  the release. Missing, stale, or invalid evidence fails closed on every host.
- #1566 is not built.
- Operators on remote provider mode re-initialize a Tenkai-owned store.
- ADR 0015 is superseded. ADR 0062 §4 is obsolete. ADR 0013's pull of
  `GetEvaluationGateEvidence` no longer admits `[gate].eval_suite`.

## Rejected

- Keep the provider optional: every optional path is a second host with its
  own recovery semantics.
- Build #1566: large cost for a mode no known deployment uses.
- Remove `eval_suite` gates: they stay, on stored evidence rather than a
  pulled projection.
