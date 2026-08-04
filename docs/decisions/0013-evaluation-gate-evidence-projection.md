# ADR 0013: Evaluation gate evidence projection

- Status: Accepted
- Date: 2026-08-04
- Issue: [#207](https://github.com/Sannrox/tenkai/issues/207)
- Owner: Tenkai maintainers
- Related: [ADR 0001](0001-standalone-core-and-service-evolution.md)
- Dependencies: [Sekai-Chisei #524](https://github.com/Sannrox/sekai-chisei/pull/524), [bounded clock-skew follow-up #530](https://github.com/Sannrox/sekai-chisei/pull/530)

## Context

Tenkai's release gate previously read an evaluation suite, listed historical
runs, and fetched the selected run through three broad RPCs. Those reads expose
more data than a release gate needs and are not the 1.0 evaluation-plan and
manifest semantics. `ResolveEvaluationPlan` freezes situation-specific inputs;
it does not select a historical run or authorize a release gate.

The gate nevertheless needs a server-owned expected case set, deterministic
latest-run selection for an exact release and artifact, bounded pass/fail
evidence, and fail-closed behavior when the evaluation plane is unavailable.

## Decision

Use Sekai-Chisei's purpose-built authenticated
`GetEvaluationGateEvidence` query as the source of truth for the existing
`[gate].eval_suite` behavior. The request binds the suite ID, release digest,
artifact digest, and a bounded timestamp. Chisei computes the suite digest and
the length-delimited `tenkai-gate-v1` config reference, selects the latest
matching valid run by timestamp then run ID, and validates exact case coverage
before returning only case IDs and pass/fail bits.

Tenkai accepts only a `found` response whose suite, release, artifact,
config-reference, run identity, and timestamp bind to the request. It then
denies empty or failing evidence and any non-exact case set. `suite_not_found`
and `no_matching_run` deny the gate. RPC failures, unavailable storage,
malformed or unbound responses, unknown statuses, and invalid timestamps are
unavailable and fail closed.

The suite digest preserves the former `EvalSuite` protobuf field numbering and
values, allowing pre-migration stored run bindings to remain valid without
retaining the three broad public suite/run RPCs. The projection omits raw
evaluation content, assertions, scores, reasons, and timings. Evaluation-plan
resolution and manifest execution remain separate contracts.

## Alternatives considered

### Use `ResolveEvaluationPlan`

Rejected because resolution freezes an exact situation-specific manifest but
does not provide historical latest-run selection or the existing suite case
gate semantics.

### Keep the three broad legacy reads

Rejected because they expose unbounded suite/run data, require client-side
selection, and make the gate depend on a compatibility surface that is not a
narrow 1.0 evidence contract.

### Accept caller-supplied case truth or config references

Rejected because callers must not become evaluation authority. Chisei computes
all gate bindings and reads the persisted run evidence.

## Consequences

- Tenkai makes one bounded remote query for a release gate.
- Sekai-Chisei owns run selection, suite/config binding, exact case coverage,
  authorization, and strict durable decoding.
- Both sides retain fail-closed behavior for unavailable or invalid evidence.
- The old `GetEvalSuite`, `GetEvalRun`, and `ListEvalRuns` RPCs and vendored
  definitions are removed; domain persistence types remain internal to
  evaluation producers.
- A future change to gate semantics requires a versioned contract and a new
  decision rather than silently reusing evaluation-plan resolution.

## Evidence and provenance

- Tenkai issue [#207](https://github.com/Sannrox/tenkai/issues/207) records the
  decision requirement and acceptance criteria.
- Sekai-Chisei PR [#524](https://github.com/Sannrox/sekai-chisei/pull/524)
  merged as `3a4b15ebc42bcb944c7b9ad5c0748dbabe1d9a17` and implements the
  projection, persistence queries, authorization, bounded redaction, and
  inventory changes.
- Sekai-Chisei PR [#530](https://github.com/Sannrox/sekai-chisei/pull/530)
  merged as `01f9c31cd101978878cfe7a2686ffcb681053bb6` and preserves Tenkai's
  60-second local evidence window with an explicit 60-second inter-host clock
  skew allowance.
- The Tenkai mapping and validation are implemented in
  [`src/apply.rs`](../../src/apply.rs) and [`src/client.rs`](../../src/client.rs);
  the vendored contract is pinned in
  [`proto/vendor/chisei.proto`](../../proto/vendor/chisei.proto).
