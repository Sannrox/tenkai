# Evaluation gate evidence

Tenkai release gates use Sekai-Chisei's server-owned
`GetEvaluationGateEvidence` projection. This is the selected 1.0 evidence
contract for the existing `[gate].eval_suite` behavior. Tenkai does not use
`ResolveEvaluationPlan` as a substitute: plan resolution freezes inputs but
does not select historical runs or make a gate decision.

The request contains the suite ID, exact release digest, exact artifact digest,
and an upper timestamp bound of the current time plus 60 seconds. The caller
does not provide a run ID, config reference, expected case set, or pass/fail
result. Chisei accepts this bound no more than 120 seconds ahead of its own
clock: the additional 60 seconds is an explicit inter-host clock-skew
allowance. Tenkai validates returned evidence against the exact cutoff it sent.

| Existing gate responsibility | Server-owned projection behavior |
| --- | --- |
| Expected case set | Chisei reads the immutable suite and returns `expected_case_ids`. |
| Current release/artifact binding | Chisei computes the suite digest and the length-delimited `tenkai-gate-v1` `config_ref`; Tenkai verifies the returned binding. |
| Latest run selection | Chisei selects the matching run with the greatest valid timestamp, then greatest run ID, at or before the request bound. |
| Case evidence | Chisei returns only case IDs and pass/fail bits, after exact one-result-per-case validation. Tenkai denies any failing, empty, duplicate, missing, or unexpected result set. |
| Missing or unavailable evidence | `suite_not_found` and `no_matching_run` deny the gate; transport errors, malformed responses, unknown statuses, invalid bindings, and unavailable storage become `Unavailable` and fail closed. |

The response echoes the suite, release, artifact, suite digest, config
reference, selected run ID, and timestamp. Tenkai checks those bindings before
evaluating the bounded case projection. The suite digest is the raw SHA-256
hex digest of the former `EvalSuite` wire shape, so pre-migration run
`config_ref` values remain selectable after the old public suite/run reads are
removed.

The projection intentionally omits suite specifications, assertions, raw
results, scores, reasons, and elapsed timings. Evaluation plans, manifests,
and execution receipts remain separate contracts with their own authority and
semantics.
