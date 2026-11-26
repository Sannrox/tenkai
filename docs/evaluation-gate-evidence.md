# Evaluation gate evidence

`[gate].eval_suite` admits a release from stored signed evaluation evidence
([ADR 0064](decisions/0064-tenkai-stands-alone.md),
[ADR 0032](decisions/0032-model-release-evidence.md)). Producers push a
`chisei.model_evaluation_evidence.v1` record through the existing ingest
(`tenkaictl eval-evidence` or `POST /v1/model-evaluation/evidence`). Tenkai
does not pull `GetEvaluationGateEvidence` for this gate.

The stored record must:

- name the suite in `eval_suite_id`;
- bind `identity.artifact_digest` to the release artifact (`sha256:` plus 64
  lowercase hex characters; an unprefixed 64-hex stored digest still matches);
- record `outcome=passed`;
- verify against installed evaluation trust roots;
- be fresh (`expires_at` after now, `observed_at` not more than 60 seconds
  ahead).

Missing, stale, or invalid evidence fails closed on every host. When several
records match the suite and artifact, Tenkai uses the newest `observed_at`;
two records at the same time are invalid.

The ingest contract, identity fields, and trust roots are in
[model-release evidence](model-release-evidence.md).
