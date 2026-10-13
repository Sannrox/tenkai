# ADR 0032: Versioned two-way model-release evidence

- Status: Accepted
- Date: 2026-10-13
- Issue: [#603](https://github.com/Sannrox/tenkai/issues/603)
- Owner: Tenkai maintainers
- Related: [ADR 0007](0007-model-runtime-fleet-control-plane.md),
  [ADR 0013](0013-evaluation-gate-evidence-projection.md)
- Companion: Sekai-Chisei will consume the same identity and schema names when
  it takes the evaluation-side record (tracked there as the model-eval
  companion to this contract).

## Context

Tenkai already gates software releases on canary outcomes and on Chisei's
`GetEvaluationGateEvidence` projection (ADR 0013). Open-weight `model_runtime`
releases need a narrower, two-way record: Tenkai must tell the evaluation
plane that a specific model identity is healthy and has passed canary, and
Chisei must tell Tenkai that the same identity passed evaluation. Promotion
must fail closed when that evidence is missing, stale, or invalid.

The identity is not a host inventory row. It is provider, model, profile
version, artifact digest, and an opaque serving endpoint. Export (#604) and
channel promotion (#605) consume this schema so both sides serialize the same
bytes. Chisei's companion persist remains follow-on.

## Decision

Publish two versioned JSON records that share one identity object.

### Shared identity

`provider`, `model`, and `profile_version` are Tenkai identifiers.
`artifact_digest` is `sha256:` plus 64 lowercase hex characters.
`endpoint` is an absolute URI for the served model (for example
`served://qwen-coder`). It is not a machine name, address, or inventory
record.

### Tenkai → Chisei

Schema name: `tenkai.model_runtime_evidence.v1`.

Fields: `schema`, `identity`, `release_id`, `release_digest`, `health`
(`healthy` / `unhealthy` / `unknown`), `canary` (`passed` / `failed` /
`incomplete`), `observed_at`, `expires_at`, `signer` (`key_id`,
`signature`). Timestamps are milliseconds since epoch. `signer.key_id` is
`sha256:<hex>`; `signer.signature` is a 64-byte Ed25519 signature in
standard Base64. Cryptographic verification against trust roots is the
consumer's duty using the existing signature-verification seam; this
decision requires the envelope shape.

### Chisei → Tenkai

Schema name: `chisei.model_evaluation_evidence.v1`.

Fields: `schema`, `identity`, `eval_suite_id`, `eval_run_id`, `outcome`
(`passed` / `failed`), `observed_at`, `expires_at`, `signer`.

This record is not a substitute for ADR 0013's suite-case projection. It
binds evaluation of a *model identity* for model-release promotion. Suite
gates on software releases stay on `GetEvaluationGateEvidence`.

### Promotion refusal

`evaluate_model_release_promotion` admits a release only when both records
are present, match the expected identity, validate, have not expired, and
carry passing outcomes (`health=healthy`, `canary=passed`,
`outcome=passed`). Otherwise it returns one of:

| Reason | When |
| --- | --- |
| `missing` | Either record is absent. |
| `stale` | A present record has `expires_at <= now`, or `observed_at` is more than 60 seconds ahead of `now` (same skew allowance as ADR 0013). |
| `invalid` | Unknown schema, unknown fields, failed structural validation, identity mismatch, or a non-passing outcome. |

Unknown fields are denied. Unknown schema names are denied. A future
schema bump is a new decision.

## Alternatives considered

### Reuse `GetEvaluationGateEvidence` alone

Rejected because that projection binds a software suite, release digest,
and artifact digest. It has no model identity (provider, profile version,
endpoint) and no Tenkai-emitted health or canary half.

### One combined record signed by both planes

Rejected because each plane is authority for its own observations. Tenkai
must not become evaluation authority; Chisei must not become runtime-health
authority.

### Treat endpoint as a host or inventory fact

Rejected because public model identity must not encode machine inventory.
An opaque serving URI is enough to distinguish two served copies of the
same digest.

## Consequences

- `src/model_release_evidence.rs` is the schema source of truth.
  Example records live under `docs/examples/model-release-evidence/`.
- Exporting runtime evidence through the integration outbox is #604. Refusing
  `promote` of `model_runtime` without a passing evaluation record is #605.
  Those paths must not invent a second identity or schema name.
- Chisei's companion consumer binds `chisei.model_evaluation_evidence.v1`
  and the shared identity fields; it does not need this crate.

## Evidence and provenance

- Tenkai issue [#603](https://github.com/Sannrox/tenkai/issues/603) records
  the decision requirement and acceptance criteria.
- Operator schema: [model-release-evidence.md](../model-release-evidence.md).
- Types and schema-validation tests:
  [`src/model_release_evidence.rs`](../../src/model_release_evidence.rs).
