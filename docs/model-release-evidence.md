# Model-release evidence

Tenkai and Chisei exchange two versioned JSON records for the same model
identity. Tenkai emits runtime health and canary evidence. Chisei emits an
evaluation result. Promotion of that identity refuses when either record is
missing, stale, or invalid. This is the schema contract
([ADR 0032](decisions/0032-model-release-evidence.md)). Tenkai signs and
exports the runtime record through the integration outbox when a
`model_runtime` canary or smoke completes (pass or fail). The promotion
gate remains follow-on work.

This contract is distinct from [evaluation gate evidence](evaluation-gate-evidence.md)
(ADR 0013), which still gates software releases on suite-case projections.

## Identity

Both records carry the same `identity` object:

| Field | Rule |
| --- | --- |
| `provider` | Tenkai identifier |
| `model` | Tenkai identifier |
| `profile_version` | Tenkai identifier |
| `artifact_digest` | `sha256:` and 64 lowercase hex characters |
| `endpoint` | Absolute URI for the served model, not a machine inventory record |

Example identity:

```json
{
  "provider": "huggingface",
  "model": "qwen-coder",
  "profile_version": "v1",
  "artifact_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "endpoint": "served://qwen-coder"
}
```

## Tenkai → Chisei

Schema: `tenkai.model_runtime_evidence.v1`.

Required fields: `schema`, `identity`, `release_id`, `release_digest`,
`health` (`healthy`, `unhealthy`, `unknown`), `canary` (`passed`, `failed`,
`incomplete`), `observed_at`, `expires_at`, `signer`.

`signer.key_id` is `sha256:<hex>`. `signer.signature` is a 64-byte Ed25519
signature in standard Base64. Timestamps are milliseconds since epoch.
Unknown fields are rejected.

Worked example: [runtime-health.json](examples/model-release-evidence/runtime-health.json).

## Chisei → Tenkai

Schema: `chisei.model_evaluation_evidence.v1`.

Required fields: `schema`, `identity`, `eval_suite_id`, `eval_run_id`,
`outcome` (`passed`, `failed`), `observed_at`, `expires_at`, `signer`.

Worked example: [evaluation-result.json](examples/model-release-evidence/evaluation-result.json).

## Promotion refusal

`evaluate_model_release_promotion` in `src/model_release_evidence.rs`
admits a release only when both records are present, match the expected
identity, validate, have not expired, and pass (`health=healthy`,
`canary=passed`, `outcome=passed`).

| Reason | Meaning |
| --- | --- |
| `missing` | Either record is absent. |
| `stale` | `expires_at` is at or before now, or `observed_at` is more than 60 seconds ahead of now. |
| `invalid` | Unknown schema, unknown fields, failed validation, identity mismatch, or a non-passing outcome. |

## Export

When a `model_runtime` canary attempt is persisted, or when model-runtime
apply finishes smoke, Tenkai signs `tenkai.model_runtime_evidence.v1` and
enqueues it on the integration outbox as provider kind
`model_runtime_evidence`. Failed and passing outcomes both export. Successful
smoke sets `health=healthy` and `canary=incomplete`; `canary=passed` is
reserved for a terminal canary outcome that satisfies the existing canary
pass checks. Identity uses an opaque `served://<product>` URI, never a host
or credential.

Signing uses the 32-byte Ed25519 seed at `TENKAI_MODEL_EVIDENCE_KEY`. Export
runs only when terminal-outcome export is enabled and that key is present.

## Follow-on

- Consume Chisei evaluation evidence at promote time.
- Chisei companion: persist and return `chisei.model_evaluation_evidence.v1`
  for the same identity.
