# Model-release evidence

Tenkai and Chisei exchange two versioned JSON records for the same model
identity. Tenkai emits runtime health and canary evidence. Chisei emits an
evaluation result. Promotion of that identity refuses when either record is
missing, stale, or invalid. This is the schema contract
([ADR 0032](decisions/0032-model-release-evidence.md)). Tenkai signs and
exports the runtime record through the integration outbox when a
`model_runtime` canary or smoke completes (pass or fail). Channel promotion
of `model_runtime` consumes a stored evaluation record.

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

## Channel promotion

`catalog::promote` of a `model_runtime` release requires a stored
`chisei.model_evaluation_evidence.v1` record, Ed25519-verified against
installed evaluation trust roots, for the release identity derived from the
published descriptor (provider from the weight source, `model=<product>`,
`profile_version=<product version>`, the manifest artifact digest,
`endpoint=served://<product>`). Missing, stale, or invalid (including failed)
evidence blocks promotion as
`model evaluation promotion blocked: missing|stale|invalid`. Other
product kinds are unchanged.

Install trusted evaluation signers, then record a signed evaluation JSON
document, then promote:

```bash
tenkaictl eval-evidence trust --trust-roots eval-trust.toml
tenkaictl eval-evidence record evaluation-result.json
tenkaictl promote qwen-coder@0.1.0 stable
```

`eval-trust.toml` is versioned TOML with `version = 1` and one or more
`[[signers]]` entries (`key_id` and Ed25519 `public_key`). The evidence file
is `chisei.model_evaluation_evidence.v1` JSON. Remote mode uses the same
commands against `POST /v1/model-evaluation/trust` (management) and
`POST /v1/model-evaluation/evidence` (publish). Recording fails closed when
trust roots are missing, the signer is untrusted, or the signature does not
verify.

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

- Chisei companion: persist and return `chisei.model_evaluation_evidence.v1`
  for the same identity.
