# Machine-readable command results

`tenkaictl --output json-v1` exposes a bounded result envelope for local typed
adapters. The default remains `--output human`; existing scripts and operator
output are unchanged.

Version 1 is available only with `--target embedded` for:

- `publish`
- `promote`
- `plan`
- `apply`
- `status`
- `env inspect`
- `rollback`
- `restart`
- `release recall` (`recall`)

Every supported invocation writes exactly one compact JSON object to standard
output:

```json
{
  "schema": "tenkai.command-result/v1",
  "command": "plan",
  "outcome": "succeeded",
  "retry": "not_needed",
  "resources": [
    {"kind": "plan", "id": "tenkai:plan:local:1:opaque"},
    {"kind": "environment", "id": "local"}
  ],
  "counts": {"steps": 1}
}
```

The fixed fields are:

- `schema`: exactly `tenkai.command-result/v1`.
- `command`: `invocation`, `publish`, `promote`, `plan`, `apply`, `status`,
  `inspect_environment`, `rollback`, `restart`, or `recall`.
- `outcome`: `succeeded`, `failed`, `awaiting_approval`, or `unknown`.
- `retry`: `not_needed`, `correct_request`, `reconcile_before_retry`, or
  `not_safe`.
- `resources`: opaque Tenkai-owned identifiers suitable for subsequent
  inspection or status reconciliation. A resource kind is at most 64 bytes
  and a complete resource identifier at most 512 bytes. An envelope contains
  at most eight resources. These bounds apply only to this opt-in output
  contract; existing human-mode identifiers remain compatible. Publish may
  return the release followed by `release_provenance` resources whose ids are
  canonical envelope digests.
- `counts`: optional bounded step or item counts.
- `error`: optional fixed `code` and sanitized `message`.

Unknown fields and enum values must be rejected. Identifiers are opaque.
Envelopes never contain manifests, artifacts, database paths, credentials,
signing material, approval envelopes, or arbitrary command output.

## Outcome and retry rules

A complete, parseable envelope with the expected schema is correlation
metadata, not an execution receipt. An absent, truncated, duplicated,
malformed, or incompatible envelope means the outcome is **unknown**, even
when a process exit code is available. Reconcile the returned or previously
known release, channel, plan, or environment before deciding what to do next.

Exit code zero accompanies `succeeded`. Invalid invocation uses Clap's
non-zero invocation exit code. Domain denial, execution failure, unsupported
command/target combinations, and approval-required results exit non-zero.
Process exit alone is never authoritative.

Mutation retry behavior:

| Command | Reconciliation before another attempt |
| --- | --- |
| `publish` | Inspect the immutable `product@version`; identical publication is idempotent. |
| `promote` | Inspect the channel head before promoting again. |
| `plan` | Inspect the referenced/latest environment plan before creating another. |
| `apply` | Inspect plan state and environment status; never blindly repeat an unknown apply. |
| `rollback` | Inspect the rollback plan and environment; approval-required and unknown rollback are not safe to repeat blindly. |

`status` and `env inspect` are reads. Correct rejected input before retrying
them. Machine-readable remote mutation APIs and a general command-execution
protocol are outside this contract.
