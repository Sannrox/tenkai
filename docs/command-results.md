# Machine-readable command results

`tenkaictl --output json-v1` exposes a bounded result envelope for typed
adapters, against embedded state and a remote server alike. The default
remains `--output human`; existing scripts and operator output are unchanged.

| Command | `--target embedded` | `--target remote` |
| --- | --- | --- |
| `publish` | yes | yes |
| `promote` | yes | yes |
| `release recall` (`recall`) | yes | yes |
| `env subscribe` (`subscribe`) | yes | yes |
| `plan` | yes | yes |
| `approval submit` (`approve`) | yes | yes |
| `apply` | yes | yes |
| `rollback` | yes | yes |
| `restart` | yes | no |
| `status` | yes | yes |
| `env inspect` (`inspect_environment`) | yes | yes |
| `env list` (`list_environments`) | yes | yes |
| `fleet status` (`fleet_status`) | yes | yes |

Any other command, or a `no` above, fails closed before contacting Tenkai with
`unsupported_command` (embedded) or `unsupported_target` (remote).

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
  `inspect_environment`, `rollback`, `restart`, `recall`, `approve`,
  `subscribe`, `list_environments`, or `fleet_status`.
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

`status`, `env inspect`, `env list`, and `fleet status` are reads. Correct
rejected input before retrying them. A general command-execution protocol is
outside this contract.

## Remote mode

Both targets build each envelope the same way. Remote results differ only in
these documented, target-only fields:

- `plan` and `rollback` add a `plan_digest` resource and the `generation`
  resource that `approval submit` and `apply` take as `--generation`.
- `plan`, `apply`, and `rollback` omit `counts`; the v1 HTTP result does not
  report step counts.
- A remote `rollback` only plans, so it always returns `awaiting_approval`
  with `approval_required`.

Remote failures carry a fixed `code` and never echo server detail:

| Code | Cause | Outcome | Retry |
| --- | --- | --- | --- |
| `transport_unavailable` | The request never reached the server | `failed` | `correct_request` |
| `transport_interrupted` | No complete response arrived | `unknown` for mutations, `failed` for reads | `reconcile_before_retry` |
| `authentication_refused` | HTTP 401 | `failed` | `correct_request` |
| `authorization_denied` | HTTP 403 | `failed` | `correct_request` |
| `conflict` | HTTP 409: stale `--generation`, lease, or state conflict | `failed` | `reconcile_before_retry` |
| `execution_failed` | HTTP 422: one or more apply steps did not succeed | `failed` | `reconcile_before_retry` |
| `domain_denied` | Any other HTTP 4xx | `failed` | `correct_request` |
| `server_error` | HTTP 5xx | `unknown` for mutations, `failed` for reads | `reconcile_before_retry` |

A failed remote `plan`, `approval submit`, `apply`, `rollback`, or
`env subscribe` keeps the `plan`, `environment`, and `subscription` resources it
targeted. A mutation interrupted mid-flight is never reported as `succeeded`.
