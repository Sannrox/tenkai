# Remote management lifecycle v1

Operator lifecycle verbs share one versioned HTTP contract,
`tenkai.management-lifecycle.v1`. Both hosts call the same application core.
Transport is not a domain boundary.

The spoke runtime protocol is a different surface. Runtimes still initiate
every `Negotiate` / `Pull` / `CompleteStep` / `Heartbeat` exchange; see
[runtime protocol v1](runtime-protocol-v1.md). Do not place management verbs
on that proto and do not overload `POST /v1/reconcile`.

Package-migration preview, apply, status, resume, and rollback stay on
`/v1/migrations/*` ([ADR 0026](decisions/0026-remote-package-migration-parity.md)).
They are not generic apply wrappers.

## Contract header

Every lifecycle request and result carries:

| Field | Rule |
| --- | --- |
| `version` | Must be `1`. Any other value fails closed. |
| `operation` | One of the closed vocabulary below. Unknown names fail closed. |
| `environment` | Required for environment-bound operations. Forbidden for catalog-wide operations. |
| `expected_generation` | Required for mutating environment-bound operations. A stale generation fails before the next effect. |

Unknown JSON fields fail closed (`deny_unknown_fields`). A remote body must
not carry `--allow-unapproved-development` or any other embedded
local-development bypass.

The Rust admission entry is `tenkai::management_lifecycle`. Routes added by
later issues must call it before the Catalog, planner, or apply core.

## Operations

| Operation | Scope | Reserved path | Later issue |
| --- | --- | --- | --- |
| `publish` | Catalog-wide | `POST /v1/releases` | [#394](https://github.com/Sannrox/tenkai/issues/394) |
| `promote` | Catalog-wide | `POST /v1/channels/{channel}/promote` | #394 |
| `recall` | Catalog-wide | `POST /v1/releases/{release}/recall` | #394 |
| `subscribe` | Environment | `POST /v1/environments/{environment}/subscriptions` | #394 |
| `plan` | Environment | `POST /v1/environments/{environment}/plans` | [#395](https://github.com/Sannrox/tenkai/issues/395) |
| `approve` | Environment | `POST /v1/plans/{plan_id}/approve` | #395 |
| `apply` | Environment | `POST /v1/plans/{plan_id}/apply` | #395 |
| `rollback` | Environment | `POST /v1/environments/{environment}/rollback` | #395 |

These paths are reserved. This document does not add the routes.

## Credentials

Authentication stays on `AuthStack` ([request context](auth-request-context.md)).
`DeliveryCapability::Management` is required for every lifecycle operation.
`read` is not enough.

| Principal | Grant | Lifecycle effect |
| --- | --- | --- |
| Fleet management | No environment binding | May call catalog-wide and environment-bound operations on environments it can see. Tenant-mode hosts still apply the non-disclosing deny. |
| Environment-scoped management | Exactly one environment | May call environment-bound operations only for that environment. Catalog-wide publish, promote, and recall fail closed. |
| Runtime | Exactly one environment | Refused on every management lifecycle operation. Runtime tokens stay on `/v1/runtime/*`. |

Missing approval evidence fails closed. A stale fencing generation cannot
complete apply. Cached inspect payloads and retained files cannot grant
execution authority.

`--allow-unapproved-development` remains embedded-only and restricted to the
built-in `local` environment.

## Compatibility

Within version `1`, senders may add fields only through a new minor contract
revision that existing receivers treat as unknown and refuse when the field
would change admission. Removing an operation, changing digest meaning, or
changing failure semantics requires version `2` and an explicit migration
window.

Existing `/v1/reconcile`, `/v1/environments`, `/v1/fleet/status`, and
`/v1/migrations/*` routes are unchanged.

## See also

- [ADR 0030](decisions/0030-remote-management-lifecycle.md)
- [Discussion #384](https://github.com/Sannrox/tenkai/discussions/384)
- [Catalog contract](catalog-contract.md)
- [Plan approval](plan-approval.md)
- [Release signing](release-signing.md)
