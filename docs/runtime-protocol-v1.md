# Environment runtime protocol v1

The shipped host is pull-only HTTP on `tenkai-server`. An environment runtime
initiates every exchange; the server never pushes work into an environment.
There is no served gRPC `RuntimeService`.

| HTTP | Request | Result |
| --- | --- | --- |
| `GET /v1/runtime/environments/{environment}/work` | Bearer token and `x-tenkai-runtime-instance`. No body. | JSON `RuntimeWork` (`environment`, optional `plan`, optional `claim`) |
| `POST /v1/runtime/environments/{environment}/complete` | JSON `RuntimeCompletion` (`plan_id`, `generation`, `succeeded`, `detail`, `receipts`) | `204` |
| `POST /v1/runtime/environments/{environment}/heartbeat` | JSON `RuntimeHeartbeat` (`plan_id`, `generation`) | JSON claim |
| `POST /v1/runtime/environments/{environment}/inventory` | JSON `RuntimeInventoryReport` (`facts`, `source`) | JSON `RuntimeInventoryResponse` |

Work pull does not accept supported versions or capabilities and does not
negotiate. Completion covers the claimed plan in one request, not one proto
`CompleteStep` per step. Inventory is an admitted facts map, not a proto
`Observation`.

Operator publish, promote, plan, apply, and rollback are a different surface:
the authenticated HTTP [management lifecycle](management-lifecycle.md)
([ADR 0030](decisions/0030-remote-management-lifecycle.md)).
Transport authentication maps a principal to exactly one `environment_id`, and
the server rejects any request whose payload identity differs from that scope.
Each runtime process also presents a fresh instance identity. Authentication
remains token-based, while durable lease ownership binds both the authenticated
scope and that instance so overlapping processes cannot share one generation.

The HTTP host supplies the executor with a stable `<plan-id>:<step-id>`
idempotency key. Executors must durably claim that key before mutation and
return the previously recorded outcome after reconnect. This closes the
ambiguous interval where a runtime process can stop after the target changed
but before its receipt reached Tenkai.

Cancellation is advisory until observed by the runtime. Losing a lease is a
hard fence: the runtime must stop work, and a completion from that generation
is rejected.

## Typed proto contract

`proto/tenkai/runtime/v1/runtime.proto` is a separate typed contract. Helpers
in `runtime_protocol` validate proto deliveries and compute
`delivery_plan_digest`. Those messages are not the HTTP JSON payloads and are
not served on the wire.

The runtime opens a proto session with all protocol major/minor pairs and
capabilities it supports. The server selects the highest mutually supported
minor in major version 1 and returns its required capabilities. A major
mismatch or missing capability fails negotiation. Before returning a plan,
both sides validate every step's required capability and version.

Within major version 1, senders may add fields and enum values, receivers
ignore unknown fields, and existing field numbers and meanings never change.
Fields are never reused. During a rolling upgrade, servers support the current
and previous minor; runtimes may be upgraded before or after servers. A
feature is delivered only after negotiation proves support. A major version
requires a parallel API package and an explicit migration window.

A proto delivery is immutable and scoped to one environment. Each step has an
attempt number and digest-only execution input. Its lease has an opaque ID and
a monotonically increasing generation. The runtime verifies that generation
immediately before mutation. Heartbeats renew only the exact `(lease_id,
generation)` pair. Completion under an older generation returns `STALE_LEASE`.
The plan digest uses the versioned canonical field sequence implemented by
`delivery_plan_digest`, not serialized protobuf bytes, so additive transport
fields do not change older digest contracts.
The server uses its own clock for lease authority; runtime completion
timestamps are audit metadata and are accepted only within five minutes of
server time and never after the active lease expiry.

The receipt ID is a deterministic digest of environment, plan, step, and
attempt. The result and result digest belong to the canonical receipt but not
its mutation identity. The server stores the first accepted receipt under that
identity atomically. Re-delivery, including a conflicting later result,
returns the first canonical receipt with `ALREADY_COMPLETED`; it must not
invoke the executor again. A plan cannot become successful until every step
has an accepted success receipt.

## Secrets and logging

Credentials belong to transport/runtime configuration.

The proto contract contains no credential, environment-variable, arbitrary
metadata, command-output, or free-form log field. Proto plans carry only
actions and content digests; proto receipts carry a result enum and digest.

HTTP `RuntimeCompletion` and `RuntimeStepReceipt` carry free-form `detail`
strings plus a success boolean. Those details persist into plan transitions
and terminal-outcome evidence. Runtimes must not put secrets, tokens,
command output, or credentials in `detail`. Implementations must log
identifiers, versions, result codes, and digests only, and must not
serialize authentication metadata into payloads, errors, tracing fields, or
logs.

## Compatibility checklist

- Authorize the path `environment` against the transport principal.
- Persist delivery and receipt idempotency keys atomically.
- Compare plan ID and generation on HTTP heartbeat and completion.
- Treat unknown HTTP JSON fields as unsupported, never as success.
- Keep the proto `Negotiate` / `Pull` / `CompleteStep` / `Heartbeat` /
  `ReportObservation` surface distinct from the HTTP JSON types above.
- On the proto contract, negotiate versions and capabilities before accepting
  a delivery, and upgrade either side independently within the stated rolling
  window.
