# Environment runtime protocol v1

The public contract is `proto/tenkai/runtime/v1/runtime.proto`. An environment
runtime initiates every RPC; the server never pushes work into an environment.
Transport authentication maps a principal to exactly one `environment_id`, and
the server rejects any request whose payload identity differs from that scope.
Each runtime process also presents a fresh instance identity. Authentication
remains token-based, while durable lease ownership binds both the authenticated
scope and that instance so overlapping processes cannot share one generation.

## Negotiation and rolling upgrades

The runtime opens a session with all protocol major/minor pairs and capabilities
it supports. The server selects the highest mutually supported minor in major
version 1 and returns its required capabilities. A major mismatch or missing
capability fails negotiation. Before returning a plan, both sides validate every
step's required capability and version.

Within major version 1, senders may add fields and enum values, receivers ignore
unknown fields, and existing field numbers and meanings never change. Fields are
never reused. During a rolling upgrade, servers support the current and previous
minor; runtimes may be upgraded before or after servers. A feature is delivered
only after negotiation proves support. A major version requires a parallel API
package and an explicit migration window.

## Delivery, leases, and receipts

A delivery is immutable and scoped to one environment. Each step has an attempt
number and digest-only execution input. Its lease has an opaque ID and a
monotonically increasing generation. The runtime verifies that generation
immediately before mutation. Heartbeats renew only the exact `(lease_id,
generation)` pair. Completion under an older generation returns `STALE_LEASE`.
The plan digest uses the versioned canonical field sequence implemented by
`delivery_plan_digest`, not serialized protobuf bytes, so additive transport
fields do not change older digest contracts.
The server uses its own clock for lease authority; runtime completion timestamps
are audit metadata and are accepted only within five minutes of server time and
never after the active lease expiry.

The receipt ID is a deterministic digest of environment, plan, step, and
attempt. The result and result digest belong to the canonical receipt but not
its mutation identity. The server stores the first accepted receipt under that
identity atomically. Re-delivery, including a conflicting later result, returns
the first canonical receipt with `ALREADY_COMPLETED`; it must not invoke the
executor again. A plan cannot become successful until every step has an
accepted success receipt.

The v0 HTTP runtime host supplies the executor with a stable
`<plan-id>:<step-id>` idempotency key. Executors must durably claim that key
before mutation and return the previously recorded outcome after reconnect.
This closes the ambiguous interval where a runtime process can stop after the
target changed but before its receipt reached Tenkai.

Cancellation is advisory until observed by the runtime. Losing a lease is a
hard fence: the runtime must stop work, and a completion from that generation
is rejected.

## Secrets and logging

Credentials belong to transport/runtime configuration. The protocol contains no
credential, environment-variable, arbitrary metadata, command-output, or free
form log fields. Plans carry only actions and content digests; receipts carry a
result enum and digest. Implementations must log identifiers, versions, result
codes, and digests only. They must not serialize authentication metadata or
execution input/output into payloads, errors, tracing fields, or logs.

## Compatibility checklist

- Negotiate versions and capabilities before pulling work.
- Authorize the payload `environment_id` against the transport principal.
- Validate all required capabilities before returning a delivery.
- Persist delivery and receipt idempotency keys atomically.
- Compare lease ID and generation on heartbeat and completion.
- Treat unknown fields and enum values as unsupported, never as success.
- Upgrade either side independently within the stated rolling window.
