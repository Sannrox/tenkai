# Delivery telemetry

Tenkai emits the same allowlisted OpenTelemetry traces and metrics from
embedded `tenkaictl` and `tenkai-server`. Transport is not a domain boundary:
both hosts use the application telemetry port. Export is **off by default**.
Cached files, workdirs, commands, approval paths, cluster-config paths, and
payload contents cannot appear on a span. Only versioned delivery identities
are admitted.

Source: `src/telemetry.rs`.

## Enablement

Set a collector root. Tenkai POSTs OTLP/HTTP JSON to `{endpoint}/v1/traces`
and `{endpoint}/v1/metrics`. Export failures never fail plan, apply, health,
rollback, or reconcile.

```bash
export TENKAI_OTEL_ENDPOINT=http://127.0.0.1:4318
```

Unset, empty, or unreachable endpoints leave delivery behavior unchanged.
Each export gives up after one second to connect and three seconds in all,
and export runs in the background, so a stalled collector never delays a
delivery operation.

Every span carries a trace id, a random span id, and its start and end time;
every metric point carries the time it was recorded.

## Trace structure

Spans of one delivery share a trace. A span opened while another Tenkai span
runs its work is that span's child and carries its `parentSpanId`:

```text
tenkai.reconcile            one tick, the root unless a caller's trace is given
├── tenkai.plan             planning of each environment
└── tenkai.apply            each plan the tick applies
    ├── tenkai.rollback     when the plan rolls back
    ├── tenkai.health
    └── tenkai.health_gate
```

A plan or apply run on its own, from `tenkaictl` or a hub request, is the
root of its trace, with its health and rollback spans under it. Embedded and
server hosts produce the same shape. `tenkai.operation_id` stays the delivery
identity; the trace id only links spans.

## Inbound trace context

A hub request may carry the standard `traceparent` header. When it is valid, the
hub's spans for that request join the caller's trace as children of the
caller's span. Only version `00` in lowercase hex with non-zero ids is
accepted, and `tracestate` is ignored. A missing or malformed value starts a
new trace: the request is never refused for it, and the value is never
recorded. Like `x-request-id`, trace context is caller input and grants
nothing.

Remote `tenkaictl` sends `traceparent` next to `x-request-id` when the call
runs inside a Tenkai trace context.

gRPC calls Tenkai makes to Sekai or Chisei send the same `traceparent` as
request metadata when the call runs inside a Tenkai trace, so those servers'
spans join the delivery trace. A call outside a trace sends none. A missing
or unusable context never fails the call.

## Inbound correlation identity

Supply the caller-owned operation identity. Hub HTTP uses `x-request-id`
(authenticated request context). Embedded and remote CLI accept the same
identity:

```bash
tenkaictl --operation-id corr-380 plan --env local
# or
export TENKAI_OPERATION_ID=corr-380
```

Remote `tenkaictl` forwards that identity as `x-request-id`. The server
reconcile path scopes the same identity around hub work. A process-wide
`--operation-id` / `TENKAI_OPERATION_ID` on `tenkai-server` is the fallback
when a request does not carry one.

## Span names

| Name | When |
| --- | --- |
| `tenkai.plan` | Plan create, including reconciler planning |
| `tenkai.apply` | One authorized plan execution attempt |
| `tenkai.health` | Post-apply health command or implicit healthy software apply |
| `tenkai.health_gate` | Post-apply SLO/health gate evaluation (#590) |
| `tenkai.rollback` | Rollback step computation and apply of a rollback plan |
| `tenkai.reconcile` | One reconciler tick |

## Allowlisted attributes

| Attribute | Meaning |
| --- | --- |
| `tenkai.operation` | `plan`, `apply`, `health`, `rollback`, or `reconcile` |
| `tenkai.operation_id` | Inbound correlation identity |
| `tenkai.plan_id` | Stored plan identity |
| `tenkai.release_digest` | Content digest of the first plan step or health target |
| `tenkai.environment` | Environment name |
| `tenkai.fencing_generation` | Environment lease generation |
| `tenkai.outcome` | `ok` or `error` |

Unknown keys and values that look like secrets (`bearer`, `token=`,
`password=`, PEM markers, `kubeconfig`, credentials) are dropped. Spans never
grant execution authority.

## Metrics

| Name | Meaning |
| --- | --- |
| `tenkai.reconcile.latency_ms` | Tick wall time |
| `tenkai.apply.outcomes` | `1` on apply success, `0` on apply failure |
| `tenkai.lease.acquired` | Environment apply lease claimed |
| `tenkai.lease.released` | Environment apply lease released |
| `tenkai.health_gate.outcomes` | `1` on passing SLO gates, `0` on fail or unavailable |

Metric attributes use the same allowlist. Dashboards, log shipping, and
collector backends are out of scope.

## Governance correlation

When a governance provider documents a correlation contract, reuse
`tenkai.operation_id` as the inbound identity. Do not invent a second
correlation key or put provider payload contents on a Tenkai span.
