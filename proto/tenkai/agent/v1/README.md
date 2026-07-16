# Planner/agent protocol v1

The package `tenkai.agent.v1` is the first compatibility boundary between a
tenkai planner and a future environment agent. Every top-level request and
response carries `protocol_version = 1`; receivers must reject unsupported
versions, including the proto3 default value `0`, before acting on the message.
In other words, every v1 envelope must have `protocol_version == 1`. The package
name and envelope value intentionally identify the same major protocol version.

This contract defines messages only. It does not expose a listening service or
implement an agent. A later service can use these envelopes without changing
their wire representation.

## Durable identity and state

`PlanReference.plan_id` identifies the immutable stored plan. The accompanying
format version selects the decoder for a subsequently retrieved plan.
`last_seen_plan_id` supports safe pull retries without treating a freshly
computed in-memory plan as work. Canonical plan bytes, signatures, and their
digest algorithm are intentionally deferred to the approval/signing contract;
v1 does not freeze a digest whose input representation is not yet defined.

Each state report has a planner-issued plan ID and an agent-issued transition
ID. Repeating the same transition ID must be idempotent when persistence is
implemented. The planner remains authoritative: the response reports the
stored state and whether the requested transition was accepted.

The initial allowed transitions mirror the durable local plan lifecycle:

| From | To |
| --- | --- |
| `COMPUTED` | `RUNNING`, `BLOCKED` |
| `BLOCKED` | `RUNNING` |
| `RUNNING` | `BLOCKED`, `SUCCEEDED`, `FAILED` |

`SUCCEEDED` and `FAILED` are terminal. Reports with `UNSPECIFIED`, unknown
states, or another transition are invalid and must not mutate planner state.

## Compatibility rules

Within `tenkai.agent.v1`, compatible changes may only add fields with new field
numbers, add new messages, or add enum values. New fields must be optional in
practice: old senders omit them and receivers must provide safe defaults. Old
receivers ignore unknown fields, as covered by the Rust wire-compatibility
test. Golden encodings lock the existing field numbers and wire types. Unknown
enum values must be rejected for state mutation rather than coerced to an
existing state.

Existing fields, field numbers, wire types, meanings, and enum numbers must not
change. Fields and enum values must not be removed or reused. A change that
cannot follow those rules requires a new package such as `tenkai.agent.v2`, a
matching `protocol_version = 2`, and an explicit rollout in which both versions
can coexist. Changing the envelope version while keeping a breaking contract
in the `v1` package is not permitted.
