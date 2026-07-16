# Plan 02 — Public API compatibility

**Task:** Establish a versioned compatibility boundary for tenkai's use of
sekai-chisei and its future planner/agent API.

**Depends on:** Plan 00.

## Scope

- Document the supported upstream proto version and update policy.
- Add a compatibility check for the vendored `sekai.proto` and
  `chisei.proto` files.
- Define the initial planner/agent messages around durable plan IDs and state
  transitions without implementing the agent.
- Define additive-change and breaking-change rules.

## Acceptance criteria

- CI detects an unreviewed drift in vendored upstream protos.
- The planner/agent contract identifies its protocol version.
- Unknown additive fields remain compatible.
- Breaking changes require an explicit protocol version change.

## Validation

```bash
cargo build
cargo test
```
