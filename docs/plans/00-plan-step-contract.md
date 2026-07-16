# Plan 00 — Durable plan and step contract

**Task:** Replace ephemeral computed steps with immutable, executable plan
objects stored in the sekai graph.

**Depends on:** None.

## Scope

- Define versioned serialized `Plan` and `Step` structures, including stable
  IDs, environment, creation time, desired-state inputs, ordered steps, and a
  lifecycle state.
- Persist `tenkai.plan` before execution and execute by plan ID rather than by
  passing an in-memory vector directly from `compute` to `apply`.
- Record enough inputs to explain why the plan was produced.
- Reject mutation of a stored plan's executable content.
- Keep dry-run plan output available without executing it.

## Acceptance criteria

- `tenkaictl plan --env <env>` creates and prints a stored plan ID.
- `tenkaictl apply <plan-id>` executes exactly the stored ordered steps.
- Re-running apply does not silently recompute different steps.
- Changing a plan's executable content under an existing ID is rejected.
- Existing gate, health, rollback, and audit behavior remains covered by tests.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```
