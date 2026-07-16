# Plan 01 — Executor interface

**Task:** Move command execution behind a typed executor interface while
retaining current local shell behavior as the first adapter.

**Depends on:** Plan 00.

## Scope

- Define executor inputs and outputs from the durable step contract.
- Move install, uninstall, health, and rollback command handling out of the
  orchestration path.
- Implement a `local-shell` executor matching current behavior.
- Make executor selection explicit in the manifest with a backward-compatible
  default.
- Keep orchestration responsible for gates and lifecycle transitions.

## Acceptance criteria

- Existing manifests continue to execute with `local-shell` by default.
- Executor failures return structured results rather than terminating the
  orchestration process directly.
- A fake executor can exercise success, failure, health failure, and rollback
  paths without launching commands.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```
