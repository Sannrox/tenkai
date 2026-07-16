# Plan 10 — Maintenance windows

**Task:** Enforce environment maintenance windows in reconciliation.

**Depends on:** Plans 03, 04, and 09.

## Scope

- Add timezone-aware recurring maintenance-window constraints.
- Separate plan computation from authorization to begin execution.
- Permit explicit emergency override with principal, reason, and audit record.
- Define behavior for a window closing during an active plan.

## Acceptance criteria

- A valid plan remains pending outside its maintenance window.
- It becomes eligible when the window opens without recomputation unless its
  inputs changed.
- Invalid or ambiguous timezone rules fail closed.
- Emergency override requires and records a non-empty reason.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```
