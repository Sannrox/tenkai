# Plan 03 — Generic constraint model

**Task:** Add a typed, auditable constraint model and evaluator to plan
computation.

**Depends on:** Plan 00.

## Scope

- Add graph types linking constraints to environments or subscriptions.
- Define constraint identity, kind, parameters, enabled state, and reason.
- Return structured allow, deny, and not-applicable evaluations.
- Store evaluation evidence with the durable plan.
- Fail closed for unknown enabled constraint kinds.

## Acceptance criteria

- Constraints can be created, listed, enabled, and disabled for an environment.
- Plan creation records every evaluated constraint and its result.
- A denied or unknown enabled constraint prevents an executable plan.
- Evaluation order does not alter the result.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```
