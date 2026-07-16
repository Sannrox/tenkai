# Plan 18 — Deployment outcome learning

**Task:** Feed normalized rollout outcomes into chisei and expose learned risk
as non-authoritative planner evidence.

**Depends on:** Plans 15 and 17.

## Scope

- Define a normalized observation for success, gate failure, health failure,
  execution failure, and rollback.
- Record environment and release features without leaking secrets.
- Query learned failure patterns during planning.
- Surface learned risk as explanation or prioritization evidence; it must not
  silently override deterministic constraints.

## Acceptance criteria

- Every terminal fleet deployment records one idempotent observation.
- A known risky feature combination appears in plan explanation.
- Missing learning service does not break deterministic planning.
- Operators can distinguish learned evidence from hard policy decisions.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```
