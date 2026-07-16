# Plan 15 — Canary-gated promotion

**Task:** Gate wider channel promotion on successful deployment outcomes from
designated canary environments.

**Depends on:** Plans 09 and 10.

## Scope

- Identify canary environments through explicit facts or subscriptions.
- Define the required canary cohort and success policy for a release.
- Aggregate gate, execution, health, and rollback outcomes.
- Permit wider promotion only when the cohort policy passes.
- Invalidate stale evidence when release content or cohort policy changes.

## Acceptance criteria

- A failed or rolled-back canary blocks wider promotion.
- A passing complete cohort permits promotion with linked evidence.
- Missing canary results do not count as success.
- Promotion audit explains the cohort and every outcome used.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```
