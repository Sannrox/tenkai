# Plan 17 — Fleet rollout waves

**Task:** Execute a release across an environment fleet in bounded,
observable rollout waves.

**Depends on:** Plans 09 and 15.

## Scope

- Define ordered environment cohorts, concurrency limits, pause conditions,
  and success thresholds.
- Advance only when the current wave satisfies its outcome policy.
- Add fleet status showing release, wave, environment, plan, and failure state.
- Support pause, resume, and abort without losing audit history.

## Acceptance criteria

- No wave exceeds its configured concurrency.
- A failed threshold pauses later waves automatically.
- Resume does not duplicate completed environment deployments.
- Fleet status explains why each environment is pending, active, complete, or
  blocked.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```
