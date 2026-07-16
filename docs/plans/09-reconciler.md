# Plan 09 — Environment reconciler

**Task:** Add a restart-safe loop that continuously converges registered
environments from subscriptions and observed state.

**Depends on:** Plans 02, 07, and 08.

## Scope

- Reconcile each eligible environment through observe, plan, and execute
  states.
- Add idempotency, retry backoff, and per-environment execution serialization.
- Resume safely after process restart without duplicating successful steps.
- Retain an explicit one-shot mode for local operation and tests.

## Acceptance criteria

- Promoting a subscribed channel causes convergence without a manual apply.
- Concurrent ticks cannot execute two plans for the same environment.
- Restarting during a plan resumes or terminates it deterministically.
- A failing environment does not block reconciliation of another environment.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```
