# Plan 14 — Intelligence-artifact deployment

**Task:** Deliver one governed intelligence-artifact product through the same
plan and executor lifecycle used for software.

**Depends on:** Plans 01, 03, and 12.

## Scope

- Add one concrete product type: model-routing configuration.
- Define its immutable manifest payload, validation, executor adapter, health
  or postcondition check, and rollback behavior.
- Apply through sekai-chisei APIs rather than shell or cluster execution.
- Reuse durable plans, constraints, gates, approval, and deployment records.

## Acceptance criteria

- A routing-config release can be published, promoted, planned, applied, and
  rolled back.
- Invalid references or policy violations fail before mutation.
- Software and routing-config steps can coexist in one ordered plan.
- Audit lineage reaches the release, plan, environment, and resulting config.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```
