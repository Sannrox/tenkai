# Plan 08 — Drift detection

**Task:** Detect differences between declared deployment state and executor-
observed state.

**Depends on:** Plans 01 and 04.

## Scope

- Add an executor observation operation with structured installed version and
  health results.
- Store reported state separately from desired and last-applied state.
- Classify missing, unexpected, version, and health drift.
- Surface drift in status and make it an explicit input to plan creation.

## Acceptance criteria

- Manual removal of a deployed product is reported as missing drift.
- A mismatched installed version produces a corrective step.
- Observation failures are not treated as proof that a product is absent.
- Status clearly separates desired, last applied, and observed values.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```
