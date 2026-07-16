# Plan 05 — Version constraints

**Task:** Enforce environment-level version pins and semver ranges during plan
creation.

**Depends on:** Plan 03.

## Scope

- Add exact pin and semver-range constraint kinds.
- Parse product versions and constraint expressions with a standard semver
  implementation.
- Reject channel heads outside the allowed range with an actionable reason.
- Preserve deliberate downgrade behavior when the selected version is valid.

## Acceptance criteria

- An exact pin prevents a newer channel head from being planned.
- A semver range admits and rejects expected boundary versions.
- Invalid versions or ranges fail closed with clear errors.
- Constraint evidence names the product, candidate, and required range.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```
