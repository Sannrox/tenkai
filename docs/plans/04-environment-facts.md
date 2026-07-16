# Plan 04 — Environment facts and capabilities

**Task:** Add typed environment facts that constraints can evaluate.

**Depends on:** Plan 03.

## Scope

- Define typed facts for connectivity, region, runtime capabilities, and data
  classification.
- Add CLI commands to set and inspect facts with audit attribution.
- Include the fact snapshot used by planning in constraint evidence.
- Distinguish missing facts from false values and fail closed where required.

## Acceptance criteria

- Two environments can hold different typed values for the same fact.
- Updating a fact produces an auditable graph change.
- Plans retain the fact snapshot used for their decision.
- Invalid values are rejected before persistence.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```
