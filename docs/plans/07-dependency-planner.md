# Plan 07 — Dependency-ordered planner

**Task:** Produce a deterministic topological plan satisfying product
dependencies, environment facts, and version constraints.

**Depends on:** Plans 04, 05, and 06.

## Scope

- Resolve subscribed channel heads and their transitive dependencies.
- Select compatible published releases using semver ranges.
- Topologically order installs/upgrades and reverse the order for removals or
  rollback where required.
- Detect cycles and unsatisfiable dependency sets.
- Do not introduce a general SAT solver.

## Acceptance criteria

- Dependencies are installed before dependents regardless of product name.
- The same graph and environment facts produce byte-equivalent ordered steps.
- Cycles and incompatible ranges produce no executable plan and explain the
  conflict.
- A version-pinned environment never receives an invalid dependency solution.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```
