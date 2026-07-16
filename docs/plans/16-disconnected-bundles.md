# Plan 16 — Disconnected signed bundles

**Task:** Export and import a self-verifying bundle for one approved plan and
its required release content.

**Depends on:** Plans 11, 12, and 13.

## Scope

- Define a versioned bundle containing the plan, approvals, release manifests,
  artifact references or payloads, signatures, and verification subgraph.
- Export deterministically and verify before any offline execution.
- Let the agent execute an imported bundle without control-plane connectivity.
- Export signed execution receipts and import them idempotently.

## Acceptance criteria

- A valid bundle executes in a network-isolated integration test.
- Any changed plan, manifest, artifact, or approval causes verification failure.
- Receipt import reconstructs the normal audit lifecycle without duplicates.
- Bundle format and size limits are documented.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```
