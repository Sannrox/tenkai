# Plan 06 — Product dependencies

**Task:** Let a release declare semver dependencies on other products.

**Depends on:** Plan 03.

## Scope

- Extend the manifest with product dependency names and semver ranges.
- Persist immutable dependency metadata on release publication.
- Validate self-dependencies, duplicate declarations, invalid ranges, and
  references to unavailable releases.
- Expose dependency metadata in release inspection output.

## Acceptance criteria

- A published release retains its exact dependency declarations.
- Invalid dependency declarations are rejected before graph mutation.
- Republishing cannot alter dependencies for an existing release.
- Manifests without dependencies remain compatible.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```
