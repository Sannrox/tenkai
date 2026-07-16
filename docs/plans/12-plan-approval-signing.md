# Plan 12 — Plan approval and signing

**Task:** Require policy approval and a verifiable signature before a durable
plan may execute.

**Depends on:** Plans 00, 02, and 11.

## Scope

- Define canonical plan bytes and a signed approval envelope.
- Resolve approval policy for the target environment through chisei.
- Bind approvals to the exact immutable plan, environment, and expiry.
- Verify authorization and signature immediately before execution.
- Record bypasses only under an explicit local-development policy.

## Acceptance criteria

- Altering any executable plan field invalidates its approval.
- A missing, expired, unauthorized, or wrongly scoped approval blocks apply.
- Approved plans expose signer, policy decision, and verification evidence.
- Local bypass is visible in the graph and disabled by default outside local.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```
