# Plan 11 — Release signing

**Task:** Verify release signatures and provenance during publication.

**Depends on:** None.

## Scope

- Choose and document one initial signature envelope and trust-root mechanism.
- Bind the signature to the canonical manifest digest and artifact digests.
- Persist signer identity, verification result, and provenance metadata.
- Add an explicit development policy for unsigned releases; default non-local
  policy remains fail closed.

## Acceptance criteria

- A valid trusted signature permits publication.
- Modified content, an untrusted signer, or malformed provenance is rejected.
- Verification evidence is queryable from the release object.
- Reverification produces the same identity and digest result.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```
