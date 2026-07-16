# Vendored sekai-chisei API

The protobuf files in this directory are the supported upstream API boundary
for tenkai. They are copied without modification from
[`Sannrox/sekai-chisei`](https://github.com/Sannrox/sekai-chisei) commit
`30d52a964ae928cfb3e96e84cd8d17a949d816f3`.

| File | SHA-256 |
| --- | --- |
| `sekai.proto` | `ae62da7bba6fe9e00e5ec8f6f682f547d829c36f4f5865d1708de1a72880af91` |
| `chisei.proto` | `fe6578641d4d1e74e8f57368eb52f151ccc038ccbbebbfc734cfcc3bc2499fcd` |

`build.rs` verifies these digests before generating Rust bindings, normalizing
CRLF to LF so existing cross-platform checkouts hash the same source text. A
changed vendored file therefore fails local builds and CI until its new
contents are reviewed and the pinned digest is updated deliberately.

## Update policy

To adopt a newer upstream API:

1. Copy both proto files from one sekai-chisei commit. Do not mix snapshots.
2. Review the upstream diff using the compatibility rules below.
3. Update the commit and both digests in this document, and update the digests
   in `build.rs` in the same change.
4. Run `cargo build` and `cargo test` against the updated bindings.
5. Exercise tenkai against a server built from the pinned upstream commit.

Additive changes are accepted within the pinned snapshot when they only add
new messages, services, methods, enum values, or fields with previously unused
numbers. Existing field numbers, types, cardinality, service methods, and
request/response types must remain unchanged. Fields may be deprecated but not
reused.

Removing or renaming an existing API element, reusing a field number, changing
a field's wire type or meaning, changing cardinality, or changing an RPC
signature is breaking. A breaking upstream change requires a new explicitly
versioned tenkai integration boundary; updating these digests alone is not
sufficient.
