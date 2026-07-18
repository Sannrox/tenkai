# Release signing format

Tenkai release signatures use a detached JSON envelope with
`schema: "tenkai.release-signature.v1"`. The envelope contains a statement,
an Ed25519 signature over the canonical binary encoding described below, and a
`sha256:<hex>` key id. The statement binds these fields:

- `manifest_digest`: SHA-256 of the manifest bytes exactly as published.
- `artifact_digest`: Tenkai's deterministic digest of the declared deploy inputs.
- `provenance`: source URL, source revision, builder identity, build time in Unix
  milliseconds, and an optional URL-to-SHA-256 map of source materials.

The canonical signed bytes do not depend on JSON serialization. They start with
the ASCII domain separator `TENKAI-RELEASE-SIGNATURE-V1` plus a NUL byte,
followed by the manifest digest, artifact digest, source URL, revision, and
builder as UTF-8 byte strings, each prefixed by its unsigned 64-bit big-endian
byte length. The build time follows as a signed 64-bit big-endian integer, then
the unsigned 64-bit big-endian number of materials. Materials are sorted by URL
and each URL and digest uses the same length-prefixed byte-string encoding.

Unknown JSON fields, duplicate material URLs, invalid digests, malformed or
non-canonical URLs, URLs containing credentials, and invalid field values are
rejected. Producers must emit URLs in the exact canonical representation
defined by the WHATWG URL parser used by the `url` Rust crate.

Trust roots are a TOML file containing Ed25519 public keys and their operator-
assigned identities:

```toml
version = 1

[[signers]]
key_id = "sha256:<sha256-of-the-32-byte-public-key>"
identity = "release@example.com"
public_key = "<base64-encoded-32-byte-Ed25519-public-key>"
```

Signer identity comes only from this local trust-root file, never from the
untrusted signature envelope. Duplicate keys or identities and key ids that do
not match their public keys are rejected.

## Publication policy

Publication fails closed unless both `--signature` and `--trust-roots` are
provided. Tenkai strictly verifies the Ed25519 signature and compares both
signed digests with the manifest and declared deploy inputs before creating a
snapshot or modifying the catalog.

Unsigned publication is available only through the conspicuous
`--allow-unsigned-development` flag. It is intended for local development and
cannot be combined with signature options. Automation and non-development
publication must omit this escape hatch and therefore remain fail closed.
