# Release signing format

Tenkai release signatures use a detached JSON envelope with
`schema: "tenkai.release-signature.v1"`. The envelope contains a statement,
an Ed25519 signature over the canonical binary encoding described below, and a
`sha256:<hex>` key id. The statement binds these fields:

- `manifest_digest`: SHA-256 of the manifest bytes exactly as published.
- `artifact_digest`: Tenkai's deterministic identity digest of the declared
  deploy inputs plus any digest-bound OCI artifact references. File-only
  releases keep today's input-tree digest. Naming an artifact by digest
  changes the signed identity; a tag is never part of that identity.
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
# optional Unix milliseconds (#812); omit both to leave validity unrecorded
# not_before = 1700000000000
# not_after = 1800000000000
```

Signer identity comes only from this local trust-root file, never from the
untrusted signature envelope. Duplicate keys or identities and key ids that do
not match their public keys are rejected. Optional `not_before` and `not_after`
are Unix milliseconds. A signature verified before `not_before` or after
`not_after` is refused with that field named. Files that omit the fields stay
valid and report `signer_validity: "not_recorded"`. Older releases that do not
know the fields refuse a file that has them ([ADR 0039](decisions/0039-signer-validity-windows.md)).

## Publication policy

Publication fails closed unless both `--signature` and `--trust-roots` are
provided. Tenkai strictly verifies the Ed25519 signature and compares both
signed digests with the manifest and declared deploy inputs before creating a
snapshot or modifying the catalog.

When a release names OCI artifacts, each `[[artifacts]]` entry must include
`registry`, `repository`, `digest`, and `media_type`. Publication verifies the
declared digest against a live registry adapter (`TENKAI_OCI_STORE` for the
filesystem adapter). Unresolvable or mismatched bytes fail closed and name the
digest. The Catalog stores the reference; it is not a second registry.

An entry may also declare the artifact's SBOM:

```toml
[[artifacts]]
registry = "registry.example.com"
repository = "edge/app"
digest = "sha256:<image digest>"
media_type = "application/vnd.oci.image.manifest.v1+json"
sbom = { digest = "sha256:<sbom digest>", media_type = "application/spdx+json" }
```

The SBOM digest and media type are bound into the release identity, so
changing either changes the release, and the release stores the reference. A
malformed SBOM reference is refused naming its artifact. An artifact without
an SBOM binds exactly as before, so existing release identities do not change.
Releases do not need SBOMs; an offline bundle build that carries them may
require them.

Apply pulls those artifacts only from the environment's
`artifact_mirror.<registry>` host (`tenkaictl env artifact-mirror set`). A
missing mirror refuses origin pull. Cached files and retained references do
not grant execution authority. Signed offline bundles may carry the same
digest-bound layers for air-gapped import; see
[offline bundles](offline-bundles.md).

Unsigned publication is available only through the conspicuous
`--allow-unsigned-development` flag. It is intended for local development and
cannot be combined with signature options. Unsigned releases can only be
planned and applied to the built-in `local` environment. Automation and
non-development publication must omit this escape hatch and therefore remain
fail closed.

## Stored evidence

Every publication stores `verification_status` and `signature_algorithm` in a
deterministic immutable verification-claim object linked from the release.
Verified claims also retain the trust-root signer identity and key id, the
verified public key, canonical statement digest, signed provenance JSON, and
detached envelope. Non-local planning and apply authenticate that retained
envelope and compare every content-bound field before trusting the claim.
Keeping trust evidence separate avoids changing or rewriting the existing
`tenkai.release` schema.

After upgrading Tenkai, run `tenkaictl init` to register the verification-claim
schema. An existing release may be verified by republishing its unchanged
content with a valid trusted signature. Concurrent claims are
first-writer-wins; retries with the same evidence are idempotent and different
evidence is rejected. Partial or conflicting evidence is never overwritten.

Use `tenkaictl release inspect <product>@<version>` to query the stored status,
signer, content digests, statement digest, and provenance. Use
`tenkaictl release verify <product>@<version> --trust-roots <path>` to recompute
the manifest and declared-artifact digests, strictly verify the retained
envelope with the current trust roots, and require the resulting signer,
digests, statement digest, and provenance to equal the stored evidence.

## Production signer

Release, offline-bundle, and plan-approval signatures share one signer
interface. A deploy profile names the backend:

```toml
version = 1
class = "production"
[key_provider]
kind = "pkcs11"
[signer]
kind = "pkcs11"
```

`kind` is `lab`, `file`, or `pkcs11`. Production refuses `lab` and `file`, so
a supported production profile never keeps a signing seed on disk. PKCS#11
holds the Ed25519 private key on the token (a software token stands in for CI)
and never exports it. Opening a PKCS#11 signer restores a previously
provisioned key and refuses a missing or ambiguous label. Provisioning mints
the labeled pair when the token has none. The module, token label, PIN, and
object label come from `TENKAI_SIGNER_MODULE`, `TENKAI_SIGNER_TOKEN`,
`TENKAI_SIGNER_PIN`, and optional `TENKAI_SIGNER_KEY_LABEL`. The PIN is a
secret setting; see [environment variables](environment-variables.md#secret-files).

`tenkaictl dev` signing remains laptop dogfood. It writes owner-only seed
files and is not a production signer.
