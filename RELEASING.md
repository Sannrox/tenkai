# Releasing Tenkai

Family versioning, tagging, and release policy:
[ADR 0040](docs/decisions/0040-family-versioning-and-release-policy.md).

Sibling family repositories link that ADR from their own `RELEASING.md`. This
page is Tenkai-local: how a maintainer prepares and tags **this** repository.

## Who cuts a tag

Agents never push `v*` tags. A prepare-release job checks the changelog and
workspace version and opens the version-bump pull request. After merge, the
maintainer or a keyless workflow identity creates an annotated, signed
`vX.Y.Z` tag. The tag must equal the workspace version. The workflow refuses
unsigned or lightweight tags.

## Tenkai-local surfaces

Confirm compatibility for any public or host-facing contract in the range.
The checklist lives in [release readiness](docs/release-readiness.md). In
short: crate version, SQLite schema, runtime protocol, HTTP contract, CLI,
and signed release identity.

## Prepare

1. Choose the target version. Do not invent one in a feature pull request.
2. Draft notes with `scripts/changelog-draft.sh`. Pull requests never edit
   `CHANGELOG.md`; the release step writes the section from merged work.
   The section heading is `## vX.Y.Z (date)` or `## [X.Y.Z]`; its body is the
   GitHub Release body. List gate markers on one line,
   `Gate flags: breaking, migration, realm` (any subset, or `none`), from the
   `risk:breaking` and `risk:migration` pull requests and any realm change in
   the range. The release manifest copies them.
3. Walk [release readiness](docs/release-readiness.md). Pair with the
   project-local `prepare-release` skill.
4. Land the version-bump pull request. Crate versions move in lockstep.

## Tag

Create an annotated, signed tag on the merged release commit:

```text
vX.Y.Z
```

Pre-releases are `vX.Y.Z-rc.N` or `vX.Y.Z-beta.N`. Hotfixes are tagged on
`release/vX.Y`, never on `main` ahead of a minor. A tag is never moved,
deleted, or reused.

## After the tag

The `v*` workflow refuses a lightweight, unsigned, or off-version tag, then
builds the hosts, writes a CycloneDX SBOM, attests provenance and the SBOM,
and attaches the hosts with `tenkai-release.json`, the attested
[family release manifest](docs/family-release-manifests.md). It drafts the
GitHub Release from the matching CHANGELOG section, then publishes it. Tenkai
ships no images, so no image or `latest` tag is produced. The manifest is
what Tenkai admits: digests, not floating names. Pull requests run the
release dry run (`scripts/release-dry-run.sh`), which never attests or
publishes.

To trust a new tag signing key, add its public key to
`security/release-tag-key.asc` and its fingerprint to
`security/release-tag-fingerprints` in a reviewed pull request.

Provenance and binary layout: [release binaries](docs/release-binaries.md),
[release signing](docs/release-signing.md),
[release provenance](docs/release-provenance.md).
