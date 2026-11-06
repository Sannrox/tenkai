# Releasing Tenkai

Family versioning, tagging, and release policy:
[ADR 0040](docs/decisions/0040-family-versioning-and-release-policy.md).

Sibling family repositories link that ADR from their own `RELEASING.md`. This
page is Tenkai-local: how a maintainer prepares and tags **this** repository.

## Who cuts a tag

Agents never push `v*` tags. A prepare-release job checks the changelog and
workspace version and opens the version-bump pull request. After merge, the
maintainer or a keyless workflow identity creates an annotated, signed
`vX.Y.Z` or `vX.Y.Z-rc.N` tag. The tag must equal the workspace version. The
workflow refuses unsigned or lightweight tags.

## Tenkai-local surfaces

Confirm compatibility for any public or host-facing contract in the range.
The checklist lives in [release readiness](docs/release-readiness.md). In
short: crate version, SQLite schema, runtime protocol, HTTP contract, CLI,
and signed release identity.

## Prepare

1. Choose the target version. Do not invent one in a feature pull request.
2. Draft notes with `scripts/changelog-draft.sh`. Pull requests never edit
   `CHANGELOG.md`; the release step writes the section from merged work.
   The section heading is `## vX.Y.Z (date)` or `## [X.Y.Z]` (a release
   candidate uses its full version, `## v0.7.0-rc.1 (date)`); its body is the
   GitHub Release body. List gate markers on one required line,
   `Gate flags: breaking, migration, realm` (any subset, or `none`), from the
   `risk:breaking` and `risk:migration` pull requests and any realm change
   since the previous final tag (an rc never starts the range). The release
   manifest copies them.
3. Walk [release readiness](docs/release-readiness.md). Pair with the
   project-local `prepare-release` skill.
4. Land the version-bump pull request. Crate versions move in lockstep.

## Tag

Create an annotated, signed tag on the merged release commit on `main`:

```text
vX.Y.Z
```

A tag is never moved, deleted, or reused. The tagged commit must be on
`main`; the workflow refuses any other commit.

## Release candidates

Cut `vX.Y.Z-rc.N` (N from 1, no leading zeros) before the final tag:

1. Land a version-bump pull request that sets the workspace version to
   `X.Y.Z-rc.N` and adds a `## [X.Y.Z-rc.N]` (or `## vX.Y.Z-rc.N (date)`)
   section to `CHANGELOG.md` with its `Gate flags:` line. The final `vX.Y.Z`
   needs its own section; it never reuses the rc notes.
2. Tag `vX.Y.Z-rc.N` on that commit.
3. The release publishes as a GitHub pre-release and is never marked latest.

A failed release candidate costs only an rc number. A final tag on a commit
whose workspace version is still `X.Y.Z-rc.N` is refused. The workflow
accepts no other suffix (no `-beta.N` yet). Fix on `main` first. The tagged
commit must be on `main`, so a tag whose commit lives only on `release/vX.Y`
is not releasable.

## Start, retry, and dry-run

A `v*` tag push runs `.github/workflows/release-dispatch.yml`. It only runs
`gh workflow run release-binaries.yml --ref main -f tag=<tag>`, so the
release always runs **main's** `release-binaries.yml`, never the copy at the
tagged commit.

`release-binaries.yml` refuses a tagged run that does not start from `main`.
It then:

- checks out the tag and fetches the annotated tag object
- verifies the signed tag with main's `scripts/verify-release-tag.sh` and
  main's allowed keys against the tagged commit's `Cargo.toml`
- requires the tagged commit to be on `main`
- builds the hosts, writes a CycloneDX SBOM, attests provenance and the SBOM,
  and writes the manifest `git_sha` from that commit
- drafts the GitHub Release with `gh release create <tag> --verify-tag` from
  the matching CHANGELOG section, attaches the hosts with `tenkai-release.json`,
  the attested [family release manifest](docs/family-release-manifests.md),
  and publishes it last

Tenkai ships no images, so no image or `latest` tag is produced. The
manifest is what Tenkai admits: digests, not floating names.

To retry a failed release, fix the workflow on `main` and run it again for
the same tag:

```sh
gh workflow run release-binaries.yml --ref main -f tag=vX.Y.Z
```

A retry picks up fixes to `release-binaries.yml` and to the tag verifier and
keys. Everything else (the release scripts, `CHANGELOG.md`, and the sources)
comes from the tagged commit, so a bug there needs a new rc or patch version.

A re-run resumes the draft release and replaces its assets. Every job that
uploads, attests, or publishes refuses a release that is already published,
so neither a new run nor "Re-run failed jobs" on an old one can change it;
cut a new version instead. One run per tag executes at a time.

Pull requests run `scripts/release-dry-run.sh`, which never attests or
publishes. `workflow_dispatch` without a tag dry-runs the same packaging
path on that ref.

Attestations record the workflow that built the artifacts, which is main's
`release-binaries.yml` at `refs/heads/main`, not the tag. The source is
pinned by the signed tag and by the manifest `git_sha`, which is the tagged
commit.

To trust a new tag signing key, add its public key to
`security/release-tag-key.asc` and its fingerprint to
`security/release-tag-fingerprints` in a reviewed pull request.

Provenance and binary layout: [release binaries](docs/release-binaries.md),
[release signing](docs/release-signing.md),
[release provenance](docs/release-provenance.md).
