# ADR 0040: Family versioning, tagging, and release policy

- Status: Accepted
- Date: 2026-10-30
- Issue: [#883](https://github.com/Sannrox/tenkai/issues/883)
- Owner: Tenkai maintainers
- Related: [software compatibility](../software-compatibility.md),
  [release signing](../release-signing.md),
  [release provenance](../release-provenance.md),
  [RELEASING.md](../../RELEASING.md)

## Context

Family components version, tag, and publish on their own. Compatibility is
discovered when a plan is built, not declared when a tag is cut. Existing tags
are mixed: some annotated, some lightweight, some unsigned. Some repositories
have no `v*` workflow and no `CHANGELOG.md`. Consumers pin git revisions while
coding and those pins do not move to tags.

Tenkai already admits signed, digest-pinned releases and signed software
compatibility profiles. What was missing is one family policy that every
component can point at from `RELEASING.md`.

This record is that policy. Tenkai holds it because Tenkai owns releases,
channels, and trains. Sibling repositories keep repo-local surfaces, artifacts,
and workflows in their own docs and link here.

## Decision

### 1. Semver per repository

- `0.y.z`: a minor bump may break the listed surface; a patch stays compatible.
- From `1.0`: major for a break, minor for additions, patch for fixes.
- The listed surface is each repository's own list (a `docs/plans/1.0-surface.md`
  or equivalent). Items not on that list may change without a bump.
- Workspace crates move in lockstep with one repository version. No crate is
  published on an independent cycle.
- Registry publish (crates.io, npm) stays off until a maintainer authorizes it.

### 2. 1.0 is a cut, not a code slice

Cutting `1.0` is a deploy-track decision after the listed surface is written.
It is not a coding issue. Proto stays add-only. A `2.0` is only for a breaking
proto, receipt, or storage change, announced one minor ahead.

### 3. Compatibility is declared

- Each component publishes its own compatibility matrix.
- Tenkai holds the family view as signed train profiles. A profile names the
  exact component versions and digests that were tested together. Example
  identity: `train-2026.11`.
- Channels are `candidate` then `stable`. A component joins a train only with
  its matrix and green conformance.
- Git revision pins are off-matrix. A train names tags and digests, not
  floating revisions.

### 4. Pins while coding, tags on the train

- Consumers pin merged SHAs while coding.
- After the lower repository's tag is an immutable GitHub Release, pins move to
  that tag.
- Release manifests and Tenkai plans reference digests only. A tag-only or
  `latest` image reference is refused at admission.

### 5. Proto, HTTP, receipts, and SDKs

- Proto: add fields; never renumber or reuse field numbers. Checked against
  the last tag.
- HTTP APIs use a versioned path (`/v1`). OpenAPI diff runs in CI. Breaking
  changes are announced in `BREAKING.md` (or the CHANGELOG Breaking section)
  before the bump.
- Receipts and evidence use versioned schema ids (`…/v1`). Readers accept N-1.
  A breaking schema gets a new id.
- SDKs are generated and versioned with the server minor.
- After `1.0`, removals need one minor of deprecation warning. Internal protos
  keep one minor plus one train.

### 6. Schemas and storage formats

- Every persisted format carries a magic or version.
- Migrations are additive and forward-only, with a schema target bump.
- A CI test opens N-1 data with the new release.
- Unknown versions fail closed.
- Rebuildable projections may bump freely and must fail closed on unknown
  versions.

### 7. CLI and config

Config files carry a `version`. Unknown versions fail closed. CLI flags and
commands get one minor of deprecation warning before removal. `--json` output
is versioned like an HTTP API.

### 8. Changelog and release notes

- `CHANGELOG.md` follows Keep a Changelog, with Upgrade and Breaking sections.
- Pull requests never edit `CHANGELOG.md`. The release step drafts the section
  from merged pull requests.
- The GitHub Release body is generated from that section.
- Gate markers (migration, realm, breaking) are listed explicitly so Tenkai
  can copy them onto the signed release manifest.

### 9. Breaking-change CI

A pull request that breaks a listed surface without the matching version bump
and Breaking note fails CI.

| Check | Where |
| --- | --- |
| `cargo-semver-checks` against the pull request base | Library crates |
| `buf breaking` against the last tag | Proto |
| OpenAPI diff | HTTP contracts |

### 10. Tagging

1. **Format.** `vX.Y.Z`. Pre-releases are `vX.Y.Z-rc.N` and `vX.Y.Z-beta.N`.
   Leading `v` always. One repository tag; lockstep crate versions. Per-crate
   tags need a later ADR. The release workflow fails if the tag does not equal
   the workspace version.
2. **Annotated and signed.** Every release tag is annotated and signed. The
   workflow runs `git verify-tag` and refuses unsigned or lightweight tags.
   The signer is the maintainer's registered signing key, or a keyless
   workflow identity. There is no long-lived project signing key in the
   repository.
3. **Who cuts tags.** A prepare-release job checks the changelog and version
   and opens the version-bump pull request. After merge, the maintainer or the
   keyless workflow creates the signed tag. Agents never push `v*` tags.
4. **Protection.** A ruleset on `refs/tags/v*` allows create only by repository
   admins and the release workflow or GitHub App, and blocks update and
   deletion. Immutable GitHub Releases are on.
5. **What a tag triggers.** A `v*` push builds, tests, writes an SBOM, attests
   provenance, pushes images by digest (never `latest`), drafts then publishes
   a GitHub Release from the matching CHANGELOG section, and emits a signed
   release manifest for Tenkai: component, version, git SHA, image and binary
   digests, attestation references, and gate flags. Pull requests and dry runs
   never mint attestations.
6. **Immutable tags.** A tag is never moved, deleted, or reused. A bad release
   gets a new patch version.
7. **Hotfixes.** Fix on `main` first. Cherry-pick onto `release/vX.Y`, cut from
   `vX.Y.0` at the first patch need. Tag `vX.Y.(Z+1)` on that branch, never on
   `main` ahead of a minor. Pre-release patches are `vX.Y.(Z+1)-rc.N`. Release
   branches get the same protection as `main`.

### 11. Images, channels, and trains

- Images carry the `vX.Y.Z` tag for humans and the immutable digest. Plans and
  manifests use the digest.
- Tenkai admits the signed manifest into the `candidate` channel. Gate flags
  from merged work since the previous tag (`risk:migration`, realm,
  `risk:breaking`) set a human-approval hold. Promotion to `stable` follows
  the train profile.
- A train profile lists every component of a train by digest.

## Out of scope

Cutting the first tags. Enabling GitHub settings. Per-repository workflow
changes. Those follow this record.

## Consequences

- Sibling repositories add a `RELEASING.md` that links this ADR. This change
  adds Tenkai's page only.
- Follow-up work (rulesets, workflows, breaking CI, train admission, pin
  moves, N-1 format tests, CLI and config version) implements this policy. It
  does not reopen the policy questions.
- Existing lightweight or unsigned tags stay history. New `v*` tags must
  satisfy section 10.
- Coding stays unblocked: SHA pins remain valid until a tag exists.

## Alternatives considered

- **Per-repository policy only.** Rejected: compatibility stays discovered at
  deploy time, which is the problem.
- **Agents push `v*` tags.** Rejected: tags must be annotated and signed, and
  a ruleset cannot tell an agent's push from a maintainer's.
- **Tag-only or `latest` image references.** Rejected: those names move. Tenkai
  already binds identity to digests.
- **Publish crates or npm packages now.** Rejected: registry publish is
  irreversible per version and needs an explicit maintainer authorization.
- **Require a 1.0 surface list in this record.** Rejected: each repository
  owns its listed surface. This record states the bump rules, not Tenkai's
  type list.
