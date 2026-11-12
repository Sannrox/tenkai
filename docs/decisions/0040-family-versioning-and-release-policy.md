# ADR 0040: Family versioning, tagging, and release policy

- Status: Accepted
- Date: 2026-10-30
- Amended: 2026-11-06 ([#915](https://github.com/Sannrox/tenkai/issues/915)),
  §10 tagging (dispatcher from main, tagged commit on main, `-rc.N` first,
  idempotent re-run) and §11 gate-flag range
- Amended: 2026-11-12 ([#1198](https://github.com/Sannrox/tenkai/issues/1198)),
  §10.5 ancestry and §10.9 matching `release-*` maintenance lines
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

1. **Format.** `vX.Y.Z`. Pre-releases are `vX.Y.Z-rc.N` (N from 1, no leading
   zeros). `vX.Y.Z-beta.N` is allowed by this policy; a repository may refuse
   it in its workflow. Leading `v` always. One repository tag; lockstep crate
   versions. Per-crate tags need a later ADR. The release workflow fails if
   the tag does not equal the workspace version.
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
5. **Releases from the default branch for a signed tag.** A `v*` tag push
   starts a tiny dispatcher. The dispatcher only runs
   `gh workflow run <release workflow> --ref main -f tag=<tag>`. The real
   release workflow runs from main, not from the tagged commit. It refuses a
   tagged run that is not from main. It verifies the signed annotated tag with
   main's verifier and allowed keys against the tagged commit, requires that
   commit to be on main or on the matching `release-*` maintenance line
   (`release-<major>.<minor>`, one per minor, before and after 1.0), and uses
   that commit for the CI gate, packaging, images, manifest `git_sha`, and
   GitHub Release. A GitHub Release on a previous line is never marked
   latest. A failed run is fixed on main and re-run for the same tag. A retry
   picks up fixes to the workflow and to the tag verifier and keys only.
   Release scripts, CHANGELOG, and sources come from the tagged commit; a bug
   there needs a new rc or patch. Pull requests and dry runs never mint
   attestations.
6. **Immutable tags.** A tag is never moved, deleted, or reused. A bad
   published release gets a new patch version. A failed draft is retried for
   the same tag.
7. **Release candidates first.** Cut `vX.Y.Z-rc.N` before the final tag. The
   rc tag equals workspace version `X.Y.Z-rc.N` and publishes as a GitHub
   pre-release that is never marked latest. A failed rc costs only an rc
   number. A final tag on a commit whose workspace version is still an rc is
   refused. The final `vX.Y.Z` has its own CHANGELOG section; it never reuses
   the rc notes.
8. **Re-run.** A re-run resumes a draft release and replaces its assets.
   Every job that uploads, pushes, attests, or publishes refuses a release
   that is already published, so neither a new run nor "Re-run failed jobs"
   on an old one can change it. One run per tag at a time.
9. **Hotfixes.** Fix on `main` first, then backport with `git cherry-pick -x`
   onto the matching `release-*` line when a consumer pins that line. Create
   the line from the last tag of that version when the first fix needs it,
   never in advance. Keep at most the current line plus one previous line. A
   tag whose commit lives only on a non-matching `release-*` branch, or on
   any other branch, is not releasable. Pre-release patches are
   `vX.Y.(Z+1)-rc.N` on the same line as the final tag they precede.

### 11. Images, channels, and trains

- Images carry the `vX.Y.Z` tag for humans and the immutable digest. Plans and
  manifests use the digest.
- Tenkai admits the signed manifest into the `candidate` channel. Gate flags
  (`risk:migration`, realm, `risk:breaking`) cover pull requests merged since
  the previous final tag (an rc never starts the range) and only those merged
  into the release commit's range. They set a human-approval hold. Promotion
  to `stable` follows the train profile.
- A train profile lists every component of a train by digest.

## Out of scope

Cutting the first tags. Enabling GitHub settings. Per-repository workflow
file names and extra jobs. Those follow this record; the dispatcher,
main-only run, tagged-commit, rc, and re-run rules above are the shared
shape.

## Consequences

- Sibling repositories add a `RELEASING.md` that links this ADR and keep
  repo-local start, retry, and pre-release steps there.
- Follow-up work (rulesets, workflows, breaking CI, train admission, pin
  moves, N-1 format tests, CLI and config version) implements this policy. It
  does not reopen the policy questions.
- Existing lightweight or unsigned tags stay history. New `v*` tags must
  satisfy section 10.
- Coding stays unblocked: SHA pins remain valid until a tag exists.
- A workflow bug no longer burns a final version: fix main and re-run the
  same tag. A bug in tagged sources still needs a new rc or patch.
- A matching `release-*` line can ship a patch without taking `main`. The
  next family release on `main` should still go through `vX.Y.Z-rc.1` first.

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
- **Run the release workflow from the tagged commit.** Rejected: tags cannot
  be moved or deleted, so a workflow bug that only shows on a real tag run
  burns that version.
- **Run the release workflow from a maintenance branch.** Rejected: tags
  cannot be moved, so a workflow bug on that ref burns the version. The run
  still starts from main; only the ancestry check accepts the matching
  `release-*` line.
- **Hotfix tags on `release/v*` (slash).** Rejected: that name collides with
  `release/<version>` bump branches. Matching lines are `release-*`.
