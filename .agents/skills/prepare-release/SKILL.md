---
name: prepare-release
description: Prepare a tenkai release by auditing version scope, compatibility, migrations, validation, artifacts, and release notes. Use when a maintainer asks for release readiness, a version bump plan, or a draft GitHub Release.
---

# Prepare Release

Assemble decision-ready release evidence. Do not tag, push, publish, or alter
GitHub state unless the maintainer explicitly authorizes that action.

Use the maintained operator checklist in `docs/release-readiness.md` as the
canonical gate list for versions, contracts, security, and validation commands.

## Procedure

1. Identify the target version, base tag, target commit, and milestone or merged
   PR range. Read `Cargo.toml`, the release workflow, and open release-blocking
   Issues. Complete when the exact release contents are bounded.
2. Classify changes as `Added`, `Changed`, `Fixed`, `Security`, or `Migration`.
   Check SemVer fit; before `1.0`, call out all public breaking changes even when
   they fit a minor bump. Complete when every user-visible merged change is
   represented once.
3. Audit release impact:
   - `Cargo.toml` version and lockfile consistency;
   - public CLI, vendored protocol, manifest, and sekai-chisei compatibility;
   - ontology, graph-record, runtime-state, and configuration migration impact;
   - environment variables, defaults, examples, and operator documentation;
   - signing, approval, security, recovery, rollback, and operator actions;
   - `tenkaictl` binary and GitHub Release community hosts
     (`docs/release-binaries.md`); any container or bundle packaging.
   Complete when every applicable item is resolved or a named blocker.
4. Use `verify-change` for the full local gates. Confirm current GitHub CI and
   security checks when access is available. Do not run live-provider tests
   without intentional prerequisites. Complete when evidence is current for the
   target commit.
5. Draft concise user-facing release notes. Put upgrade and migration actions
   before internal implementation detail. Credit contributors through GitHub's
   generated notes rather than maintaining a manual ledger.
6. After an authorized tag `vX.Y.Z`, confirm the Release binaries workflow
   attached the five community hosts for `linux-x86_64` and `darwin-aarch64`
   plus `SHA256SUMS`. Do not rewrite existing Release notes when only uploading
   assets. Historical tags before that workflow have no attached hosts.
7. Report go/no-go. A release is `go` only when required checks pass, no known
   blocker remains, rollback/upgrade implications are explicit, and the tagged
   GitHub Release has the checksummed community hosts (or a named blocker).

## Output

Return the target, commit range, readiness checklist, validation results,
compatibility/migration notes, release-note draft, and blockers. Separate
verified facts from recommendations.
