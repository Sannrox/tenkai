#!/usr/bin/env bash
# List the changes merged to main (or RELEASE_BRANCH) since its last final
# release tag, newest first, as a starting point for the release owner's
# CHANGELOG.md section. Release candidates (vX.Y.Z-rc.N) are skipped, so a
# final section covers the whole range its candidates tried. Pass a tag to
# start elsewhere. Set RELEASE_BRANCH=release-X.Y for a maintenance-line
# release. Pull requests do not edit CHANGELOG.md; their bodies carry the
# release notes.
set -euo pipefail

ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "${ROOT_PATH}"

branch="${RELEASE_BRANCH:-main}"
[[ "$branch" == main || "$branch" =~ ^release-[0-9]+\.[0-9]+$ ]] || { echo "RELEASE_BRANCH must be main or release-X.Y, not ${branch}" >&2; exit 1; }
git fetch --quiet --tags origin "+refs/heads/${branch}:refs/remotes/origin/${branch}"
ref="refs/remotes/origin/${branch}"
since="${1:-$(git describe --tags --abbrev=0 --match 'v*' --exclude '*-*' "$ref" 2>/dev/null || git rev-list --max-parents=0 "$ref")}"
echo "## Unreleased (since ${since})"
echo
git log --first-parent --format='- %s' "${since}..${ref}"
