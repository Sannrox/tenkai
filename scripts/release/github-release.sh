#!/usr/bin/env bash
# The only script that changes a GitHub Release. Every command first refuses a
# published release and fails closed when the lookup fails, so "Re-run failed
# jobs" can resume a draft but never rewrite what was published. A tag with
# "-" is a pre-release; a pre-release or a release from a previous maintenance
# line is never marked latest. Needs GH_TOKEN and GH_REPO.
#
# Usage:
#   bash scripts/release/github-release.sh guard <tag>
#       Exit 0 when the release is a draft or does not exist yet.
#   bash scripts/release/github-release.sh draft <tag> <notes> <asset>...
#       Create the draft with these assets, or resume it: upload them again
#       and reset title, notes, and pre-release state.
#   bash scripts/release/github-release.sh publish <tag> <line>
#       Publish the draft. <line> is main or the release-* line the tagged
#       commit was accepted from (verify-tag.sh release-commit).
set -euo pipefail

fail() {
  printf 'github-release: %s\n' "$1" >&2
  exit 1
}

# Prints "draft" or "missing"; fails on a published release or a lookup error.
# A token that cannot see drafts reports a draft as not found.
release_state() {
  local tag="$1" state
  if state="$(gh release view "$tag" --json isDraft --jq .isDraft 2>&1)"; then
    [[ "$state" == true ]] || fail "release ${tag} is already published; releases are immutable"
    echo draft
  elif [[ "$state" == *"release not found"* ]]; then
    echo missing
  else
    fail "cannot read release ${tag}: ${state}"
  fi
}

prerelease() {
  if [[ "$1" == *-* ]]; then echo true; else echo false; fi
}

cmd="${1:-}"
[[ $# -ge 1 ]] && shift
case "$cmd" in
  guard)
    [[ $# -eq 1 ]] || fail "usage: $0 guard <tag>"
    release_state "$1" >/dev/null
    ;;
  draft)
    [[ $# -ge 3 ]] || fail "usage: $0 draft <tag> <notes> <asset>..."
    tag="$1" notes="$2"
    shift 2
    pre="$(prerelease "$tag")"
    state="$(release_state "$tag")"
    if [[ "$state" == draft ]]; then
      gh release upload "$tag" "$@" --clobber
      gh release edit "$tag" --title "$tag" --notes-file "$notes" --draft --prerelease="$pre"
    else
      gh release create "$tag" "$@" --draft --verify-tag --prerelease="$pre" --title "$tag" --notes-file "$notes"
    fi
    ;;
  publish)
    [[ $# -eq 2 ]] || fail "usage: $0 publish <tag> <line>"
    tag="$1" line="$2"
    [[ "$line" == main || "$line" == release-* ]] || fail "invalid release line: ${line}"
    pre="$(prerelease "$tag")"
    latest=false
    [[ "$pre" == false && "$line" == main ]] && latest=true
    state="$(release_state "$tag")"
    [[ "$state" == draft ]] || fail "release ${tag} has no draft to publish"
    gh release edit "$tag" --draft=false --prerelease="$pre" --latest="$latest"
    echo "Published GitHub Release ${tag}"
    ;;
  *)
    fail "usage: $0 {guard|draft|publish} <tag> ..."
    ;;
esac
