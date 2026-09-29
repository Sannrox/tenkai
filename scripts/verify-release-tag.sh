#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/$(basename -- "${BASH_SOURCE[0]}")"

fail() {
  printf 'verify-release-tag: %s\n' "$1" >&2
  exit 1
}

verify_release_tag() {
  local tag="$1" expected_commit="$2" remote="${3:-origin}"
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "invalid release tag: ${tag}"
  [[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]] || fail "expected commit must be a full lowercase SHA"

  local direct_ref="refs/tags/${tag}" peeled_ref="refs/tags/${tag}^{}" refs direct peeled actual
  refs="$(git ls-remote "$remote" "$direct_ref" "$peeled_ref")" || fail "could not read release tag"
  direct="$(awk -v ref="$direct_ref" '$2 == ref { print $1; exit }' <<<"$refs")"
  peeled="$(awk -v ref="$peeled_ref" '$2 == ref { print $1; exit }' <<<"$refs")"
  actual="${peeled:-$direct}"

  [[ -n "$actual" ]] || fail "tag ${tag} was not found"
  [[ "$actual" =~ ^[0-9a-f]{40}$ ]] || fail "tag ${tag} did not resolve to a commit"
  [[ "$actual" == "$expected_commit" ]] || fail "tag ${tag} resolves to ${actual}, expected ${expected_commit}"
  printf 'Release tag %s resolves to triggering commit %s\n' "$tag" "$expected_commit"
}

expect_failure() {
  local message="$1" output
  shift
  if output="$(bash "$SCRIPT_PATH" verify "$@" 2>&1)"; then
    fail "expected verification failure containing: ${message}"
  fi
  [[ "$output" == *"$message"* ]] || fail "verification failed without expected message: ${message}"
}

self_test() {
  local tmp remote work first second
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/tenkai-release-tag.XXXXXX")"
  trap "rm -rf $(printf '%q' "$tmp")" EXIT
  remote="${tmp}/remote.git"
  work="${tmp}/work"
  git init --bare -q "$remote"
  git init -q "$work"
  git -C "$work" config user.name "Release tag self-test"
  git -C "$work" config user.email "release-tag-self-test@example.invalid"
  git -C "$work" config commit.gpgsign false
  git -C "$work" config tag.gpgSign false
  git -C "$work" config core.editor :

  printf 'first commit\n' >"${work}/source"
  git -C "$work" add source
  git -C "$work" commit -q -m first
  first="$(git -C "$work" rev-parse HEAD)"
  git -C "$work" tag v1.0.0 "$first"
  git -C "$work" tag -a v1.0.1 -m annotated "$first"
  git -C "$work" push -q "$remote" refs/tags/v1.0.0 refs/tags/v1.0.1

  bash "$SCRIPT_PATH" verify v1.0.0 "$first" "$remote" >/dev/null
  bash "$SCRIPT_PATH" verify v1.0.1 "$first" "$remote" >/dev/null

  printf 'second commit\n' >>"${work}/source"
  git -C "$work" commit -qam second
  second="$(git -C "$work" rev-parse HEAD)"
  git -C "$work" tag --force v1.0.0 "$second" >/dev/null
  git -C "$work" push -q --force "$remote" refs/tags/v1.0.0
  expect_failure "expected ${first}" v1.0.0 "$first" "$remote"
  bash "$SCRIPT_PATH" verify v1.0.0 "$second" "$remote" >/dev/null
  expect_failure "was not found" v1.0.2 "$second" "$remote"
  printf 'release tag self-test passed\n'
}

case "${1:-}" in
  verify)
    shift
    [[ $# -ge 2 && $# -le 3 ]] || fail "usage: $0 verify <tag> <commit-sha> [remote]"
    verify_release_tag "$1" "$2" "${3:-origin}"
    ;;
  self-test)
    [[ $# -eq 1 ]] || fail "usage: $0 self-test"
    self_test
    ;;
  *)
    fail "usage: $0 {verify <tag> <commit-sha> [remote]|self-test}"
    ;;
esac
