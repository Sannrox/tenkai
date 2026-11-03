#!/usr/bin/env bash
# Release tag checks for the v* workflow.
#
# Usage:
#   scripts/verify-release-tag.sh verify <tag> <commit-sha> [remote]
#       The live remote tag still resolves to the triggering commit.
#   scripts/verify-release-tag.sh verify-signed <tag> <commit-sha>
#       The local tag object is annotated, signed by a key listed in
#       security/release-tag-fingerprints, resolves to the commit, and equals
#       the workspace version. Lightweight and unsigned tags are refused.
#   scripts/verify-release-tag.sh self-test
set -euo pipefail

SCRIPT_PATH="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/$(basename -- "${BASH_SOURCE[0]}")"
ROOT_PATH="${RELEASE_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
FINGERPRINTS_FILE="${RELEASE_TAG_FINGERPRINTS:-${ROOT_PATH}/security/release-tag-fingerprints}"
KEY_FILE="${RELEASE_TAG_KEY:-${ROOT_PATH}/security/release-tag-key.asc}"

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

# The root package version; workspace crates move in lockstep with it.
workspace_version() {
  awk '
    /^\[/ { in_package = ($0 == "[package]") }
    in_package && /^version = "/ { gsub(/^version = "|"$/, ""); print; exit }
  ' "${ROOT_PATH}/Cargo.toml"
}

normalize_fingerprint() {
  tr '[:lower:]' '[:upper:]' <<<"$1" | tr -d '[:space:]'
}

verify_signed_tag() {
  local tag="$1" expected_commit="$2" object_type actual raw fingerprint primary allowed line version
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "invalid release tag: ${tag}"
  [[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]] || fail "expected commit must be a full lowercase SHA"

  object_type="$(git cat-file -t "refs/tags/${tag}" 2>/dev/null)" || fail "tag ${tag} was not found"
  [[ "$object_type" == tag ]] || fail "tag ${tag} is lightweight; release tags must be annotated and signed"
  actual="$(git rev-parse "refs/tags/${tag}^{commit}")"
  [[ "$actual" == "$expected_commit" ]] || fail "tag ${tag} resolves to ${actual}, expected ${expected_commit}"

  [[ -f "$KEY_FILE" ]] || fail "missing release tag key: ${KEY_FILE}"
  [[ -f "$FINGERPRINTS_FILE" ]] || fail "missing release tag fingerprints: ${FINGERPRINTS_FILE}"
  gpg --batch --quiet --import "$KEY_FILE" >/dev/null 2>&1 || fail "could not import ${KEY_FILE}"
  raw="$(git verify-tag --raw "refs/tags/${tag}" 2>&1)" || true
  line="$(grep -m1 '^\[GNUPG:\] VALIDSIG ' <<<"$raw")" || fail "tag ${tag} is unsigned or its signature is not valid"
  fingerprint="$(normalize_fingerprint "$(awk '{ print $3 }' <<<"$line")")"
  primary="$(normalize_fingerprint "$(awk '{ print $12 }' <<<"$line")")"
  allowed=false
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    line="$(normalize_fingerprint "$line")"
    if [[ "$line" == "$fingerprint" || "$line" == "$primary" ]]; then
      allowed=true
    fi
  done <"$FINGERPRINTS_FILE"
  $allowed || fail "tag ${tag} is signed by a key not listed in ${FINGERPRINTS_FILE##*/}"

  version="$(workspace_version)"
  [[ -n "$version" ]] || fail "Cargo.toml has no [package] version"
  [[ "${tag#v}" == "$version" ]] || fail "tag ${tag} does not match workspace version ${version}"
  printf 'Release tag %s is annotated, signed by %s, and matches workspace version %s\n' "$tag" "$fingerprint" "$version"
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
  signed_self_test "$tmp"
  printf 'release tag self-test passed\n'
}

# Signed-tag checks against a throwaway key and repository. GNUPGHOME and the
# key paths stay inside the self-test's own temp directory.
signed_self_test() {
  local tmp="$1" work fpr first
  work="${tmp}/signed"
  export GNUPGHOME="${tmp}/gnupg"
  mkdir -m 700 "$GNUPGHOME"
  gpg --batch --pinentry-mode loopback --passphrase '' \
    --quick-generate-key "Release tag self-test <release-tag-self-test@example.invalid>" ed25519 sign never \
    >/dev/null 2>&1 || fail "could not generate a self-test signing key"
  fpr="$(gpg --batch --with-colons --list-secret-keys 2>/dev/null | awk -F: '/^fpr:/ { print $10; exit }')"
  gpg --batch --armor --export "$fpr" >"${tmp}/key.asc"
  printf '# self-test\n%s\n' "$fpr" >"${tmp}/fingerprints"
  export RELEASE_TAG_KEY="${tmp}/key.asc" RELEASE_TAG_FINGERPRINTS="${tmp}/fingerprints" RELEASE_ROOT="$work"

  git init -q "$work"
  git -C "$work" config user.name "Release tag self-test"
  git -C "$work" config user.email "release-tag-self-test@example.invalid"
  git -C "$work" config commit.gpgsign false
  git -C "$work" config user.signingkey "$fpr"
  git -C "$work" config tag.gpgSign false
  git -C "$work" config gpg.format openpgp
  git -C "$work" config gpg.openpgp.program "$(command -v gpg)"
  printf '[package]\nname = "fixture"\nversion = "1.2.3"\n\n[dependencies]\nversion = "9.9.9"\n' >"${work}/Cargo.toml"
  git -C "$work" add Cargo.toml
  git -C "$work" commit -q -m first
  first="$(git -C "$work" rev-parse HEAD)"

  git -C "$work" tag v1.2.3 "$first"
  (cd "$work" && expect_signed_failure "is lightweight" v1.2.3 "$first")
  git -C "$work" tag -d v1.2.3 >/dev/null
  git -C "$work" tag -a v1.2.3 -m unsigned "$first"
  (cd "$work" && expect_signed_failure "is unsigned" v1.2.3 "$first")
  git -C "$work" tag -d v1.2.3 >/dev/null
  git -C "$work" tag -s v1.2.3 -m signed "$first"
  (cd "$work" && bash "$SCRIPT_PATH" verify-signed v1.2.3 "$first" >/dev/null) \
    || fail "signed tag at the workspace version was refused"
  (cd "$work" && expect_signed_failure "expected 0000000000000000000000000000000000000000" v1.2.3 0000000000000000000000000000000000000000)
  git -C "$work" tag -s v1.2.4 -m "wrong version" "$first"
  (cd "$work" && expect_signed_failure "does not match workspace version 1.2.3" v1.2.4 "$first")
  printf 'AEDA618886BF0331105B9CFCE4DC1F4A579505FB\n' >"${tmp}/fingerprints"
  (cd "$work" && expect_signed_failure "not listed" v1.2.3 "$first")
  gpgconf --kill gpg-agent >/dev/null 2>&1 || true
}

expect_signed_failure() {
  local message="$1" output
  shift
  if output="$(bash "$SCRIPT_PATH" verify-signed "$@" 2>&1)"; then
    fail "expected signed-tag failure containing: ${message}"
  fi
  [[ "$output" == *"$message"* ]] || fail "signed-tag check failed without expected message: ${message} (got: ${output})"
}

case "${1:-}" in
  verify)
    shift
    [[ $# -ge 2 && $# -le 3 ]] || fail "usage: $0 verify <tag> <commit-sha> [remote]"
    verify_release_tag "$1" "$2" "${3:-origin}"
    ;;
  verify-signed)
    shift
    [[ $# -eq 2 ]] || fail "usage: $0 verify-signed <tag> <commit-sha>"
    verify_signed_tag "$1" "$2"
    ;;
  self-test)
    [[ $# -eq 1 ]] || fail "usage: $0 self-test"
    self_test
    ;;
  *)
    fail "usage: $0 {verify <tag> <commit-sha> [remote]|verify-signed <tag> <commit-sha>|self-test}"
    ;;
esac
