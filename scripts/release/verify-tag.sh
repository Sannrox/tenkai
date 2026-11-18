#!/usr/bin/env bash
# Release tag checks for the v* workflow. scripts/tests/release/ tests them.
#
# Usage:
#   scripts/release/verify-tag.sh release-commit <tag> <workflow-ref>
#       The whole tagged-run check, run with main's copy of this script from
#       the tag's checkout: the run starts from main, the tag passes
#       verify-signed for HEAD, and HEAD is on main or the matching release-*
#       line (fetched from origin). Prints line=<main|release-*> for
#       $GITHUB_OUTPUT.
#   scripts/release/verify-tag.sh verify <tag> <commit-sha> [remote]
#       The live remote tag still resolves to the triggering commit.
#   scripts/release/verify-tag.sh verify-signed <tag> <commit-sha>
#       The local tag object is annotated, signed by a key listed in
#       security/release-tag-fingerprints, resolves to the commit, and equals
#       the workspace version. Lightweight and unsigned tags are refused.
#   scripts/release/verify-tag.sh maintenance-line <tag>
#       The matching release-* branch for the tag's version.
#   scripts/release/verify-tag.sh require-ancestry <tag> <commit-sha>
#       The commit is on origin/main, or on the matching origin/release-*
#       line when origin has a final tag of a newer minor (the newest line
#       releases from main). Prints that line name (main or release-*).
#
# Release tags are vX.Y.Z or the pre-release vX.Y.Z-rc.N (N >= 1). Numbers
# carry no leading zeros; any other suffix is refused.
set -euo pipefail

ROOT_PATH="${RELEASE_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)}"
FINGERPRINTS_FILE="${RELEASE_TAG_FINGERPRINTS:-${ROOT_PATH}/security/release-tag-fingerprints}"
KEY_FILE="${RELEASE_TAG_KEY:-${ROOT_PATH}/security/release-tag-key.asc}"

RELEASE_TAG_PATTERN='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.[1-9][0-9]*)?$'

fail() {
  printf 'verify-tag: %s\n' "$1" >&2
  exit 1
}

verify_release_tag() {
  local tag="$1" expected_commit="$2" remote="${3:-origin}"
  [[ "$tag" =~ $RELEASE_TAG_PATTERN ]] || fail "invalid release tag: ${tag}"
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

# release-<major>.<minor>, one line per minor, before and after 1.0. Hyphen,
# not the release/<version> bump branch.
maintenance_line() {
  local tag="$1" version major rest minor
  [[ "$tag" =~ $RELEASE_TAG_PATTERN ]] || fail "invalid release tag: ${tag}"
  version="${tag#v}"
  version="${version%%-*}"
  major="${version%%.*}"
  rest="${version#*.}"
  minor="${rest%%.*}"
  printf 'release-%s.%s\n' "$major" "$minor"
}

# origin/main wins when the commit is on it, so tags on main stay latest.
require_ancestry() {
  local tag="$1" sha="$2" line line_ref
  [[ "$tag" =~ $RELEASE_TAG_PATTERN ]] || fail "invalid release tag: ${tag}"
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || fail "expected commit must be a full lowercase SHA"
  git rev-parse --verify -q refs/remotes/origin/main >/dev/null || fail "missing origin/main"
  if git merge-base --is-ancestor "$sha" refs/remotes/origin/main; then
    printf 'main\n'
    return
  fi
  line="$(maintenance_line "$tag")"
  line_ref="refs/remotes/origin/${line}"
  if git rev-parse --verify -q "$line_ref" >/dev/null \
    && git merge-base --is-ancestor "$sha" "$line_ref"; then
    require_newer_final_release "$tag" "$line"
    printf '%s\n' "$line"
    return
  fi
  fail "tag ${tag} commit ${sha} is not on main or ${line}"
}

# A release-X.Y line only patches a line older than the newest final
# release (ADR 0040 §10.9): origin must carry a final vA.B.C with A.B above
# X.Y. A newer rc does not count. Fails closed when the tags cannot be listed.
require_newer_final_release() {
  local tag="$1" line="$2" tags line_major line_minor ref name major minor
  tags="$(git ls-remote --refs --tags origin 'v*')" || fail "could not list release tags on origin"
  line_major="${line#release-}"
  line_minor="${line_major#*.}"
  line_major="${line_major%%.*}"
  while read -r _ ref; do
    name="${ref#refs/tags/}"
    [[ "$name" =~ $RELEASE_TAG_PATTERN && -z "${BASH_REMATCH[4]}" ]] || continue
    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"
    if ((major > line_major || (major == line_major && minor > line_minor))); then
      return
    fi
  done <<<"$tags"
  fail "tag ${tag} is only on ${line}, and no final release of a newer minor exists; the newest line releases from main"
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
  [[ "$tag" =~ $RELEASE_TAG_PATTERN ]] || fail "invalid release tag: ${tag}"
  [[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]] || fail "expected commit must be a full lowercase SHA"

  object_type="$(git cat-file -t "refs/tags/${tag}" 2>/dev/null)" || fail "tag ${tag} was not found"
  [[ "$object_type" == tag ]] || fail "tag ${tag} is lightweight; release tags must be annotated and signed"
  actual="$(git rev-parse "refs/tags/${tag}^{commit}")"
  [[ "$actual" == "$expected_commit" ]] || fail "tag ${tag} resolves to ${actual}, expected ${expected_commit}"

  [[ -f "$KEY_FILE" ]] || fail "missing release tag key: ${KEY_FILE}"
  [[ -f "$FINGERPRINTS_FILE" ]] || fail "missing release tag fingerprints: ${FINGERPRINTS_FILE}"
  gpg --batch --quiet --import "$KEY_FILE" >/dev/null 2>&1 || fail "could not import ${KEY_FILE}"
  # git verify-tag succeeds only on GOODSIG; also refuse a good signature
  # from a revoked or expired key, which GnuPG still reports as VALIDSIG.
  verified=true
  raw="$(git verify-tag --raw "refs/tags/${tag}" 2>&1)" || verified=false
  if grep -Eq '^\[GNUPG:\] (REVKEYSIG|EXPKEYSIG|EXPSIG) ' <<<"$raw"; then
    fail "tag ${tag} is signed by a revoked or expired key"
  fi
  $verified || fail "tag ${tag} is unsigned or its signature is not valid"
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

release_commit() {
  local tag="$1" workflow_ref="$2" sha line
  [[ "$workflow_ref" == refs/heads/main ]] || fail "tagged release runs must start from refs/heads/main, not ${workflow_ref}"
  [[ "$tag" =~ $RELEASE_TAG_PATTERN ]] || fail "invalid release tag: ${tag}"
  # The checkout's tag may be a peeled copy; fetch the annotated tag object.
  git fetch --quiet --force origin "refs/tags/${tag}:refs/tags/${tag}" "+refs/heads/main:refs/remotes/origin/main" \
    || fail "could not fetch ${tag} and main from origin"
  sha="$(git rev-parse "refs/tags/${tag}^{commit}")"
  verify_signed_tag "$tag" "$sha" >&2
  line="$(maintenance_line "$tag")"
  if git ls-remote --exit-code --heads origin "$line" >/dev/null 2>&1; then
    git fetch --quiet --force origin "+refs/heads/${line}:refs/remotes/origin/${line}" \
      || fail "could not fetch ${line} from origin"
  fi
  line="$(require_ancestry "$tag" "$sha")"
  [[ "$(git rev-parse HEAD)" == "$sha" ]] || fail "HEAD is not the commit ${tag} resolves to (${sha})"
  printf 'line=%s\n' "$line"
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
  maintenance-line)
    shift
    [[ $# -eq 1 ]] || fail "usage: $0 maintenance-line <tag>"
    maintenance_line "$1"
    ;;
  require-ancestry)
    shift
    [[ $# -eq 2 ]] || fail "usage: $0 require-ancestry <tag> <commit-sha>"
    require_ancestry "$1" "$2"
    ;;
  release-commit)
    shift
    [[ $# -eq 2 ]] || fail "usage: $0 release-commit <tag> <workflow-ref>"
    release_commit "$1" "$2"
    ;;
  *)
    fail "usage: $0 {verify <tag> <commit-sha> [remote]|verify-signed <tag> <commit-sha>|maintenance-line <tag>|require-ancestry <tag> <commit-sha>|release-commit <tag> <workflow-ref>}"
    ;;
esac
