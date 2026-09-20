#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  printf 'secret check failed: %s\n' "$1" >&2
  exit 1
}

path_ok=0
while IFS= read -r path; do
  [[ -n "$path" ]] || continue
  case "$path" in
    *.db | *.sqlite | *.sqlite3 | *.pem | *.p12 | *.pfx)
      printf 'tracked path looks like secret or local state: %s\n' "$path" >&2
      path_ok=1
      ;;
    */id_ed25519 | id_ed25519 | .tenkai-state/* | */.tenkai-state/* | .tenkai-dev-keys/* | */.tenkai-dev-keys/*)
      printf 'tracked path looks like secret or local state: %s\n' "$path" >&2
      path_ok=1
      ;;
  esac
done < <(git ls-files)

if [[ "$path_ok" -ne 0 ]]; then
  exit 1
fi

token_value_allowed() {
  local value="$1"
  case "$value" in
    replace-from-secret-store | inject-from-secret-store | load-from-secret-store | \
    '<load-from-secret-store>' | tenkai-local-management | lab-management-token | …)
      return 0
      ;;
  esac
  if printf '%s' "$value" | grep -Eq 'secret-store'; then
    return 0
  fi
  return 1
}

assignment_value() {
  local line="$1"
  local value
  value="$(printf '%s' "$line" | sed -nE 's/.*TENKAI_(MANAGEMENT|RUNTIME)_TOKEN=[[:space:]]*//p')"
  value="${value%"${value##*[![:space:]]}"}"
  value="${value%,}"
  value="${value%;}"
  if [[ "$value" == \"*\" || "$value" == \'*\' ]]; then
    value="${value:1:${#value}-2}"
  elif [[ "$value" == '"' || "$value" == "'" ]]; then
    value=""
  fi
  printf '%s' "$value"
}

scan_line() {
  local file="$1"
  local line="$2"
  local assignment value
  case "$file" in
    scripts/validate-secrets.sh) return 0 ;;
  esac
  printf '%s' "$line" | grep -Eq 'TENKAI_(MANAGEMENT|RUNTIME)_TOKEN=' || return 0
  while IFS= read -r assignment; do
    [[ -n "$assignment" ]] || continue
    value="$(assignment_value "$assignment")"
    if [[ -z "$value" ]]; then
      continue
    fi
    if [[ "$value" == \$* ]]; then
      default="$(printf '%s' "$value" | sed -nE 's/^\$\{[A-Za-z_][A-Za-z0-9_]*:?-([^}]*)\}$/\1/p')"
      if [[ -z "$default" || "$default" == \$* ]]; then
        continue
      fi
      value="$default"
    fi
    if token_value_allowed "$value"; then
      continue
    fi
    fail "literal Tenkai token assignment in ${file}"
  done < <(printf '%s\n' "$line" | grep -oE 'TENKAI_(MANAGEMENT|RUNTIME)_TOKEN=[^[:space:]]*')
}

scan_diff() {
  local diff="$1"
  [[ -n "$diff" ]] || return 0

  local file="" pem=0
  while IFS= read -r line; do
    case "$line" in
      +++\ *)
        file="${line#+++ }"
        file="${file#b/}"
        pem=0
        continue
        ;;
    esac
    if [[ "$line" == +-----BEGIN*PRIVATE\ KEY* ]]; then
      pem=1
      continue
    fi
    if [[ "$pem" -eq 1 ]]; then
      if [[ "$line" == +* ]] && printf '%s' "${line#+}" | grep -Eq '^[A-Za-z0-9+/=]{40,}$'; then
        fail "added private-key material in ${file}"
      fi
      if [[ "$line" != +* ]]; then
        pem=0
      fi
    fi
    if [[ "$line" == +* ]]; then
      scan_line "$file" "${line#+}"
    fi
  done <<<"$diff"
}

base=""
for candidate in origin/main refs/remotes/origin/main main "${GITHUB_BASE_REF:-}"; do
  if [[ -n "$candidate" ]] && git rev-parse --verify "$candidate" >/dev/null 2>&1; then
    base="$candidate"
    break
  fi
done
if [[ -z "$base" ]]; then
  fail "no comparison base (need origin/main or GITHUB_BASE_REF) for secret diff scan"
fi
if [[ "$(git rev-parse "$base")" == "$(git rev-parse HEAD)" ]]; then
  if [[ -n "${GITHUB_EVENT_BEFORE:-}" && "${GITHUB_EVENT_BEFORE}" != 0000000000000000000000000000000000000000 ]]; then
    if git rev-parse --verify "${GITHUB_EVENT_BEFORE}^{commit}" >/dev/null 2>&1; then
      base="$GITHUB_EVENT_BEFORE"
    elif git rev-parse --verify HEAD^ >/dev/null 2>&1; then
      base="HEAD^"
    else
      fail "push comparison revision ${GITHUB_EVENT_BEFORE} is not in this checkout"
    fi
  elif git rev-parse --verify HEAD^ >/dev/null 2>&1; then
    base="HEAD^"
  fi
fi
committed="$(git diff -U0 "${base}...HEAD")" || fail "cannot diff ${base}...HEAD"
worktree="$(git diff -U0)" || fail "cannot diff the working tree"
cached="$(git diff --cached -U0)" || fail "cannot diff the index"
scan_diff "${committed}"$'\n'"${worktree}"$'\n'"${cached}"

printf 'secret path and diff checks ok\n'
