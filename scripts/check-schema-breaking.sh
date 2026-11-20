#!/usr/bin/env bash
# Compare listed JSON Schema contracts to a git tag. Exit 1 when a field or
# route was removed; exit 0 when the change is additive or the tag has no copy.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() {
  printf 'usage: check-schema-breaking.sh --tag <vX.Y.Z>\n' >&2
  printf '       check-schema-breaking.sh --self-test\n' >&2
  exit 2
}

if [[ "${1:-}" == "--self-test" ]]; then
  python3 "$ROOT/scripts/schema-breaking.py" --self-test
  exit 0
fi

[[ "${1:-}" == "--tag" && -n "${2:-}" ]] || usage
tag="$2"

mapfile -t listed < <(python3 "$ROOT/scripts/schema-breaking.py" --listed)
[[ ${#listed[@]} -gt 0 ]] || {
  printf 'schema-breaking: listed schema list is empty\n' >&2
  exit 2
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

broke=0
compared=0
for path in "${listed[@]}"; do
  if [[ ! -f "$path" ]]; then
    printf 'schema-breaking: working tree is missing %s\n' "$path" >&2
    exit 2
  fi
  if ! git cat-file -e "${tag}:${path}" 2>/dev/null; then
    printf 'schema-breaking: %s is new since %s; nothing to compare.\n' "$path" "$tag"
    continue
  fi
  git show "${tag}:${path}" >"$tmp/old.json"
  rc=0
  out="$(python3 "$ROOT/scripts/schema-breaking.py" "$tmp/old.json" "$path")" || rc=$?
  compared=$((compared + 1))
  if [[ $rc -eq 0 ]]; then
    printf 'schema-breaking: %s is compatible with %s\n' "$path" "$tag"
    continue
  fi
  if [[ $rc -ne 1 ]]; then
    printf 'schema-breaking: comparer failed for %s (exit %s)\n' "$path" "$rc" >&2
    printf '%s\n' "$out" >&2
    exit "$rc"
  fi
  printf 'schema-breaking: %s breaks %s\n' "$path" "$tag"
  printf '%s\n' "$out"
  broke=1
done

if [[ $compared -eq 0 ]]; then
  printf 'schema-breaking: %s has none of the listed schemas; nothing to compare.\n' "$tag"
  exit 0
fi
exit "$broke"
