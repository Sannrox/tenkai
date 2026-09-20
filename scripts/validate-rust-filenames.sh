#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail=0
while IFS= read -r path; do
  [[ -n "$path" ]] || continue
  base="$(basename "$path")"
  case "$base" in
    lib.rs | main.rs | mod.rs) continue ;;
  esac
  if printf '%s' "$base" | grep -q '[[:upper:]]'; then
    printf 'rust filename is not snake_case: %s\n' "$path" >&2
    fail=1
  fi
  if printf '%s' "$base" | grep -q '-' && [[ "$path" != src/bin/* ]]; then
    printf 'rust filename uses a hyphen outside src/bin/: %s\n' "$path" >&2
    fail=1
  fi
done < <(git ls-files -c -o --exclude-standard -- '*.rs')

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
printf 'rust filenames ok\n'
