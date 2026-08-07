#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

count=0
while IFS= read -r script; do
  [[ -n "$script" ]] || continue
  bash -n "$script"
  count=$((count + 1))
done < <(find scripts -type f -name '*.sh' -print | LC_ALL=C sort)

printf 'shell syntax ok: %d scripts\n' "$count"
