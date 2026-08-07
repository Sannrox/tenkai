#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

export LC_ALL=C

count=0
for test_file in tests/*.rs; do
  [[ -f "$test_file" ]] || continue
  test_target="${test_file##*/}"
  test_target="${test_target%.rs}"
  if [[ -n "${WHAT:-}" ]]; then
    cargo test --locked --test "$test_target" "$WHAT"
  else
    cargo test --locked --test "$test_target"
  fi
  count=$((count + 1))
done

if [[ "$count" -eq 0 ]]; then
  echo "no integration test targets found under tests/" >&2
  exit 1
fi
