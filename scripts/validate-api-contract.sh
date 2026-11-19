#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Fail when api/tenkai-http-v1.schema.json,
# api/tenkai-terminal-outcome-v2.schema.json, or
# api/tenkai-feedback-observation-v1.schema.json no longer matches the code.
# A filter that selects no tests exits 0, so a renamed test would silently
# disable the gate: require the three checked_in_*_contract_matches_the_code tests to have run.
EXPECTED_TESTS=3
output="$(cargo test --locked -p tenkai-http --lib checked_in_ --quiet 2>&1)" || {
  printf '%s\n' "$output" >&2
  exit 1
}
printf '%s\n' "$output"
passed="$(printf '%s\n' "$output" | sed -n 's/^test result: ok\. \([0-9][0-9]*\) passed.*/\1/p' | head -n1)"
if [[ "${passed:-0}" -lt "$EXPECTED_TESTS" ]]; then
  printf 'http api contract: expected at least %s contract tests to run, ran %s\n' \
    "$EXPECTED_TESTS" "${passed:-0}" >&2
  exit 1
fi
printf 'http api contract ok\n'
