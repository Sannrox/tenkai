#!/usr/bin/env bash
# Fail when a copy-paste tenkaictl command in docs/tasks/ does not parse.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

# A filter that selects no tests exits 0, so a renamed test would silently
# disable this check: require the test to have run.
output="$(cargo test --locked -p tenkaictl --bin tenkaictl task_page_commands_parse 2>&1)" || {
  printf '%s\n' "$output" >&2
  exit 1
}
printf '%s\n' "$output"
if ! printf '%s\n' "$output" | grep -qE '^test result: ok\. [1-9][0-9]* passed'; then
  printf 'task page commands: no test ran for the filter task_page_commands_parse\n' >&2
  exit 1
fi
