#!/usr/bin/env bash
# Soak and recall drill for a deliberately bad tenkai-server catalog release (#1080).
#
# Offline: the coordinating server refuses to apply tenkai-server, a runtime
# restores the previous pin when a bad build fails health, and recall of that
# build refuses planning. Evidence is the passing tests. Live soak uses
# `tenkaictl channel policy` as in docs/deliver-tenkai.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# libtest exits 0 when a filter matches nothing, so a renamed or removed test
# would pass the drill vacuously. Require at least one passed test per step.
run_tests() {
  local output passed
  output="$(cargo test --locked "$@" 2>&1 | tee -a /dev/stderr)"
  passed="$(sed -n 's/^test result: ok\. \([0-9][0-9]*\) passed.*/\1/p' <<<"$output" |
    awk '{ total += $1 } END { print total + 0 }')"
  if [[ "$passed" -lt 1 ]]; then
    printf 'tenkai-server self-delivery drill: no test ran for: cargo test %s\n' "$*" >&2
    exit 1
  fi
}

run_tests -p tenkai --lib \
  apply::release_executor_tests::the_coordinating_server_refuses_tenkai_server_and_releases_the_fence \
  -- --exact --nocapture
run_tests -p tenkai-runtime --test self_delivery -- --nocapture
printf 'tenkai-server self-delivery drill: coordinating refuse and plan-path restore recorded\n'
