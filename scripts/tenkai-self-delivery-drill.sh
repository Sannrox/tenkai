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

cargo test --locked -p tenkai --lib \
  apply::release_executor_tests::the_coordinating_server_refuses_tenkai_server_and_releases_the_fence \
  -- --exact --nocapture
cargo test --locked -p tenkai-runtime --test self_delivery -- --nocapture
printf 'tenkai-server self-delivery drill: coordinating refuse and plan-path restore recorded\n'
