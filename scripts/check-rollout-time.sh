#!/usr/bin/env bash
# Live rollout-time gate against perf/rollout-baseline.json (#596).
# Fails on a >20% regression when TENKAI_ROLLOUT_GATE=regression.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export TENKAI_ROLLOUT_GATE="${TENKAI_ROLLOUT_GATE:-regression}"

cargo test --locked rollout_time -- --nocapture --test-threads=1

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  cargo test --locked docker_live_against_runner_baseline -- --ignored --nocapture --test-threads=1
else
  echo "docker daemon unavailable; skipping live Docker samples" >&2
fi

if [[ -n "${TENKAI_CLUSTER_CONFIG:-}" ]]; then
  cargo test --locked -p tenkai-executor --test rollout_time_kind -- --ignored --nocapture --test-threads=1
else
  echo "TENKAI_CLUSTER_CONFIG unset; skipping kind samples" >&2
fi
