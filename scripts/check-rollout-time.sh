#!/usr/bin/env bash
# Live rollout-time gate against perf/rollout-baseline.json (#596), plus the
# ci-hub-postgres fleet profile against perf/hub-fleet-baseline.json (#1084).
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

if [[ -n "${TENKAI_POSTGRES_URL:-}" ]]; then
  # Alone in its process: the fleet budget reads process-wide CPU and memory.
  cargo test --locked -p tenkai-postgres --features postgres --lib -- \
    --ignored --exact tests::live_hub_fleet::live_hub_fleet_measure --nocapture
else
  echo "TENKAI_POSTGRES_URL unset; skipping ci-hub-postgres fleet samples" >&2
fi
