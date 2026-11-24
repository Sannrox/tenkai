#!/usr/bin/env bash
# Live rollout-time gate against perf/rollout-baseline.json (#596), plus the
# ci-hub-postgres fleet profile against perf/hub-fleet-baseline.json (#1084).
# Fails on a >20% regression when TENKAI_ROLLOUT_GATE=regression. Every
# stage runs and reports even when an earlier one fails; the script fails at
# the end, naming the failed stages.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export TENKAI_ROLLOUT_GATE="${TENKAI_ROLLOUT_GATE:-regression}"

failed=()

# Run one stage; record its name instead of stopping when it fails.
stage() {
  local name="$1"
  shift
  if ! "$@"; then
    failed+=("$name")
  fi
}

stage "rollout_time" cargo test --locked rollout_time -- --nocapture --test-threads=1

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  stage "docker live" cargo test --locked docker_live_against_runner_baseline -- --ignored --nocapture --test-threads=1
else
  echo "docker daemon unavailable; skipping live Docker samples" >&2
fi

if [[ -n "${TENKAI_CLUSTER_CONFIG:-}" ]]; then
  stage "kind" cargo test --locked -p tenkai-executor --test rollout_time_kind -- --ignored --nocapture --test-threads=1
else
  echo "TENKAI_CLUSTER_CONFIG unset; skipping kind samples" >&2
fi

# Only the hub stage sees the URL: embedded hosts refuse TENKAI_POSTGRES_URL
# (ADR 0029), so it must not be set for the stages above.
if [[ -n "${TENKAI_HUB_FLEET_POSTGRES_URL:-}" ]]; then
  # Alone in its process: the fleet budget reads process-wide CPU and memory.
  stage "ci-hub-postgres fleet" env TENKAI_POSTGRES_URL="$TENKAI_HUB_FLEET_POSTGRES_URL" \
    cargo test --locked -p tenkai-postgres --features postgres --lib -- \
    --ignored --exact tests::live_hub_fleet::live_hub_fleet_measure --nocapture
else
  echo "TENKAI_HUB_FLEET_POSTGRES_URL unset; skipping ci-hub-postgres fleet samples" >&2
fi

if ((${#failed[@]} > 0)); then
  printf 'rollout-time gate failed stages: %s\n' "$(IFS=','; echo "${failed[*]}")" >&2
  exit 1
fi
