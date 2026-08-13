#!/usr/bin/env bash
# Multi-environment local demo for tenkai (issue #73).
# Requires: cargo, a built or cargo-runnable tree. Uses development-only flags
# with recorded reasons. Does not commit secrets.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

STATE="${TENKAI_DEMO_STATE:-$ROOT/.tenkai-demo-multi-env}"
BIN="${TENKAI_BIN:-}"
if [[ -z "$BIN" ]]; then
  cargo build --bin tenkaictl --quiet
  BIN="$ROOT/target/debug/tenkaictl"
fi

if [[ ! -x "$BIN" ]]; then
  echo "tenkaictl binary not found at $BIN" >&2
  exit 1
fi

rm -rf "$STATE"
mkdir -p "$STATE"
export TENKAI_DATABASE="$STATE/tenkai.db"
export TENKAI_MANAGEMENT_TOKEN="${TENKAI_MANAGEMENT_TOKEN:-tenkai-local-management}"

run() {
  echo "+ $BIN $*"
  "$BIN" --database "$TENKAI_DATABASE" "$@"
}

echo "== init =="
run init

echo "== second environment =="
run env add edge --description "demo edge environment"

echo "== list environments =="
run env list

echo "== publish + promote (unsigned development) =="
run publish examples/hello-local/tenkai.toml \
  --allow-unsigned-development
run promote hello-local@0.1.0 stable

echo "== subscribe both environments =="
run env subscribe local hello-local=stable
run env subscribe edge hello-local=stable

echo "== plan + apply local (unsigned development is local-only) =="
# Capture plan id from plan output
PLAN_LOCAL="$(run plan --env local | sed -n 's/^plan id: //p' | head -1)"
if [[ -z "$PLAN_LOCAL" ]]; then
  echo "failed to create plan for local" >&2
  exit 1
fi
run apply "$PLAN_LOCAL" \
  --allow-unapproved-development \
  --development-reason "multi-env demo local apply"

echo "== edge remains subscribed but not deployable with unsigned-development =="
echo "(Production multi-env deploys require signed releases; this demo shows fleet list/status.)"
run plan --env edge || true

echo "== status per environment =="
run status --env local
run status --env edge

echo "== list + inspect (no secrets) =="
run env list
run env inspect local | head -50
run env inspect edge | head -50

echo "== demo complete =="
echo "State directory: $STATE"
echo "Remove with: rm -rf \"$STATE\""
