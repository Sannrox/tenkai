#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TENKAI_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SEKAI_DIR="${SEKAI_CHISEI_DIR:-$(cd "$TENKAI_DIR/../sekai-chisei" && pwd)}"
OUTPUT_DIR="${REPLAY_OUTPUT_DIR:-$TENKAI_DIR/artifacts/replay}"
GRPC_PORT="${REPLAY_GRPC_PORT:-50061}"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tenkai-replay.XXXXXX")"
TRANSCRIPT="$RUN_DIR/terminal.log"
SERVER_LOG="$RUN_DIR/sekai-chisei.log"
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

record() {
  local label="$1"
  shift
  local started output status
  started="$(date +%s)"
  printf '[%s] $ %s\n' "$started" "$label" | tee -a "$TRANSCRIPT"
  set +e
  output="$("$@" 2>&1)"
  status=$?
  set -e
  if [[ -n "$output" ]]; then
    printf '%s\n' "$output" | tee -a "$TRANSCRIPT"
  fi
  printf '[%s] exit %s\n' "$(date +%s)" "$status" | tee -a "$TRANSCRIPT"
  return "$status"
}

record_capture() {
  local variable="$1"
  local label="$2"
  shift 2
  local started output status
  started="$(date +%s)"
  printf '[%s] $ %s\n' "$started" "$label" | tee -a "$TRANSCRIPT"
  set +e
  output="$("$@" 2>&1)"
  status=$?
  set -e
  if [[ -n "$output" ]]; then
    printf '%s\n' "$output" | tee -a "$TRANSCRIPT"
  fi
  printf '[%s] exit %s\n' "$(date +%s)" "$status" | tee -a "$TRANSCRIPT"
  printf -v "$variable" '%s' "$output"
  return "$status"
}

mkdir -p "$OUTPUT_DIR"
: > "$TRANSCRIPT"

printf 'Building sekai-chisei and Tenkai...\n'
cargo build --manifest-path "$SEKAI_DIR/Cargo.toml" --bin sekai-chisei --bin sekaictl
cargo build --manifest-path "$TENKAI_DIR/Cargo.toml" --bin tenkaictl

SEKAI_BIN="$SEKAI_DIR/target/debug/sekai-chisei"
SEKAICTL="$SEKAI_DIR/target/debug/sekaictl"
TENKAICTL="$TENKAI_DIR/target/debug/tenkaictl"
export DB_PATH="$RUN_DIR/sekai.db"
export SEKAI_INSECURE=1
export SEKAI_SOCKET=
export OPS_PORT=
export GRPC_PORT
export TENKAI_SEKAI_URL="http://127.0.0.1:$GRPC_PORT"
export TENKAI_STATE_DIR="$RUN_DIR/tenkai-state"
export CHISEI_GRPC_URL="$TENKAI_SEKAI_URL"

"$SEKAI_BIN" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 60); do
  if record "tenkaictl init" "$TENKAICTL" init; then
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    printf 'sekai-chisei exited before becoming ready:\n' >&2
    tail -n 80 "$SERVER_LOG" >&2
    exit 1
  fi
  sleep 0.25
done
if ! grep -q 'registered schema types\|schema already registered' "$TRANSCRIPT"; then
  printf 'sekai-chisei did not become ready; see %s\n' "$SERVER_LOG" >&2
  exit 1
fi

HEALTHY="$TENKAI_DIR/examples/replay-incident/healthy/tenkai.toml"
UNHEALTHY="$TENKAI_DIR/examples/replay-incident/unhealthy/tenkai.toml"

record "tenkaictl publish healthy" "$TENKAICTL" publish "$HEALTHY"
record "tenkaictl promote replay-service@0.1.0 stable" \
  "$TENKAICTL" promote replay-service@0.1.0 stable
record "tenkaictl env subscribe local replay-service=stable" \
  "$TENKAICTL" env subscribe local replay-service=stable
record_capture BASELINE_PLAN_OUTPUT "tenkaictl plan --env local" \
  "$TENKAICTL" plan --env local
BASELINE_PLAN_ID="$(printf '%s\n' "$BASELINE_PLAN_OUTPUT" | sed -n 's/^plan id: //p' | tail -n 1)"
[[ -n "$BASELINE_PLAN_ID" ]] || { printf 'baseline plan id was not reported\n' >&2; exit 1; }
record "tenkaictl apply baseline" "$TENKAICTL" apply "$BASELINE_PLAN_ID"

record "tenkaictl publish unhealthy" "$TENKAICTL" publish "$UNHEALTHY"
record "tenkaictl promote replay-service@0.2.0 stable" \
  "$TENKAICTL" promote replay-service@0.2.0 stable
record_capture INCIDENT_PLAN_OUTPUT "tenkaictl plan --env local" \
  "$TENKAICTL" plan --env local
INCIDENT_PLAN_ID="$(printf '%s\n' "$INCIDENT_PLAN_OUTPUT" | sed -n 's/^plan id: //p' | tail -n 1)"
[[ -n "$INCIDENT_PLAN_ID" ]] || { printf 'incident plan id was not reported\n' >&2; exit 1; }

if record "tenkaictl apply incident (expected rollback)" \
  "$TENKAICTL" apply "$INCIDENT_PLAN_ID"; then
  printf 'expected unhealthy release to trigger rollback\n' >&2
  exit 1
fi
record "tenkaictl status --env local" "$TENKAICTL" status --env local

OUTPUT="$OUTPUT_DIR/rollback-incident.json"
"$SEKAICTL" replay export "$INCIDENT_PLAN_ID" \
  --terminal "$TRANSCRIPT" \
  --output "$OUTPUT"

printf 'Replay bundle: %s\n' "$OUTPUT"
printf 'Captured run directory: %s\n' "$RUN_DIR"
