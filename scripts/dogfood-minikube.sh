#!/usr/bin/env bash
# Local dogfood: embedded tenkaictl + minikube. No tenkai-server, no cloud.
#
# Modes (TENKAI_DOGFOOD_MODE):
#   local              — unsigned publish/apply to built-in `local` only (default)
#   signed-multi-env   — signed publish + apply to `local` and `stage` (proves
#                        fail-closed multi-env trust with tenkaictl dev …)
#
# Env:
#   TENKAI_DATABASE       SQLite path (default: .tenkai-dogfood-minikube/tenkai.db)
#   TENKAI_DEV_KEYS       Dev keys dir (default: .tenkai-dev-keys)
#   TENKAI_KUBECTL_BIN    kubectl binary
#   TENKAI_SOFTWARE_EXECUTOR  forced to kubernetes
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MODE="${TENKAI_DOGFOOD_MODE:-local}"
export TENKAI_SOFTWARE_EXECUTOR=kubernetes
export TENKAI_KUBECTL_BIN="${TENKAI_KUBECTL_BIN:-$(command -v kubectl || true)}"

die() {
  echo "$*" >&2
  exit 1
}

if ! command -v minikube >/dev/null 2>&1; then
  die "minikube not found; install with: brew install minikube"
fi
if [[ -z "${TENKAI_KUBECTL_BIN}" ]] || [[ ! -x "${TENKAI_KUBECTL_BIN}" ]]; then
  if command -v kubectl >/dev/null 2>&1; then
    TENKAI_KUBECTL_BIN="$(command -v kubectl)"
    export TENKAI_KUBECTL_BIN
  else
    die "kubectl not found; install kubectl or set TENKAI_KUBECTL_BIN"
  fi
fi
if ! minikube status >/dev/null 2>&1; then
  echo "starting minikube (docker driver)…"
  minikube start --driver=docker
fi
"${TENKAI_KUBECTL_BIN}" get nodes >/dev/null \
  || die "kubectl cannot reach a cluster; is minikube running?"

if [[ ! -x "$ROOT/target/debug/tenkaictl" ]]; then
  cargo build --bin tenkaictl
fi
BIN="$ROOT/target/debug/tenkaictl"
MANIFEST="$ROOT/examples/hello-minikube/tenkai.toml"
PRODUCT_VERSION="hello-minikube@0.1.0"

DB="${TENKAI_DATABASE:-$ROOT/.tenkai-dogfood-minikube/tenkai.db}"
mkdir -p "$(dirname "$DB")"
export TENKAI_DATABASE="$DB"

parse_plan_id() {
  local out="$1"
  local id
  id="$(printf '%s\n' "$out" | sed -n 's/^plan id: //p' | tail -1)"
  [[ -n "$id" ]] || die "could not parse plan id from plan output:\n$out"
  printf '%s\n' "$id"
}

run_local_unsigned() {
  local env_name="${TENKAI_DOGFOOD_ENV:-local}"
  echo "==> mode=local (unsigned, env=$env_name)"
  echo "==> init ($DB)"
  "$BIN" --database "$DB" init 2>/dev/null || true
  "$BIN" --database "$DB" env add "$env_name" 2>/dev/null || true

  echo "==> publish / promote / subscribe (unsigned development)"
  "$BIN" --database "$DB" publish "$MANIFEST" --allow-unsigned-development
  "$BIN" --database "$DB" promote "$PRODUCT_VERSION" stable
  "$BIN" --database "$DB" env subscribe "$env_name" hello-minikube=stable

  echo "==> plan"
  local plan_out plan_id
  plan_out="$("$BIN" --database "$DB" plan --env "$env_name")"
  echo "$plan_out"
  plan_id="$(parse_plan_id "$plan_out")"
  echo "using plan: $plan_id"

  echo "==> apply (local unapproved development)"
  "$BIN" --database "$DB" apply "$plan_id" \
    --allow-unapproved-development \
    --development-reason "local minikube dogfood"

  echo "==> status"
  "$BIN" --database "$DB" status --env "$env_name" 2>/dev/null \
    || "$BIN" --database "$DB" status
  "${TENKAI_KUBECTL_BIN}" -n "$env_name" get deploy,svc,pods

  echo "dogfood ok: $PRODUCT_VERSION in namespace $env_name (db=$DB)"
  echo "Next: TENKAI_DOGFOOD_MODE=signed-multi-env ./scripts/dogfood-minikube.sh"
  echo "  (fresh DB recommended: rm -rf .tenkai-dogfood-minikube)"
}

run_signed_multi_env() {
  local keys="${TENKAI_DEV_KEYS:-$ROOT/.tenkai-dev-keys}"
  local art="$ROOT/.tenkai-dogfood-minikube/artifacts"
  mkdir -p "$art"
  local rel_sig="$art/rel.sig.json"
  local rel_trust="$art/rel-trust.toml"
  local appr_sig="$art/approval-stage.json"
  local appr_trust="$art/approval-stage-trust.toml"

  echo "==> mode=signed-multi-env (signed publish; local + stage)"
  echo "    keys=$keys  artifacts=$art"
  echo "    WARNING: development-only keys (not production KMS)"

  echo "==> init ($DB)"
  "$BIN" --database "$DB" init 2>/dev/null || true
  "$BIN" --database "$DB" env add stage 2>/dev/null || true

  echo "==> dev init-keys / sign-release"
  "$BIN" dev init-keys --dir "$keys"
  "$BIN" dev sign-release "$MANIFEST" \
    --keys "$keys" \
    --signature "$rel_sig" \
    --trust-roots "$rel_trust"

  echo "==> signed publish / promote / subscribe"
  "$BIN" --database "$DB" publish "$MANIFEST" \
    --signature "$rel_sig" \
    --trust-roots "$rel_trust"
  "$BIN" --database "$DB" promote "$PRODUCT_VERSION" stable
  "$BIN" --database "$DB" env subscribe local hello-minikube=stable
  "$BIN" --database "$DB" env subscribe stage hello-minikube=stable

  echo "==> plan + apply local (unapproved development allowed only on local)"
  local plan_out plan_id
  plan_out="$("$BIN" --database "$DB" plan --env local)"
  echo "$plan_out"
  plan_id="$(parse_plan_id "$plan_out")"
  "$BIN" --database "$DB" apply "$plan_id" \
    --allow-unapproved-development \
    --development-reason "local minikube dogfood (signed release)"

  echo "==> plan + sign-approval + apply stage (no unapproved bypass)"
  plan_out="$("$BIN" --database "$DB" plan --env stage)"
  echo "$plan_out"
  plan_id="$(parse_plan_id "$plan_out")"
  "$BIN" --database "$DB" dev sign-approval "$plan_id" \
    --keys "$keys" \
    --approval "$appr_sig" \
    --trust-roots "$appr_trust"
  "$BIN" --database "$DB" apply "$plan_id" \
    --approval "$appr_sig" \
    --approval-trust-roots "$appr_trust"

  echo "==> fleet / wave / kubectl"
  "$BIN" --database "$DB" fleet status 2>/dev/null || true
  "$BIN" --database "$DB" wave run local,stage 2>/dev/null || true
  "$BIN" --database "$DB" status --env local 2>/dev/null || true
  "$BIN" --database "$DB" status --env stage 2>/dev/null || true
  "${TENKAI_KUBECTL_BIN}" -n local get deploy,pods 2>/dev/null || true
  "${TENKAI_KUBECTL_BIN}" -n stage get deploy,pods 2>/dev/null || true

  echo "dogfood ok (signed multi-env): $PRODUCT_VERSION on local + stage (db=$DB)"
  echo "Optional: force a bad image upgrade to see phase=health|restore diagnostics (#150)."
  echo "Tear down: kubectl delete ns local stage --ignore-not-found; rm -rf .tenkai-dogfood-minikube .tenkai-dev-keys"
}

case "$MODE" in
  local) run_local_unsigned ;;
  signed-multi-env | signed) run_signed_multi_env ;;
  *)
    die "unknown TENKAI_DOGFOOD_MODE='$MODE' (use: local | signed-multi-env)"
    ;;
esac
