#!/usr/bin/env bash
# Repeatable OpenShift / OKD / MicroShift drill for the Kubernetes executors (#993).
# Does not start a cluster. Refuses implicit KUBECONFIG.
#
# Required:
#   TENKAI_CLUSTER_CONFIG  environment-scoped kubeconfig file (same contract as apply)
#
# Optional:
#   TENKAI_KUBECTL_BIN     kubectl (default: kubectl on PATH)
#   CARGO_TARGET_DIR       build artifacts (default: ./target in this checkout)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

die() {
  echo "$*" >&2
  exit 1
}

CONFIG="${TENKAI_CLUSTER_CONFIG:-}"
[[ -n "$CONFIG" ]] || die "TENKAI_CLUSTER_CONFIG is required; refusing implicit KUBECONFIG"
[[ -f "$CONFIG" ]] || die "TENKAI_CLUSTER_CONFIG is not a file"

KUBECTL="${TENKAI_KUBECTL_BIN:-}"
if [[ -z "$KUBECTL" ]]; then
  command -v kubectl >/dev/null 2>&1 || die "kubectl not found; set TENKAI_KUBECTL_BIN"
  KUBECTL="$(command -v kubectl)"
fi
[[ -x "$KUBECTL" ]] || die "TENKAI_KUBECTL_BIN is not executable"

kc() {
  "$KUBECTL" --kubeconfig "$CONFIG" "$@"
}

kc get --raw=/readyz >/dev/null \
  || die "cluster at TENKAI_CLUSTER_CONFIG is not ready"

echo "server: $(kc version -o json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["serverVersion"]["gitVersion"])' 2>/dev/null || kc version)"

api_group() {
  local group="$1"
  if kc api-resources --api-group "$group" -o name 2>/dev/null | grep -q .; then
    echo "$group: present"
  else
    echo "$group: absent"
  fi
}

api_group route.openshift.io
api_group security.openshift.io

export TENKAI_CLUSTER_CONFIG="$CONFIG"
export TENKAI_KUBECTL_BIN="$KUBECTL"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

echo "in-process kind tests (ignored live suite)"
cargo test --locked -p tenkai-executor --test in_process_kubernetes_kind -- --ignored --nocapture

echo "kubectl smoke"
cargo test --locked -p tenkai-executor kubernetes_operator_kind_path_smoke -- --ignored --nocapture

if command -v helm >/dev/null 2>&1; then
  echo "helm smoke"
  chart="$(mktemp -d "${TMPDIR:-/tmp}/tenkai-helm-drill.XXXXXX")"
  ns="tk993$(python3 -c 'import uuid; print(uuid.uuid4().hex[:8])')"
  mkdir -p "$chart/templates"
  cat >"$chart/Chart.yaml" <<'EOF'
apiVersion: v2
name: tenkai-drill
version: 0.1.0
EOF
  cat >"$chart/templates/configmap.yaml" <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: tenkai-drill
data:
  ok: "1"
EOF
  helm --kubeconfig "$CONFIG" upgrade --install "tenkai-drill-$ns" "$chart" \
    --namespace "$ns" --create-namespace --wait --timeout 1m
  helm --kubeconfig "$CONFIG" uninstall "tenkai-drill-$ns" --namespace "$ns" \
    --wait --ignore-not-found
  kc delete namespace "$ns" --wait=false >/dev/null
  rm -rf "$chart"
else
  echo "helm: skipped (helm not on PATH)"
fi
