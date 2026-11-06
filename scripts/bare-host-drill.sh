#!/usr/bin/env bash
# Bare-host drill (#912, ADR 0041): on a fresh systemd host, install only
# Tenkai, then let it install a single-node cluster as a privileged host
# release and deliver a release into that cluster, with tenkai-server running
# as the unprivileged `tenkai` user throughout. Then upgrade, roll back, and
# uninstall the cluster through approved plans.
#
# Needs root (via sudo), systemd as PID 1, polkit, python3 3.11+, curl, and
# network access to GitHub. It installs system software and a cluster, so run
# it only on a throwaway host.
#
# Usage:
#   scripts/bare-host-drill.sh --release-tag vX.Y.Z[-rc.N]
#       install Tenkai from that GitHub Release
#   scripts/bare-host-drill.sh --dist DIR
#       install Tenkai from DIR: release assets with install.sh and SHA256SUMS,
#       as scripts/package-release-binaries.sh writes them
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo=Sannrox/tenkai
environment=edge
kubeconfig=/var/lib/tenkai/cluster/${environment}.kubeconfig
database=/var/lib/tenkai/tenkai.db
unit=tenkai-server

fail() {
  echo "bare-host drill: $*" >&2
  sudo journalctl -u "$unit" --no-pager -o cat 2>/dev/null | tail -n 60 >&2 || true
  sudo journalctl -t tenkai-host-apply --no-pager -o cat 2>/dev/null | tail -n 60 >&2 || true
  exit 1
}

usage() {
  sed -n '12,17p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

tag=""
dist=""
while [ $# -gt 0 ]; do
  case "$1" in
    --release-tag)
      [ $# -ge 2 ] || usage
      tag="$2"
      shift 2
      ;;
    --dist)
      [ $# -ge 2 ] || usage
      dist="$2"
      shift 2
      ;;
    *) usage ;;
  esac
done
{ [ -n "$tag" ] && [ -z "$dist" ]; } || { [ -z "$tag" ] && [ -n "$dist" ]; } || usage

work=$(mktemp -d)
chmod 0700 "$work"
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT

# Checks that file $1 matches its entry in SHA256SUMS file $2.
verify_sum() {
  local expected
  expected=$(awk -v name="$(basename "$1")" '$2 == name || $2 == "*" name {print $1}' "$2")
  [ -n "$expected" ] || fail "SHA256SUMS has no entry for $(basename "$1")"
  [ "$(sha256sum "$1" | awk '{print $1}')" = "$expected" ] || fail "checksum mismatch for $(basename "$1")"
}

json() {
  # json <python expression over r>
  python3 -c "import json,sys; r=json.load(sys.stdin); print($1)"
}

echo "== install Tenkai with the install script, verified against SHA256SUMS"
installer_args=(--role server --with-host-applier)
if [ -n "$tag" ]; then
  release_url="https://github.com/${repo}/releases/download/${tag}"
  curl -fsSL --proto =https --retry 4 -o "$work/SHA256SUMS" "${release_url}/SHA256SUMS"
  curl -fsSL --proto =https --retry 4 -o "$work/install.sh" "${release_url}/install.sh"
  verify_sum "$work/install.sh" "$work/SHA256SUMS"
  installer_args+=(--version "$tag")
else
  dist=$(cd "$dist" && pwd)
  verify_sum "$dist/install.sh" "$dist/SHA256SUMS"
  cp "$dist/install.sh" "$work/install.sh"
  version=$(sed -n 's/^RELEASE_VERSION="\(.*\)"$/\1/p' "$work/install.sh")
  [ -n "$version" ] || fail "$dist/install.sh has no release version"
  # The install script downloads <base-url>/v<version>/<asset>.
  mkdir -p "$work/releases"
  ln -s "$dist" "$work/releases/v${version}"
  installer_args+=(--version "$version" --base-url "file://$work/releases")
fi
sudo sh "$work/install.sh" "${installer_args[@]}"
for binary in tenkai-server tenkaictl tenkai-executor-guard; do
  [ -x "/usr/local/bin/$binary" ] || fail "the install script did not install $binary"
done
[ -x /usr/local/libexec/tenkai/tenkai-host-applier ] || fail "the install script did not install the host applier"
tenkaictl() { /usr/local/bin/tenkaictl "$@"; }

echo "== host setup: the tenkai user, the applier's root-owned trust, and keys the server cannot read"
id tenkai >/dev/null 2>&1 ||
  sudo useradd --system --home-dir /var/lib/tenkai --create-home --shell /usr/sbin/nologin tenkai
sudo install -o tenkai -g tenkai -m 0750 -d /var/lib/tenkai/host-spool
sudo install -o root -g root -m 0755 -d /etc/tenkai
printf 'version = 1\nspool_dir = "/var/lib/tenkai/host-spool"\n' |
  sudo tee /etc/tenkai/host-applier.toml >/dev/null
sudo chmod 0644 /etc/tenkai/host-applier.toml

# The operator's release signing key and approver key live here, in a
# directory only the invoking user can read: never the tenkai user's.
operator="$work/operator"
tenkaictl dev init-keys --dir "$operator/keys" >/dev/null
zero_digest="sha256:$(printf '0%.0s' $(seq 1 64))"
# The approver's public key, from an approval of nothing in particular.
tenkaictl dev sign-approval --plan-digest "$zero_digest" --env "$environment" \
  --keys "$operator/keys" --approval "$work/probe.json" --trust-roots "$operator/approvers.toml" >/dev/null
# The server's own automatic approver, scoped to this environment. The host
# applier never counts it.
tenkaictl dev init-keys --dir "$work/auto-keys" >/dev/null
tenkaictl dev sign-approval --plan-digest "$zero_digest" --env "$environment" \
  --keys "$work/auto-keys" --approval "$work/auto-probe.json" --trust-roots "$work/auto.toml" >/dev/null
python3 - "$work/auto.toml" "$environment" >"$work/auto-scoped.toml" <<'PY'
import sys, tomllib
signer = tomllib.load(open(sys.argv[1], "rb"))["signers"][0]
print(f'''[[signers]]
key_id = "{signer["key_id"]}"
identity = "{sys.argv[2]}-auto-approver"
public_key = "{signer["public_key"]}"
environments = ["{sys.argv[2]}"]
providers = ["builtin-auto"]''')
PY
sudo install -o tenkai -g tenkai -m 0600 "$work/auto-keys/approval.ed25519" \
  "/var/lib/tenkai/${environment}-auto-approver.ed25519"
cat "$operator/approvers.toml" "$work/auto-scoped.toml" >"$work/plan-approval-trust.toml"
sudo install -o root -g root -m 0644 "$work/plan-approval-trust.toml" /etc/tenkai/plan-approval-trust.toml
# Only the operator's approver may authorize host steps.
sudo install -o root -g root -m 0644 "$operator/approvers.toml" /etc/tenkai/host-approval-policy.toml
cat >"$work/approval-policy.toml" <<EOF
version = 1
mode = "auto"
ttl_ms = 3600000
auto_signer_key = "/var/lib/tenkai/${environment}-auto-approver.ed25519"
EOF
sudo install -o root -g root -m 0644 "$work/approval-policy.toml" "/etc/tenkai/${environment}-approval-policy.toml"

# Sign both example releases, plus a second cluster release one patch
# newer, for the upgrade and the rollback.
releases="$work/releases-src"
mkdir -p "$releases"
cp -R "$root/examples/bare-host-cluster" "$releases/cluster-1.0.0"
cp -R "$root/examples/bare-host-cluster" "$releases/cluster-1.1.0"
sed -i 's/^version = "1.0.0"$/version = "1.1.0"/' "$releases/cluster-1.1.0/tenkai.toml"
sed -i -e 's/^K3S_VERSION=.*/K3S_VERSION=v1.36.6+k3s1/' \
  -e 's/^K3S_SHA256=.*/K3S_SHA256=66ceb8e67edfa547195135d74783bfadc2ecc04a91059e90ae5f70a3dbc98c15/' \
  "$releases/cluster-1.1.0/cluster.env"
cp -R "$root/examples/bare-host-app" "$releases/app-1.0.0"
for release in cluster-1.0.0 cluster-1.1.0 app-1.0.0; do
  tenkaictl dev sign-release "$releases/$release/tenkai.toml" --keys "$operator/keys" \
    --signature "$releases/$release.sig.json" --trust-roots "$work/release-trust.toml" >/dev/null
done
sudo install -o root -g root -m 0644 "$work/release-trust.toml" /etc/tenkai/release-trust-roots.toml

echo "== the environment names its kubeconfig before the cluster exists"
# The server's own store, written as the tenkai user before the server starts.
server_cli() { (cd / && sudo -u tenkai /usr/local/bin/tenkaictl --database "$database" "$@" >/dev/null); }
server_cli init
server_cli env add "$environment" --description "single host with a cluster"
server_cli env cluster-config set "$environment" "$kubeconfig"
server_cli env approval-policy set "$environment" "/etc/tenkai/${environment}-approval-policy.toml"
sudo test ! -e "$kubeconfig" || fail "$kubeconfig exists before the cluster release ran"

echo "== tenkai-server runs as tenkai, with the host executor"
token=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
umask 077
cat >"$work/server.env" <<EOF
TENKAI_MANAGEMENT_TOKEN=$token
TENKAI_RELEASE_TRUST_ROOTS=/etc/tenkai/release-trust-roots.toml
TENKAI_PLAN_APPROVAL_TRUST_ROOTS=/etc/tenkai/plan-approval-trust.toml
TENKAI_PLAN_APPROVAL_DIR=/var/lib/tenkai/approvals
TENKAI_HOST_SPOOL_DIR=/var/lib/tenkai/host-spool
TENKAI_STATE_DIR=/var/lib/tenkai/state
EOF
umask 022
sudo install -o root -g root -m 0600 "$work/server.env" /etc/tenkai/server.env
sudo install -o tenkai -g tenkai -m 0700 -d /var/lib/tenkai/approvals
cat >"$work/$unit.service" <<EOF
[Unit]
Description=Tenkai control plane
After=network-online.target
Wants=network-online.target

[Service]
User=tenkai
Group=tenkai
EnvironmentFile=/etc/tenkai/server.env
ExecStart=/usr/local/bin/tenkai-server --listen 127.0.0.1:0 --database $database --require-executor --reconcile-interval 5
TimeoutStopSec=60
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
EOF
sudo install -o root -g root -m 0644 "$work/$unit.service" "/etc/systemd/system/$unit.service"
sudo systemctl daemon-reload
sudo systemctl restart polkit
sudo systemctl start "$unit"
address=
for _ in $(seq 1 150); do
  address=$(sudo journalctl -u "$unit" --no-pager -o cat |
    sed -n 's/^tenkai-server listening on \([^ ]*\).*/\1/p' | tail -n 1)
  [ -n "$address" ] && curl -fsS "http://$address/readyz" >"$work/readyz" 2>/dev/null && break
  sleep 0.2
done
[ -s "$work/readyz" ] || fail "the server never became ready"
grep -q 'host_executor:v1' "$work/readyz" || fail "/readyz does not report host_executor:v1: $(cat "$work/readyz")"
pid=$(systemctl show -p MainPID --value "$unit")
[ "$(ps -o user= -p "$pid" | tr -d ' ')" = tenkai ] || fail "the server does not run as tenkai"
export TENKAI_SERVER_URL="http://$address" TENKAI_MANAGEMENT_TOKEN="$token"
remote() { /usr/local/bin/tenkaictl --target remote "$@"; }
inspect() { remote env inspect "$environment"; }
generation() { inspect | json 'r["lease"]["generation"] or 0'; }
subscription() {
  # subscription <product> <field>
  inspect | json "next((s.get('$2') or '') for s in r['subscriptions'] if s['product'] == '$1')"
}

echo "== publish and promote the signed releases"
for release in cluster-1.0.0 cluster-1.1.0 app-1.0.0; do
  remote publish "$releases/$release/tenkai.toml" \
    --signature "$releases/$release.sig.json" \
    --trust-roots "$work/release-trust.toml" >/dev/null
done
remote promote cluster@1.0.0 stable >/dev/null
remote promote app@1.0.0 stable >/dev/null

echo "== the in-cluster release fails closed while the cluster does not exist"
started=$(date +%s)
remote env subscribe "$environment" app=stable --generation "$(generation)" >/dev/null
# Each failed tick is logged as degraded; reconcile backs off between them.
failed_ticks() {
  sudo journalctl -u "$unit" --since "@$started" --no-pager -o cat |
    grep -c '^tenkai.reconcile outcome=degraded .*environments_failed=1' || true
}
for _ in $(seq 1 90); do
  [ "$(failed_ticks)" -ge 2 ] && break
  sleep 2
done
attempts=$(failed_ticks)
[ "$attempts" -ge 2 ] || fail "reconcile did not retry the in-cluster release ($attempts attempts): $(inspect)"
[ "$(inspect | json 'r["latest_plan"]["state"]')" = failed ] || fail "the latest plan did not fail: $(inspect)"
# Inspect redacts failure detail; the server's store records it.
(cd / && sudo -u tenkai cat "$database" "$database-wal" 2>/dev/null) | grep -aq "$kubeconfig is not a readable kubeconfig file" ||
  fail "the failed plan does not name the missing kubeconfig"
[ -z "$(subscription app deployed)" ] || fail "app is recorded as deployed without a cluster"
[ "$(subscription app health)" != unknown ] || fail "a refused in-cluster install left app unknown"
echo "   refused $attempts times, deployment unchanged"

echo "== an approved plan installs the cluster as root and hands Tenkai its kubeconfig"
remote env subscribe "$environment" cluster=stable --generation "$(generation)" >/dev/null
# Reconcile cannot approve host steps itself; it leaves the plan for a human.
# Host steps run first even though `app` sorts before `cluster`.
# approve_and_apply [expected step products, in order]
approve_and_apply() {
  remote plan --env "$environment" --generation "$(generation)" >"$work/plan.txt"
  plan=$(sed -n 's/^plan id: //p' "$work/plan.txt")
  digest=$(sed -n 's/^plan digest: //p' "$work/plan.txt")
  [ -n "$plan" ] && [ -n "$digest" ] || fail "no plan: $(cat "$work/plan.txt")"
  if [ $# -gt 0 ]; then
    inspect >"$work/planned.json"
    [ "$(json 'r["latest_plan"]["id"]' <"$work/planned.json")" = "$plan" ] || fail "plan $plan is not the latest"
    steps=$(json '" ".join(s["product"] for s in r["latest_plan"]["steps"])' <"$work/planned.json")
    [ "$steps" = "$1" ] || fail "plan steps are \"$steps\", expected \"$1\""
  fi
  tenkaictl dev sign-approval --plan-digest "$digest" --env "$environment" --keys "$operator/keys" \
    --approval "$work/approval.json" --trust-roots "$operator/approvers.toml" >/dev/null
  remote apply "$plan" --approval "$work/approval.json" --approval-trust-roots "$operator/approvers.toml" \
    --generation "$(generation)" >"$work/apply.txt" || fail "apply failed: $(cat "$work/apply.txt")"
}
approve_and_apply "cluster cluster app"
systemctl is-active --quiet k3s.service || fail "k3s.service is not active"
[ "$(sudo stat -c '%U %a' "$kubeconfig")" = "tenkai 600" ] || fail "$kubeconfig is not tenkai's alone"
sudo test -z "$(sudo ls -A /var/lib/tenkai/host-spool)" || fail "the spool was not emptied"
k3s_version() { sudo /usr/local/bin/k3s --version | awk 'NR == 1 {print $3}'; }
[ "$(k3s_version)" = "v1.36.5+k3s1" ] || fail "k3s is $(k3s_version), not v1.36.5+k3s1"

echo "== the in-cluster release becomes healthy with no operator step"
app_available() {
  sudo /usr/local/bin/k3s kubectl -n "$environment" get deployment app \
    -o 'jsonpath={.status.availableReplicas}' 2>/dev/null
}
for _ in $(seq 1 180); do
  [ "$(subscription app deployed)" = 1.0.0 ] && [ "$(app_available)" = 1 ] && break
  sleep 2
done
[ "$(subscription app deployed)" = 1.0.0 ] || fail "app did not converge: $(inspect)"
[ "$(app_available)" = 1 ] || fail "app is recorded deployed but not available"
# It runs as Tenkai's identity: the field manager is tenkai.
sudo /usr/local/bin/k3s kubectl -n "$environment" get deployment app -o json --show-managed-fields |
  json '[m["manager"] for m in r["metadata"]["managedFields"]]' | grep -q tenkai ||
  fail "app was not applied by the tenkai field manager"
# Tenkai's identity cannot put a pod on the host: the namespace enforces the
# restricted Pod Security standard.
# The probe runs as the tenkai user: root never loads that user's kubeconfig.
# shellcheck disable=SC2024 # the output is ours to read, not root's
if (cd / && sudo -u tenkai -H /usr/local/bin/k3s kubectl --kubeconfig "$kubeconfig" -n "$environment" \
  apply -f -) >"$work/escape.txt" 2>&1 <<'POD'
apiVersion: v1
kind: Pod
metadata:
  name: host-escape
spec:
  containers:
    - name: shell
      image: nginxinc/nginx-unprivileged:1.27-alpine@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0
      securityContext:
        privileged: true
      volumeMounts:
        - name: host
          mountPath: /host
  volumes:
    - name: host
      hostPath:
        path: /
POD
then
  fail "the Tenkai identity created a privileged pod mounting the host"
fi
grep -q 'violates PodSecurity "restricted' "$work/escape.txt" ||
  fail "the privileged pod was refused for another reason: $(cat "$work/escape.txt")"
remote plan --env "$environment" --generation "$(generation)" >"$work/again.txt"
grep -q "$environment is up to date" "$work/again.txt" ||
  fail "a converged environment planned steps: $(cat "$work/again.txt")"

echo "== upgrade the cluster through an approved plan"
remote promote cluster@1.1.0 stable >/dev/null
approve_and_apply
[ "$(k3s_version)" = "v1.36.6+k3s1" ] || fail "k3s is $(k3s_version) after the upgrade"
[ "$(subscription cluster deployed)" = 1.1.0 ] || fail "cluster is not recorded at 1.1.0"
[ "$(app_available)" = 1 ] || fail "app is not available after the cluster upgrade"

echo "== roll the cluster back through an approved plan"
remote promote cluster@1.0.0 stable >/dev/null
approve_and_apply
[ "$(k3s_version)" = "v1.36.5+k3s1" ] || fail "k3s is $(k3s_version) after the rollback"
[ "$(subscription cluster deployed)" = 1.0.0 ] || fail "cluster is not recorded at 1.0.0"
[ "$(app_available)" = 1 ] || fail "app is not available after the cluster rollback"

echo "== uninstall the cluster through an approved plan"
remote env unsubscribe "$environment" cluster --generation "$(generation)" >/dev/null
approve_and_apply
! systemctl is-active --quiet k3s.service || fail "k3s.service still runs"
[ ! -e /usr/local/bin/k3s ] || fail "the k3s binary is still installed"
sudo test ! -e "$kubeconfig" || fail "$kubeconfig is still there"
[ -z "$(sudo find /var/lib/rancher /etc/rancher -mindepth 1 -maxdepth 1 2>/dev/null)" ] ||
  fail "the cluster's state is still on the host"
sudo python3 - "$environment" <<'PY' || fail "the applier does not record the cluster as empty"
import glob, json, sys
records = [json.load(open(path)) for path in glob.glob("/var/lib/tenkai-host/records/*.json")]
cluster = [r for r in records if r["environment"] == sys.argv[1] and r["product"] == "cluster"]
assert len(cluster) == 1 and cluster[0]["state"] == "empty", cluster
PY

echo "bare-host drill passed"
