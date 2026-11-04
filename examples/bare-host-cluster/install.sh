#!/bin/sh
# Install action of the cluster host release. The host applier runs it as root
# in a root-owned copy of the signed release, with TENKAI_ENVIRONMENT set to
# the approved plan's environment (docs/host-releases.md#the-command).
#
# Installs the pinned k3s binary after checking its SHA-256, runs it as its
# own systemd unit, creates Tenkai's scoped identity, and writes that
# identity's kubeconfig to /var/lib/tenkai/cluster/<environment>.kubeconfig,
# readable by the tenkai user only. Running it again converges to the same
# state, so an upgrade is this script with a newer pin.
set -eu

# shellcheck source=cluster.env
. ./cluster.env
# shellcheck source=cluster-lib.sh
. ./cluster-lib.sh

fail() {
  printf 'cluster install: %s\n' "$1" >&2
  exit 1
}

environment=${TENKAI_ENVIRONMENT:?TENKAI_ENVIRONMENT is unset}
# The environment name is also the namespace Tenkai administers, so it must
# be a namespace name and never one that holds credentials: its own
# (tenkai-system) or the cluster's (kube-*).
printf '%s\n' "$environment" | grep -Eq '^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$' ||
  fail "environment ${environment} is not a valid namespace name"
case "$environment" in
  tenkai-system | kube-*) fail "environment ${environment} names a namespace Tenkai must not administer" ;;
esac
id "$TENKAI_USER" >/dev/null 2>&1 || fail "user ${TENKAI_USER} does not exist"

k3s=/usr/local/bin/k3s
unit=/etc/systemd/system/k3s.service
admin_kubeconfig=/etc/rancher/k3s/k3s.yaml
digest() { sha256sum "$1" | awk '{print $1}'; }
kubectl() { "$k3s" kubectl --kubeconfig "$admin_kubeconfig" "$@"; }

# Waits up to $1 seconds for the command or function after it to succeed.
wait_for() {
  deadline=$(($(date +%s) + $1))
  shift
  until "$@" >/dev/null 2>&1; do
    [ "$(date +%s)" -lt "$deadline" ] || return 1
    sleep 2
  done
}

await_cleanup || fail "${CLEANUP_UNIT} from an earlier uninstall is still running"
changed=false

# 1. The pinned binary, verified before it replaces anything.
if [ ! -f "$k3s" ] || [ "$(digest "$k3s")" != "$K3S_SHA256" ]; then
  download=$(mktemp /usr/local/bin/.k3s.XXXXXX)
  trap 'rm -f "$download"' EXIT
  url="https://github.com/k3s-io/k3s/releases/download/$(printf '%s' "$K3S_VERSION" | sed 's/+/%2B/')/k3s"
  curl -fsSL --proto =https --tlsv1.2 --retry 4 --retry-delay 3 -o "$download" "$url" ||
    fail "cannot download ${url}"
  actual=$(digest "$download")
  [ "$actual" = "$K3S_SHA256" ] ||
    fail "checksum mismatch for k3s ${K3S_VERSION}: expected ${K3S_SHA256}, got ${actual}"
  chmod 0755 "$download"
  mv -f "$download" "$k3s"
  trap - EXIT
  changed=true
fi

# 2. Its own unit, so it runs outside the applier's sandbox and outlives this step.
if ! cmp -s k3s.service "$unit"; then
  install -o root -g root -m 0644 k3s.service "$unit"
  systemctl daemon-reload
  changed=true
fi
systemctl enable --quiet k3s.service
# A k3s that still runs another version, for example after an earlier
# attempt replaced the binary and stopped before the restart, restarts too.
if systemctl is-active --quiet k3s.service && [ "$(running_version)" != "$K3S_VERSION" ]; then
  changed=true
fi
# A restart keeps running pods: the unit stops only the k3s process. The unit
# is Type=notify, so this returns once the new process reports ready.
if $changed; then
  timeout 600 systemctl restart k3s.service || fail "k3s did not start within 600 s"
else
  timeout 600 systemctl start k3s.service || fail "k3s did not start within 600 s"
fi

wait_for 300 kubectl get --raw /readyz || fail "the API server did not become ready within 300 s"
node_registered() { [ -n "$(kubectl get nodes -o name)" ]; }
wait_for 120 node_registered || fail "the node did not register within 120 s"
kubectl wait --for=condition=Ready node --all --timeout=300s >/dev/null ||
  fail "the node did not become Ready within 300 s"
[ "$(running_version)" = "$K3S_VERSION" ] ||
  fail "the API server runs $(running_version), not ${K3S_VERSION}"

# 3. Tenkai's identity: admin of the environment's namespace, nothing more,
# in namespaces that enforce the restricted Pod Security standard.
sed "s/ENVIRONMENT/${environment}/g" tenkai-identity.yaml | kubectl apply -f - >/dev/null
token_data() { kubectl -n tenkai-system get secret tenkai-token -o 'jsonpath={.data.token}'; }
token_issued() { [ -n "$(token_data)" ]; }
wait_for 60 token_issued || fail "the token of the tenkai service account was not issued within 60 s"

# 4. The kubeconfig, composed in this root-only directory, then written by the
# tenkai user itself: its home is the tenkai user's to change, so root never
# follows a path there.
umask 077
compose_kubeconfig "$environment" >kubeconfig
# shellcheck disable=SC2016 # expanded by the inner shell
setpriv --reuid="$TENKAI_USER" --regid="$TENKAI_USER" --init-groups -- /bin/sh -c '
  set -eu
  umask 077
  mkdir -p "$1"
  pending=$(mktemp "$1/.kubeconfig.XXXXXX")
  cat >"$pending"
  mv -f "$pending" "$1/$2.kubeconfig"
' sh "$KUBECONFIG_DIR" "$environment" <kubeconfig
rm -f kubeconfig

printf 'k3s %s is up; Tenkai identity written to %s/%s.kubeconfig\n' \
  "$K3S_VERSION" "$KUBECONFIG_DIR" "$environment"
