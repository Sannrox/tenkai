# shellcheck shell=sh
# Sourced by install.sh, health.sh, and uninstall.sh, as root, with kubectl
# defined as the cluster admin.

# The transient unit uninstall.sh runs cleanup.sh in. It is not part of the
# applier's unit, so it outlives an applier that crashed or was stopped.
CLEANUP_UNIT=k3s-cleanup.service

# Waits up to 600 s for a cleanup still running from an interrupted
# uninstall, so nothing installs or cleans up over it.
await_cleanup() {
  deadline=$(($(date +%s) + 600))
  while systemctl is-active --quiet "$CLEANUP_UNIT"; do
    [ "$(date +%s)" -lt "$deadline" ] || return 1
    sleep 2
  done
}

# The version of k3s the API server runs, for example v1.36.5+k3s1.
running_version() {
  kubectl get --raw /version 2>/dev/null | sed -n 's/^ *"gitVersion": *"\([^"]*\)".*/\1/p'
}

# Prints the kubeconfig of Tenkai's identity for environment $1, composed only
# from what root reads from the cluster: the API server's CA and the tenkai
# service account's token. Health compares the tenkai user's file with this,
# byte for byte, instead of ever loading that file as root.
compose_kubeconfig() {
  token=$(kubectl -n tenkai-system get secret tenkai-token -o 'jsonpath={.data.token}' | base64 -d)
  # A service account token is a JWT; anything else is refused, not quoted.
  case "$token" in
    '' | *[!A-Za-z0-9._-]*) return 1 ;;
  esac
  printf 'apiVersion: v1\nkind: Config\nclusters:\n- name: %s\n  cluster:\n' "$1"
  printf '    server: https://127.0.0.1:6443\n'
  printf '    certificate-authority-data: %s\n' "$(base64 -w0 /var/lib/rancher/k3s/server/tls/server-ca.crt)"
  printf 'users:\n- name: tenkai\n  user:\n    token: %s\n' "$token"
  printf 'contexts:\n- name: %s\n  context:\n    cluster: %s\n    user: tenkai\n    namespace: %s\n' "$1" "$1" "$1"
  printf 'current-context: %s\n' "$1"
}
