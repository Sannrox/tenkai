#!/usr/bin/env bash
# Install, start, and remove the tenkai .deb and .rpm (#917) without a
# privileged container.
#
# Usage: scripts/test-system-packages.sh --linux-hosts DIR
#
# DIR holds the linux-x86_64 hosts written by
# scripts/build-linux-release-hosts.sh. The script builds both packages from
# them with scripts/package-release-binaries.sh system-packages, then:
#   - .deb, installed with sudo on this host, which must run systemd: the
#     package installs without enabling tenkai-server and writes a root-only
#     management token; `systemctl enable --now tenkai-server` serves /readyz
#     with the shell executor (the server found its guard) and /ui/;
#     tenkaictl reaches it over the socket as a tenkai-viewer and tenkai-operator user and over
#     TCP with the token; purge stops the server, deletes the binaries, the
#     unit, and the token, and keeps the store.
#   - .rpm, in an unprivileged UBI 9 container without systemd: the package
#     creates the user, groups, token, and /run/tenkai, skips systemctl, and
#     removal deletes the binaries and the unit and keeps the token. The
#     service itself is the same unit and binaries the .deb run starts.
# It changes this host's packages and users, so it runs only on a disposable
# GitHub Actions runner (the CI Release dry run job).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UBI=registry.access.redhat.com/ubi9/ubi

fail() {
  printf 'test-system-packages: %s\n' "$1" >&2
  exit 1
}

hosts=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --linux-hosts)
      [[ $# -ge 2 ]] || fail "--linux-hosts requires a directory"
      hosts="$2"
      shift 2
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done
[[ -d "$hosts" ]] || fail "--linux-hosts DIR is required"
[[ "${GITHUB_ACTIONS:-}" == true ]] || fail "runs only on a GitHub Actions runner: it installs a package on this host"
[[ -d /run/systemd/system ]] || fail "this host does not run systemd"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/tenkai-system-packages.$$.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

dist="${tmp}/dist"
mkdir -p "$dist"
for host in tenkaictl tenkai-server tenkai-executor-guard; do
  cp "${hosts}/${host}-linux-x86_64" "$dist/" || fail "missing ${host}-linux-x86_64 in ${hosts}"
done
version="$(awk '
  /^\[/ { in_package = ($0 == "[package]") }
  in_package && /^version = "/ { gsub(/^version = "|"$/, ""); print; exit }
' "${ROOT}/Cargo.toml")"
bash "${ROOT}/scripts/package-release-binaries.sh" system-packages \
  --out "$dist" --platform linux-x86_64 --version "$version"
chmod 0755 "$tmp" "$dist"
chmod 0644 "$dist"/*.deb "$dist"/*.rpm

# Checks after install, shared by both formats. $1 says whether systemd runs.
# shellcheck disable=SC2016 # expanded by the shell that runs the checks
installed_checks='
  fail() { echo "test-system-packages: $1" >&2; exit 1; }
  for path in /etc/tenkai/management.token /etc/tenkai/server.env; do
    [ "$(stat -c %U:%a "$path")" = root:600 ] || fail "$path is $(stat -c %U:%a "$path"), not root:600"
  done
  token="$(cat /etc/tenkai/management.token)"
  grep -qx "TENKAI_MANAGEMENT_TOKEN=${token}" /etc/tenkai/server.env \
    || fail "server.env does not carry the management token"
  id -nG tenkai | tr " " "\n" | grep -qx tenkai-viewer || fail "tenkai is not in tenkai-viewer"
  for group in tenkai-operator tenkai-admin; do
    getent group "$group" >/dev/null || fail "group $group is missing"
  done
  [ "$(stat -c %U:%G:%a /run/tenkai)" = tenkai:tenkai-viewer:750 ] || fail "/run/tenkai is not tenkai:tenkai-viewer:750"
  [ -f /usr/lib/systemd/system/tenkai-server.service ] || fail "the unit is not installed"
  tenkaictl --version | grep -qx "tenkaictl ${VERSION}" || fail "tenkaictl is not ${VERSION}"
'
# shellcheck disable=SC2016
removed_checks='
  for path in /usr/bin/tenkaictl /usr/bin/tenkai-server /usr/bin/tenkai-executor-guard \
    /usr/lib/systemd/system/tenkai-server.service; do
    [ ! -e "$path" ] || fail "removal left $path"
  done
'

# .deb on this host.
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${dist}/tenkai-linux-x86_64.deb" >/dev/null
sudo env VERSION="$version" CHECKS="$installed_checks" REMOVED="$removed_checks" bash -euo pipefail -c '
  eval "$CHECKS"
  [ "$(systemctl is-enabled tenkai-server.service 2>/dev/null || true)" = disabled ] \
    || fail "the package enabled tenkai-server"
  if systemctl is-active --quiet tenkai-server.service; then fail "the package started tenkai-server"; fi

  systemctl enable --now tenkai-server.service
  for _ in $(seq 1 60); do
    curl -fsS http://127.0.0.1:8080/readyz >/tmp/tenkai-readyz 2>/dev/null && break
    sleep 1
  done
  grep -q shell_executor /tmp/tenkai-readyz \
    || { journalctl -u tenkai-server --no-pager | tail -20; fail "/readyz lacks the shell executor"; }
  curl -fsS -o /dev/null http://127.0.0.1:8080/ui/ || fail "/ui/ is not served"
  # On the host tenkaictl uses the socket as the calling user; the token is
  # the TCP path.
  [ -S /run/tenkai/tenkai.sock ] || fail "the server did not bind /run/tenkai/tenkai.sock"
  useradd -m -G tenkai-viewer,tenkai-operator tenkai-pkg-test
  runuser -u tenkai-pkg-test -- tenkaictl env list >/dev/null || fail "a tenkai-viewer and tenkai-operator user cannot use the socket"
  tenkaictl --token-file /etc/tenkai/management.token env list >/dev/null \
    || fail "the package token does not reach the server over TCP"

  DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq tenkai >/dev/null
  if systemctl is-active --quiet tenkai-server.service; then fail "removal left tenkai-server running"; fi
  eval "$REMOVED"
  [ ! -e /etc/tenkai/management.token ] || fail "purge left the token"
  [ -e /var/lib/tenkai/tenkai.db ] || fail "removal deleted the store"
'
printf 'deb: installed, served, and purged on this host\n'

# .rpm in an unprivileged container. No systemd runs there, so the package
# scripts must skip systemctl.
docker run --rm -v "${dist}:/pkg:ro" -e VERSION="$version" \
  -e CHECKS="$installed_checks" -e REMOVED="$removed_checks" "$UBI" bash -euo pipefail -c '
  dnf install -y -q /pkg/tenkai-linux-x86_64.rpm >/dev/null
  eval "$CHECKS"
  dnf remove -y -q tenkai >/dev/null
  eval "$REMOVED"
  [ -e /etc/tenkai/management.token ] || fail "removal deleted the token"
'
printf 'rpm: installed and removed in %s\n' "$UBI"
