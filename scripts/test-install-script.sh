#!/usr/bin/env bash
# Test scripts/install.sh against a local fixture release (file:// URLs).
#
# Usage:
#   scripts/test-install-script.sh                    fixture self-test
#   scripts/test-install-script.sh --linux-hosts DIR  also install DIR's
#       linux-x86_64 hosts in clean distribution containers (needs docker)
#
# The self-test covers each role, the baked and --version paths, a checksum
# mismatch and a missing SHA256SUMS entry (nothing installed, existing files
# kept), a refused self-upgrade home, --role host-applier leaving that home
# alone (and refusing --prefix), and --with-host-applier refused for a
# non-root user or a non-Linux system. The container run installs on
# Ubuntu 22.04, Debian 12, RHEL 8 and 9 compatible images, also with
# --with-host-applier as root (owners, modes, files), runs every installed
# host, refuses the applier into a directory others can write, through a
# symbolic link, or for a non-root user, and expects a clean refusal on musl Alpine. CI passes the
# hosts built by scripts/build-linux-release-hosts.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE="${ROOT}/scripts/package-release-binaries.sh"
HOSTS=(tenkaictl tenkai-server tenkai-executor-guard tenkai-runtime tenkai-runtime-guard)
APPLIER=tenkai-host-applier-linux-x86_64
VERSION=1.2.3

fail() {
  printf 'test-install-script: %s\n' "$1" >&2
  exit 1
}

linux_hosts=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --linux-hosts)
      [[ $# -ge 2 ]] || fail "--linux-hosts requires a directory"
      linux_hosts="$(cd "$2" && pwd)"
      shift 2
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done

tmp="$(mktemp -d "${TMPDIR:-/tmp}/tenkai-install-test.$$.XXXXXX")"
trap "rm -rf $(printf '%q' "$tmp")" EXIT

# Run install.sh under sh; print its output; return its status.
run_install() {
  sh "$@" 2>&1
}

# Expect run_install to fail and mention message.
expect_refused() {
  local message="$1" output status
  shift
  set +e
  output="$(run_install "$@")"
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || fail "expected refusal (${message}), got success: ${output}"
  grep -Fq -- "$message" <<<"$output" || fail "refusal did not mention '${message}': ${output}"
}

# Only the named files, no leftover staging directory.
expect_files() {
  local dir="$1" actual expected=""
  shift
  actual="$(ls -A "$dir" | LC_ALL=C sort | tr '\n' ' ')"
  if [[ $# -gt 0 ]]; then
    expected="$(printf '%s\n' "$@" | LC_ALL=C sort | tr '\n' ' ')"
  fi
  [[ "$actual" == "$expected" ]] || fail "${dir} holds '${actual}', expected '$*'"
}

# A release dir under $1/v$VERSION with stub hosts for every platform.
write_fixture() {
  local release="$1/v${VERSION}" host platform
  mkdir -p "$release"
  for host in "${HOSTS[@]}"; do
    for platform in linux-x86_64 darwin-aarch64; do
      printf '#!/bin/sh\necho "%s %s"\n' "$host" "$VERSION" >"${release}/${host}-${platform}"
    done
  done
  printf '#!/bin/sh\necho applier\n' >"${release}/${APPLIER}"
  bash "$PACKAGE" install-script --out "$release" --version "$VERSION"
  bash "$PACKAGE" checksums --out "$release"
}

self_test() {
  local releases="${tmp}/releases" bad="${tmp}/bad" script out prefix
  write_fixture "$releases"
  script="${releases}/v${VERSION}/install.sh"
  local base="file://${releases}"

  # Baked version, cli role.
  prefix="${tmp}/cli"
  out="$(run_install "$script" --base-url "$base" --prefix "$prefix")"
  expect_files "$prefix" tenkaictl
  [[ "$("${prefix}/tenkaictl")" == "tenkaictl ${VERSION}" ]] || fail "cli install did not run"
  grep -Fq "gh attestation verify ${prefix}/tenkaictl --repo Sannrox/tenkai" <<<"$out" \
    || fail "no attestation command: ${out}"
  grep -Fq -- "--source-ref refs/heads/main" <<<"$out" || fail "attestation command must pin the main workflow run"

  # The guard lands beside the server. --role server writes client.toml.
  prefix="${tmp}/server"
  sysconf="${tmp}/sysconf"
  out="$(run_install "$script" --base-url "$base" --prefix "$prefix" --role server --sysconfdir "$sysconf")"
  expect_files "$prefix" tenkaictl tenkai-server tenkai-executor-guard
  expect_files "${sysconf}/tenkai" client.toml host-grants.toml management.token
  grep -Fq 'target = "remote"' "${sysconf}/tenkai/client.toml" || fail "client.toml missing target: $(cat "${sysconf}/tenkai/client.toml")"
  grep -Fq "token_file = \"${sysconf}/tenkai/management.token\"" "${sysconf}/tenkai/client.toml" \
    || fail "client.toml missing token_file: $(cat "${sysconf}/tenkai/client.toml")"
  grep -Fq 'value = "tenkai-operator"' "${sysconf}/tenkai/host-grants.toml" \
    || fail "host-grants.toml missing operator rule: $(cat "${sysconf}/tenkai/host-grants.toml")"
  grep -Fq "TENKAI_MANAGEMENT_TOKEN in ${sysconf}/tenkai/server.env" <<<"$out" \
    || fail "install did not name TENKAI_MANAGEMENT_TOKEN: ${out}"
  [[ "$(stat -c '%a' "${sysconf}/tenkai/management.token" 2>/dev/null || stat -f '%OLp' "${sysconf}/tenkai/management.token")" == *600 ]] \
    || fail "management.token is not mode 0600"
  # Re-run keeps the token and client.toml.
  token="$(cat "${sysconf}/tenkai/management.token")"
  run_install "$script" --base-url "$base" --prefix "$prefix" --role server --sysconfdir "$sysconf" >/dev/null
  [[ "$(cat "${sysconf}/tenkai/management.token")" == "$token" ]] || fail "reinstall replaced the management token"
  # Relative --sysconfdir becomes absolute in client.toml and does not hang.
  rel_sysconf="${tmp}/rel-sysconf"
  mkdir -p "$rel_sysconf"
  (
    cd "$tmp"
    run_install "$script" --base-url "$base" --prefix "${tmp}/rel-prefix" --role server --sysconfdir rel-sysconf >/dev/null
  )
  expect_files "${rel_sysconf}/tenkai" client.toml host-grants.toml management.token
  grep -Fq "token_file = \"${rel_sysconf}/tenkai/management.token\"" "${rel_sysconf}/tenkai/client.toml" \
    || fail "relative sysconfdir did not become an absolute token_file: $(cat "${rel_sysconf}/tenkai/client.toml")"
  prefix="${tmp}/runtime"
  run_install "$script" --base-url "$base" --prefix "$prefix" --role runtime >/dev/null
  expect_files "$prefix" tenkai-runtime tenkai-runtime-guard

  # Default prefix for a non-root user.
  if [[ "$(id -u)" != 0 ]]; then
    mkdir -p "${tmp}/home"
    HOME="${tmp}/home" run_install "$script" --base-url "$base" >/dev/null
    expect_files "${tmp}/home/.local/bin" tenkaictl
  fi

  # The source script has no version unless told one.
  expect_refused "no release version" "${ROOT}/scripts/install.sh" --base-url "$base" --prefix "${tmp}/src"
  run_install "${ROOT}/scripts/install.sh" --base-url "$base" --prefix "${tmp}/src" --version "v${VERSION}" >/dev/null
  expect_files "${tmp}/src" tenkaictl
  expect_refused "invalid version 1.2" "$script" --base-url "$base" --prefix "${tmp}/src" --version 1.2
  expect_refused "unknown role" "$script" --base-url "$base" --prefix "${tmp}/src" --role hub

  # A checksum mismatch or a missing entry installs nothing and keeps the
  # files already there.
  prefix="${tmp}/kept"
  mkdir -p "$prefix"
  printf 'old\n' >"${prefix}/tenkaictl"
  cp -R "$releases" "$bad"
  printf 'tampered\n' >>"${bad}/v${VERSION}/tenkai-server-linux-x86_64"
  printf 'tampered\n' >>"${bad}/v${VERSION}/tenkai-server-darwin-aarch64"
  expect_refused "checksum mismatch for tenkai-server-" "$script" --base-url "file://${bad}" --prefix "$prefix" --role server
  expect_files "$prefix" tenkaictl
  [[ "$(cat "${prefix}/tenkaictl")" == old ]] || fail "a refused install replaced tenkaictl"
  grep -v ' tenkaictl-' "${releases}/v${VERSION}/SHA256SUMS" >"${bad}/v${VERSION}/SHA256SUMS"
  expect_refused "SHA256SUMS has no entry for tenkaictl-" "$script" --base-url "file://${bad}" --prefix "$prefix"
  expect_files "$prefix" tenkaictl
  [[ "$(cat "${prefix}/tenkaictl")" == old ]] || fail "a refused install replaced tenkaictl"
  expect_refused "cannot download" "$script" --base-url "file://${tmp}/missing" --prefix "$prefix"

  # A self-upgrade home, or a link into one, belongs to tenkaictl self-upgrade.
  local home="${tmp}/home-layout"
  mkdir -p "${home}/versions/abc"
  ln -s versions/abc "${home}/current"
  printf '{}\n' >"${home}/upgrade.json"
  expect_refused "self-upgrade home" "$script" --base-url "$base" --prefix "$home" --role server
  expect_refused "self-upgrade home" "$script" --base-url "$base" --prefix "${home}/current" --role server
  expect_refused "do not pass --prefix" "$script" --base-url "$base" --prefix "$home" --role host-applier
  expect_files "$home" current upgrade.json versions
  expect_files "${home}/versions/abc"
  mkdir -p "${tmp}/linked"
  ln -s "${home}/current/tenkai-server" "${tmp}/linked/tenkai-server"
  expect_refused "is a symbolic link" "$script" --base-url "$base" --prefix "${tmp}/linked" --role server
  expect_files "${tmp}/linked" tenkai-server
  mkdir -p "${tmp}/dir/tenkai-executor-guard"
  expect_refused "is not a regular file" "$script" --base-url "$base" --prefix "${tmp}/dir" --role server
  expect_files "${tmp}/dir" tenkai-executor-guard
  expect_files "${tmp}/dir/tenkai-executor-guard"

  # The applier installs as root on linux-x86_64 only; anything else is
  # refused before a download.
  local applier_refusal="--with-host-applier must run as root"
  if [[ "$(uname -s)" != Linux ]]; then
    applier_refusal="published for linux-x86_64 only"
  fi
  if [[ "$(id -u)" != 0 || "$(uname -s)" != Linux ]]; then
    expect_refused "$applier_refusal" "$script" --base-url "file://${tmp}/missing" --prefix "${tmp}/applier" --with-host-applier
    [[ ! -e "${tmp}/applier" ]] || fail "a refused applier install created its prefix"
    # --role host-applier never inspects a self-upgrade home; without root it
    # stops on the applier's root check, not the self-upgrade refusal.
    expect_refused "$applier_refusal" "$script" --base-url "$base" --role host-applier
    expect_files "$home" current upgrade.json versions
  fi

  printf 'install script self-test passed\n'
}

# Install $linux_hosts in clean containers through the baked script.
container_test() {
  command -v docker >/dev/null 2>&1 || fail "docker is required with --linux-hosts"
  local release="${tmp}/containers/v${VERSION}" host image
  mkdir -p "$release"
  for host in "${HOSTS[@]}" tenkai-host-applier; do
    cp "${linux_hosts}/${host}-linux-x86_64" "$release/" || fail "missing ${host}-linux-x86_64 in ${linux_hosts}"
  done
  bash "$PACKAGE" install-script --out "$release" --version "$VERSION"
  bash "$PACKAGE" checksums --out "$release"

  # Minimal images lack curl; a real host has it.
  for image in ubuntu:22.04 debian:12 \
    registry.access.redhat.com/ubi8/ubi-minimal registry.access.redhat.com/ubi9/ubi-minimal; do
    printf '== %s\n' "$image"
    docker run --rm --platform linux/amd64 -v "${tmp}/containers:/release:ro" \
      -v "${ROOT}/scripts/apt-install.sh:/apt-install.sh:ro" "$image" sh -ec '
      if ! command -v curl >/dev/null 2>&1; then
        sh /apt-install.sh curl >/dev/null
      fi
      release=/release/v'"$VERSION"'
      sh "${release}/install.sh" --base-url file:///release --role server --with-host-applier
      sh "${release}/install.sh" --base-url file:///release --role runtime >/dev/null
      tenkaictl --version
      for host in tenkaictl tenkai-server tenkai-executor-guard tenkai-runtime tenkai-runtime-guard; do
        "/usr/local/bin/${host}" --help >/dev/null
      done
      applier=/usr/local/libexec/tenkai/tenkai-host-applier
      "$applier" --help >/dev/null
      test "$(stat -c "%u:%g %a" "$applier" /usr/local/libexec/tenkai)" = "0:0 755
0:0 755"
      test "$(stat -c "%u:%g %a" /etc/systemd/system/tenkai-host-apply@.service /etc/polkit-1/rules.d/50-tenkai-host-apply.rules)" = "0:0 644
0:0 644"
      # Minimal images lack cmp.
      same() { test "$(sha256sum <"$1")" = "$(sha256sum <"$2")"; }
      same "${release}/tenkai-host-apply.service" /etc/systemd/system/tenkai-host-apply@.service
      same "${release}/tenkai-host-apply.rules" /etc/polkit-1/rules.d/50-tenkai-host-apply.rules
      # Refused for a non-root user, and into a directory others can write.
      if command -v setpriv >/dev/null 2>&1 && setpriv --reuid=65534 --regid=65534 --clear-groups sh "${release}/install.sh" \
        --base-url file:///release --prefix /tmp/nobody --with-host-applier 2>/tmp/err; then
        echo "non-root applier install was not refused" >&2
        exit 1
      fi
      if command -v setpriv >/dev/null 2>&1; then
        grep -Fq "must run as root" /tmp/err
        echo "non-root applier install refused"
      fi
      chmod 0777 /usr/local/libexec/tenkai
      if sh "${release}/install.sh" --base-url file:///release --with-host-applier 2>/tmp/err; then
        echo "applier install into a world-writable directory was not refused" >&2
        exit 1
      fi
      grep -Fq "/usr/local/libexec/tenkai is writable by group or others" /tmp/err
      # Nor through a symbolic link.
      chmod 0755 /usr/local/libexec/tenkai
      mv /usr/local/libexec/tenkai /usr/local/libexec/tenkai.real
      ln -s tenkai.real /usr/local/libexec/tenkai
      if sh "${release}/install.sh" --base-url file:///release --with-host-applier 2>/tmp/err; then
        echo "applier install through a symbolic link was not refused" >&2
        exit 1
      fi
      grep -Fq "/usr/local/libexec/tenkai is a symbolic link" /tmp/err
      echo "host applier ok"
      rm /usr/local/libexec/tenkai
      mv /usr/local/libexec/tenkai.real /usr/local/libexec/tenkai
      # A self-upgrade home is refused for --role server, and left alone by
      # --role host-applier, which re-installs the applier by rename.
      mkdir -p /opt/tenkai/versions/abc
      ln -s versions/abc /opt/tenkai/current
      printf "{}\n" >/opt/tenkai/upgrade.json
      if sh "${release}/install.sh" --base-url file:///release --role server --with-host-applier --prefix /opt/tenkai 2>/tmp/err; then
        echo "server install into a self-upgrade home was not refused" >&2
        exit 1
      fi
      grep -Fq "self-upgrade home" /tmp/err
      test -L /opt/tenkai/current
      test -f /opt/tenkai/upgrade.json
      sh "${release}/install.sh" --base-url file:///release --role host-applier
      test -L /opt/tenkai/current
      test -f /opt/tenkai/upgrade.json
      test ! -e /opt/tenkai/tenkaictl
      applier=/usr/local/libexec/tenkai/tenkai-host-applier
      test "$(stat -c "%u:%g %a" "$applier")" = "0:0 755"
      echo "host-applier role ok"'
  done

  printf '== alpine:3 (musl, refused)\n'
  local output status
  set +e
  output="$(docker run --rm --platform linux/amd64 -v "${tmp}/containers:/release:ro" alpine:3 \
    sh /release/v"$VERSION"/install.sh --base-url file:///release 2>&1)"
  status=$?
  set -e
  printf '%s\n' "$output"
  [[ "$status" -ne 0 ]] || fail "alpine install was not refused"
  grep -Fq "musl libc is not supported" <<<"$output" || fail "alpine refusal did not name musl"
  printf 'install script container test passed\n'
}

self_test
if [[ -n "$linux_hosts" ]]; then
  container_test
fi
