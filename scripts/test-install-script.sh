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
# kept), and a refused self-upgrade home. The container run installs on
# Ubuntu 22.04, Debian 12, RHEL 8 and 9 compatible images, runs every
# installed host, and expects a clean refusal on musl Alpine. CI passes the
# hosts built by scripts/build-linux-release-hosts.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE="${ROOT}/scripts/package-release-binaries.sh"
HOSTS=(tenkaictl tenkai-server tenkai-executor-guard tenkai-runtime tenkai-runtime-guard)
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
  grep -Fq -- "--source-ref refs/tags/v${VERSION}" <<<"$out" || fail "attestation command lacks the tag"

  # The guard lands beside the server.
  prefix="${tmp}/server"
  run_install "$script" --base-url "$base" --prefix "$prefix" --role server >/dev/null
  expect_files "$prefix" tenkaictl tenkai-server tenkai-executor-guard
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
  expect_refused "self-upgrade home" "$script" --base-url "$base" --prefix "$home" --role server
  expect_refused "self-upgrade home" "$script" --base-url "$base" --prefix "${home}/current" --role server
  expect_files "${home}/versions/abc"
  mkdir -p "${tmp}/linked"
  ln -s "${home}/current/tenkai-server" "${tmp}/linked/tenkai-server"
  expect_refused "is a symbolic link" "$script" --base-url "$base" --prefix "${tmp}/linked" --role server
  expect_files "${tmp}/linked" tenkai-server

  printf 'install script self-test passed\n'
}

# Install $linux_hosts in clean containers through the baked script.
container_test() {
  command -v docker >/dev/null 2>&1 || fail "docker is required with --linux-hosts"
  local release="${tmp}/containers/v${VERSION}" host image
  mkdir -p "$release"
  for host in "${HOSTS[@]}"; do
    cp "${linux_hosts}/${host}-linux-x86_64" "$release/" || fail "missing ${host}-linux-x86_64 in ${linux_hosts}"
  done
  bash "$PACKAGE" install-script --out "$release" --version "$VERSION"
  bash "$PACKAGE" checksums --out "$release"

  # Minimal images lack curl; a real host has it.
  for image in ubuntu:22.04 debian:12 \
    registry.access.redhat.com/ubi8/ubi-minimal registry.access.redhat.com/ubi9/ubi-minimal; do
    printf '== %s\n' "$image"
    docker run --rm --platform linux/amd64 -v "${tmp}/containers:/release:ro" "$image" sh -ec '
      if ! command -v curl >/dev/null 2>&1; then
        apt-get update -qq >/dev/null && apt-get install -y -qq curl >/dev/null
      fi
      sh /release/v'"$VERSION"'/install.sh --base-url file:///release --role server
      sh /release/v'"$VERSION"'/install.sh --base-url file:///release --role runtime >/dev/null
      tenkaictl --version
      for host in tenkaictl tenkai-server tenkai-executor-guard tenkai-runtime tenkai-runtime-guard; do
        "/usr/local/bin/${host}" --help >/dev/null
      done'
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
