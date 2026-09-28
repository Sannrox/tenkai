#!/usr/bin/env bash
# Package default-feature Tenkai product hosts for a GitHub Release.
#
# Usage:
#   scripts/package-release-binaries.sh package --out DIR [--bin-dir DIR]
#       [--platform ID] [--strip]
#   scripts/package-release-binaries.sh checksums --out DIR [--require-complete]
#   scripts/package-release-binaries.sh self-test
#
# Hosts: tenkaictl, tenkai-server, tenkai-executor-guard, tenkai-runtime,
# tenkai-runtime-guard. Platforms: linux-x86_64, darwin-aarch64.
# These files are GitHub Release packaging, not Catalog artifacts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOSTS=(tenkaictl tenkai-server tenkai-executor-guard tenkai-runtime tenkai-runtime-guard)
PLATFORMS=(linux-x86_64 darwin-aarch64)
CHECKSUMS_NAME=SHA256SUMS

usage() {
  sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-2}"
}

fail() {
  printf 'package-release-binaries: %s\n' "$1" >&2
  exit 1
}

detect_platform() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os:$arch" in
    Linux:x86_64) printf '%s\n' linux-x86_64 ;;
    Darwin:arm64) printf '%s\n' darwin-aarch64 ;;
    *) fail "unsupported host ${os} ${arch}" ;;
  esac
}

is_platform() {
  local candidate="$1" platform
  for platform in "${PLATFORMS[@]}"; do
    if [[ "$candidate" == "$platform" ]]; then
      return 0
    fi
  done
  return 1
}

packaged_name() {
  printf '%s-%s\n' "$1" "$2"
}

is_packaged_name() {
  local name="$1" host platform
  for host in "${HOSTS[@]}"; do
    for platform in "${PLATFORMS[@]}"; do
      if [[ "$name" == "$(packaged_name "$host" "$platform")" ]]; then
        return 0
      fi
    done
  done
  return 1
}

complete_names() {
  local host platform
  for host in "${HOSTS[@]}"; do
    for platform in "${PLATFORMS[@]}"; do
      packaged_name "$host" "$platform"
    done
  done
}

checksum_tool() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s\n' sha256sum
  elif command -v shasum >/dev/null 2>&1; then
    printf '%s\n' shasum
  else
    fail "missing sha256sum or shasum"
  fi
}

checksum_file() {
  local path="$1" tool
  tool="$(checksum_tool)"
  case "$tool" in
    sha256sum) sha256sum -- "$path" ;;
    shasum) shasum -a 256 -- "$path" ;;
  esac
}

verify_checksums() {
  local out="$1" tool
  tool="$(checksum_tool)"
  case "$tool" in
    sha256sum) (cd "$out" && sha256sum -c "$CHECKSUMS_NAME") ;;
    shasum) (cd "$out" && shasum -a 256 -c "$CHECKSUMS_NAME") ;;
  esac
}

list_packaged_files() {
  local out="$1" path name glob_state
  local -a names=()
  glob_state="$(shopt -p nullglob)"
  shopt -s nullglob
  for path in "$out"/*; do
    name="$(basename "$path")"
    if [[ "$name" == "$CHECKSUMS_NAME" ]]; then
      continue
    fi
    if [[ -d "$path" ]]; then
      eval "$glob_state"
      fail "unexpected directory in ${out}: ${name}"
    fi
    if ! is_packaged_name "$name"; then
      eval "$glob_state"
      fail "unexpected file in ${out}: ${name}"
    fi
    names+=("$name")
  done
  eval "$glob_state"
  if [[ ${#names[@]} -eq 0 ]]; then
    return 0
  fi
  printf '%s\n' "${names[@]}" | LC_ALL=C sort
}

cmd_package() {
  local out="" bin_dir="${ROOT}/target/release" platform="" do_strip=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --out)
        [[ $# -ge 2 ]] || fail "--out requires a directory"
        out="$2"
        shift 2
        ;;
      --bin-dir)
        [[ $# -ge 2 ]] || fail "--bin-dir requires a directory"
        bin_dir="$2"
        shift 2
        ;;
      --platform)
        [[ $# -ge 2 ]] || fail "--platform requires an id"
        platform="$2"
        shift 2
        ;;
      --strip)
        do_strip=true
        shift
        ;;
      -h | --help) usage 0 ;;
      *) fail "unknown package argument: $1" ;;
    esac
  done
  [[ -n "$out" ]] || fail "package requires --out"
  [[ -d "$bin_dir" ]] || fail "bin directory does not exist: ${bin_dir}"

  local host_platform
  host_platform="$(detect_platform)"
  if [[ -z "$platform" ]]; then
    platform="$host_platform"
  fi
  is_platform "$platform" || fail "unknown platform: ${platform}"
  if [[ "$platform" != "$host_platform" ]]; then
    fail "platform ${platform} does not match host ${host_platform}"
  fi

  mkdir -p "$out"
  local host src dest
  for host in "${HOSTS[@]}"; do
    src="${bin_dir}/${host}"
    dest="${out}/$(packaged_name "$host" "$platform")"
    [[ -f "$src" ]] || fail "missing host binary: ${src}"
    [[ -s "$src" ]] || fail "empty host binary: ${src}"
    cp "$src" "$dest"
    chmod 0755 "$dest"
    if $do_strip; then
      command -v strip >/dev/null 2>&1 || fail "strip is required with --strip"
      strip "$dest"
    fi
  done
}

cmd_checksums() {
  local out="" require_complete=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --out)
        [[ $# -ge 2 ]] || fail "--out requires a directory"
        out="$2"
        shift 2
        ;;
      --require-complete)
        require_complete=true
        shift
        ;;
      -h | --help) usage 0 ;;
      *) fail "unknown checksums argument: $1" ;;
    esac
  done
  [[ -n "$out" ]] || fail "checksums requires --out"
  [[ -d "$out" ]] || fail "output directory does not exist: ${out}"

  local names expected
  names="$(list_packaged_files "$out")"
  [[ -n "$names" ]] || fail "no packaged host binaries in ${out}"
  if $require_complete; then
    expected="$(complete_names | LC_ALL=C sort)"
    if [[ "$names" != "$expected" ]]; then
      fail "incomplete GitHub Release set in ${out}"
    fi
  fi

  local tmp name hash
  tmp="$(mktemp)"
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    hash="$(checksum_file "${out}/${name}" | awk '{print $1}')"
    [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || fail "invalid sha256 for ${name}"
    printf '%s  %s\n' "$hash" "$name"
  done <<<"$names" >"$tmp"
  mv "$tmp" "${out}/${CHECKSUMS_NAME}"
  verify_checksums "$out" >/dev/null
}

expect_fail() {
  local message="$1"
  shift
  local output status
  set +e
  output="$("$@" 2>&1)"
  status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    fail "expected failure (${message})"
  fi
  printf '%s\n' "$output" | grep -Fq "$message" || fail "failure did not mention ${message}"
}

cmd_self_test() {
  local tmp bin out host platform other
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/tenkai-release-pack.XXXXXX")"
  trap "rm -rf $(printf '%q' "$tmp")" EXIT
  bin="${tmp}/bin"
  out="${tmp}/out"
  mkdir -p "$bin" "$out"
  platform="$(detect_platform)"
  if [[ "$platform" == linux-x86_64 ]]; then
    other=darwin-aarch64
  else
    other=linux-x86_64
  fi

  for host in "${HOSTS[@]}"; do
    printf 'stub-%s\n' "$host" >"${bin}/${host}"
    chmod 0755 "${bin}/${host}"
  done
  printf 'fixture\n' >"${bin}/tenkai-worker-lifecycle-fixture"
  chmod 0755 "${bin}/tenkai-worker-lifecycle-fixture"
  printf 'conformance\n' >"${bin}/tenkai-delivery-conformance"
  chmod 0755 "${bin}/tenkai-delivery-conformance"

  "$0" package --out "$out" --bin-dir "$bin" --platform "$platform"
  [[ -f "${out}/$(packaged_name tenkaictl "$platform")" ]] || fail "self-test missing tenkaictl asset"
  [[ ! -e "${out}/tenkai-worker-lifecycle-fixture-${platform}" ]] || fail "self-test packaged fixture host"
  [[ ! -e "${out}/tenkai-delivery-conformance-${platform}" ]] || fail "self-test packaged conformance harness"

  "$0" checksums --out "$out"
  [[ -f "${out}/${CHECKSUMS_NAME}" ]] || fail "self-test missing checksums"
  verify_checksums "$out" >/dev/null

  expect_fail "platform ${other} does not match host ${platform}" \
    "$0" package --out "$out" --bin-dir "$bin" --platform "$other"
  mkdir -p "${tmp}/empty"
  expect_fail "missing host binary" \
    "$0" package --out "${tmp}/missing" --bin-dir "${tmp}/empty" --platform "$platform"

  expect_fail "incomplete GitHub Release set" \
    "$0" checksums --out "$out" --require-complete

  printf 'junk\n' >"${out}/not-a-host"
  expect_fail "unexpected file in ${out}: not-a-host" \
    "$0" checksums --out "$out"
  rm -f "${out}/not-a-host"

  printf 'tampered\n' >>"${out}/$(packaged_name tenkaictl "$platform")"
  expect_fail "FAILED" verify_checksums "$out"

  printf 'package-release-binaries self-test passed\n'
}

main() {
  local cmd="${1:-}"
  if [[ $# -gt 0 ]]; then
    shift
  fi
  case "$cmd" in
    package) cmd_package "$@" ;;
    checksums) cmd_checksums "$@" ;;
    self-test) cmd_self_test "$@" ;;
    -h | --help | "") usage 0 ;;
    *) usage 1 ;;
  esac
}

main "$@"
