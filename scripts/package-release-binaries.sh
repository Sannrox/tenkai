#!/usr/bin/env bash
# Package default-feature Tenkai product hosts for a GitHub Release.
#
# Usage:
#   scripts/package-release-binaries.sh package --out DIR [--bin-dir DIR]
#       [--platform ID] [--strip]
#   scripts/package-release-binaries.sh package-hub --out DIR [--bin-dir DIR]
#       [--platform ID] [--strip]
#   scripts/package-release-binaries.sh install-script --out DIR --version X.Y.Z
#   scripts/package-release-binaries.sh checksums --out DIR [--require-complete]
#   scripts/package-release-binaries.sh check-glibc --out DIR
#   scripts/package-release-binaries.sh names
#   scripts/package-release-binaries.sh self-test
#
# Community hosts: tenkaictl, tenkai-server, tenkai-executor-guard,
# tenkai-runtime, tenkai-runtime-guard, and on linux-x86_64 only
# tenkai-host-applier. Hub host asset:
# tenkai-server-postgres-<platform> (built with --features postgres,ui).
# Platforms: linux-x86_64, darwin-aarch64. check-glibc refuses a Linux host
# that needs a glibc newer than LINUX_GLIBC_FLOOR (built by
# scripts/build-linux-release-hosts.sh).
# The HTTP API contract (api/tenkai-http-v1.schema.json), install.sh
# (scripts/install.sh with the release version baked in by install-script),
# and the host applier's systemd unit and polkit rule (copied by
# install-script from examples/host-applier-systemd) are attached and
# checksummed with them. These files are GitHub Release packaging, not
# Catalog artifacts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOSTS=(tenkaictl tenkai-server tenkai-executor-guard tenkai-runtime tenkai-runtime-guard)
# Hosts published for linux-x86_64 only: the applier needs systemd (#949).
LINUX_ONLY_HOSTS=(tenkai-host-applier)
HUB_SERVER_ASSET=tenkai-server-postgres
PLATFORMS=(linux-x86_64 darwin-aarch64)
CHECKSUMS_NAME=SHA256SUMS
# Release asset names of the host applier unit and polkit rule. GitHub may
# rename an asset with "@", so the unit's asset name drops it.
HOST_APPLY_UNIT=tenkai-host-apply.service
HOST_APPLY_RULES=tenkai-host-apply.rules
HOST_APPLY_UNIT_SRC=examples/host-applier-systemd/tenkai-host-apply@.service
HOST_APPLY_RULES_SRC=examples/host-applier-systemd/tenkai-host-apply.rules
ATTACHED_FILES=(tenkai-http-v1.schema.json install.sh "$HOST_APPLY_UNIT" "$HOST_APPLY_RULES")
INSTALL_SCRIPT=install.sh
# Oldest glibc a linux-x86_64 host may require (RHEL 8). Keep in step with the
# build image in scripts/build-linux-release-hosts.sh.
LINUX_GLIBC_FLOOR=2.28

usage() {
  sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'
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

# Hosts packaged for platform $1, one per line.
platform_hosts() {
  printf '%s\n' "${HOSTS[@]}"
  if [[ "$1" == linux-x86_64 ]]; then
    printf '%s\n' "${LINUX_ONLY_HOSTS[@]}"
  fi
}

packaged_name() {
  printf '%s-%s\n' "$1" "$2"
}

packaged_hub_name() {
  printf '%s-%s\n' "$HUB_SERVER_ASSET" "$1"
}

is_packaged_name() {
  local name="$1" host platform asset
  for asset in "${ATTACHED_FILES[@]}"; do
    if [[ "$name" == "$asset" ]]; then
      return 0
    fi
  done
  for platform in "${PLATFORMS[@]}"; do
    while IFS= read -r host; do
      if [[ "$name" == "$(packaged_name "$host" "$platform")" ]]; then
        return 0
      fi
    done < <(platform_hosts "$platform")
  done
  for platform in "${PLATFORMS[@]}"; do
    if [[ "$name" == "$(packaged_hub_name "$platform")" ]]; then
      return 0
    fi
  done
  return 1
}

complete_names() {
  local host platform
  printf '%s\n' "${ATTACHED_FILES[@]}"
  for platform in "${PLATFORMS[@]}"; do
    while IFS= read -r host; do
      packaged_name "$host" "$platform"
    done < <(platform_hosts "$platform")
  done
  for platform in "${PLATFORMS[@]}"; do
    packaged_hub_name "$platform"
  done
}

linux_host_names() {
  local host
  while IFS= read -r host; do
    packaged_name "$host" linux-x86_64
  done < <(platform_hosts linux-x86_64)
  packaged_hub_name linux-x86_64
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
  while IFS= read -r host; do
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
  done < <(platform_hosts "$platform")
}

cmd_package_hub() {
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
      *) fail "unknown package-hub argument: $1" ;;
    esac
  done
  [[ -n "$out" ]] || fail "package-hub requires --out"
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
  local src dest community
  src="${bin_dir}/tenkai-server"
  dest="${out}/$(packaged_hub_name "$platform")"
  community="${out}/$(packaged_name tenkai-server "$platform")"
  [[ -f "$src" ]] || fail "missing host binary: ${src}"
  [[ -s "$src" ]] || fail "empty host binary: ${src}"
  if [[ -e "$community" ]] && cmp -s "$src" "$community"; then
    fail "hub tenkai-server matches community asset; rebuild with --features postgres,ui after packaging community hosts"
  fi
  cp "$src" "$dest"
  chmod 0755 "$dest"
  if $do_strip; then
    command -v strip >/dev/null 2>&1 || fail "strip is required with --strip"
    strip "$dest"
  fi
}

# Write install.sh to --out with RELEASE_VERSION set, so the attached script
# installs the release it is attached to unless told otherwise, beside the
# host applier unit and polkit rule that install.sh --with-host-applier
# installs.
cmd_install_script() {
  local out="" version=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --out)
        [[ $# -ge 2 ]] || fail "--out requires a directory"
        out="$2"
        shift 2
        ;;
      --version)
        [[ $# -ge 2 ]] || fail "--version requires a version"
        version="$2"
        shift 2
        ;;
      -h | --help) usage 0 ;;
      *) fail "unknown install-script argument: $1" ;;
    esac
  done
  [[ -n "$out" ]] || fail "install-script requires --out"
  [[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.[1-9][0-9]*)?$ ]] \
    || fail "install-script requires --version X.Y.Z or X.Y.Z-rc.N, got '${version}'"
  local src="${ROOT}/scripts/install.sh"
  [[ "$(grep -c '^RELEASE_VERSION=""$' "$src")" == 1 ]] || fail "${src} has no single RELEASE_VERSION=\"\" line"
  mkdir -p "$out"
  sed "s/^RELEASE_VERSION=\"\"\$/RELEASE_VERSION=\"${version}\"/" "$src" >"${out}/${INSTALL_SCRIPT}"
  chmod 0755 "${out}/${INSTALL_SCRIPT}"
  cp "${ROOT}/${HOST_APPLY_UNIT_SRC}" "${out}/${HOST_APPLY_UNIT}"
  cp "${ROOT}/${HOST_APPLY_RULES_SRC}" "${out}/${HOST_APPLY_RULES}"
  chmod 0644 "${out}/${HOST_APPLY_UNIT}" "${out}/${HOST_APPLY_RULES}"
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

# Fail unless every linux-x86_64 host asset in --out is an x86-64 ELF
# executable linked to glibc whose versioned glibc symbols are all at or below
# LINUX_GLIBC_FLOOR, so it starts on every supported distribution (#904).
cmd_check_glibc() {
  local out=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --out)
        [[ $# -ge 2 ]] || fail "--out requires a directory"
        out="$2"
        shift 2
        ;;
      -h | --help) usage 0 ;;
      *) fail "unknown check-glibc argument: $1" ;;
    esac
  done
  [[ -n "$out" ]] || fail "check-glibc requires --out"
  command -v readelf >/dev/null 2>&1 || fail "readelf is required by check-glibc"

  local name path header newest
  while IFS= read -r name; do
    path="${out}/${name}"
    [[ -f "$path" ]] || fail "missing Linux host asset: ${name}"
    header="$(readelf -hW "$path" 2>/dev/null)" || fail "${name} is not an ELF executable"
    grep -Eq 'Type:[[:space:]]+(EXEC|DYN)' <<<"$header" || fail "${name} is not an ELF executable"
    grep -Eq 'Machine:.*X86-64' <<<"$header" || fail "${name} is not an x86-64 executable"
    newest="$(readelf -VW "$path" | { grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' || true; } | sed 's/^GLIBC_//' | sort -V | tail -n 1)"
    # Hosts dlopen system PKCS#11 modules, so they must link glibc.
    [[ -n "$newest" ]] || fail "${name} does not link glibc"
    if [[ "$(printf '%s\n%s\n' "$LINUX_GLIBC_FLOOR" "$newest" | sort -V | tail -n 1)" != "$LINUX_GLIBC_FLOOR" ]]; then
      fail "${name} requires glibc ${newest}, newer than the ${LINUX_GLIBC_FLOOR} floor"
    fi
  done < <(linux_host_names)
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

  for host in "${HOSTS[@]}" "${LINUX_ONLY_HOSTS[@]}"; do
    printf 'stub-%s\n' "$host" >"${bin}/${host}"
    chmod 0755 "${bin}/${host}"
  done
  printf 'fixture\n' >"${bin}/tenkai-worker-lifecycle-fixture"
  chmod 0755 "${bin}/tenkai-worker-lifecycle-fixture"
  printf 'conformance\n' >"${bin}/tenkai-delivery-conformance"
  chmod 0755 "${bin}/tenkai-delivery-conformance"

  bash "$0" package --out "$out" --bin-dir "$bin" --platform "$platform"
  [[ -f "${out}/$(packaged_name tenkaictl "$platform")" ]] || fail "self-test missing tenkaictl asset"
  [[ -f "${out}/$(packaged_name tenkai-server "$platform")" ]] || fail "self-test missing community tenkai-server asset"
  [[ ! -e "${out}/tenkai-worker-lifecycle-fixture-${platform}" ]] || fail "self-test packaged fixture host"
  [[ ! -e "${out}/tenkai-delivery-conformance-${platform}" ]] || fail "self-test packaged conformance harness"
  if [[ "$platform" == linux-x86_64 ]]; then
    [[ -f "${out}/$(packaged_name tenkai-host-applier "$platform")" ]] || fail "self-test missing tenkai-host-applier asset"
  else
    [[ ! -e "${out}/$(packaged_name tenkai-host-applier "$platform")" ]] || fail "self-test packaged tenkai-host-applier for ${platform}"
  fi
  complete_names | grep -Fxq tenkai-host-applier-linux-x86_64 || fail "self-test release set lacks the Linux applier"
  if complete_names | grep -Fxq tenkai-host-applier-darwin-aarch64; then
    fail "self-test release set requires a darwin applier"
  fi

  expect_fail "hub tenkai-server matches community asset" \
    bash "$0" package-hub --out "$out" --bin-dir "$bin" --platform "$platform"
  printf 'hub-postgres-ui\n' >"${bin}/tenkai-server"
  chmod 0755 "${bin}/tenkai-server"
  bash "$0" package-hub --out "$out" --bin-dir "$bin" --platform "$platform"
  [[ -f "${out}/$(packaged_hub_name "$platform")" ]] || fail "self-test missing hub tenkai-server-postgres asset"
  [[ "$(cat "${out}/$(packaged_name tenkai-server "$platform")")" == stub-tenkai-server ]] \
    || fail "self-test replaced community tenkai-server asset"
  [[ "$(cat "${out}/$(packaged_hub_name "$platform")")" == hub-postgres-ui ]] \
    || fail "self-test hub asset did not keep postgres,ui binary"

  bash "$0" checksums --out "$out"
  [[ -f "${out}/${CHECKSUMS_NAME}" ]] || fail "self-test missing checksums"
  verify_checksums "$out" >/dev/null

  expect_fail "platform ${other} does not match host ${platform}" \
    bash "$0" package --out "$out" --bin-dir "$bin" --platform "$other"
  mkdir -p "${tmp}/empty"
  expect_fail "missing host binary" \
    bash "$0" package --out "${tmp}/missing" --bin-dir "${tmp}/empty" --platform "$platform"

  expect_fail "incomplete GitHub Release set" \
    bash "$0" checksums --out "$out" --require-complete

  printf '{}\n' >"${out}/${ATTACHED_FILES[0]}"
  bash "$0" install-script --out "$out" --version 1.2.3
  cmp -s "${ROOT}/${HOST_APPLY_UNIT_SRC}" "${out}/${HOST_APPLY_UNIT}" || fail "self-test unit differs from its source"
  bash "$0" checksums --out "$out"
  local attached
  for attached in "${ATTACHED_FILES[@]}"; do
    grep -Fq "  ${attached}" "${out}/${CHECKSUMS_NAME}" || fail "self-test ${attached} not checksummed"
  done

  printf 'junk\n' >"${out}/not-a-host"
  expect_fail "unexpected file in ${out}: not-a-host" \
    bash "$0" checksums --out "$out"
  rm -f "${out}/not-a-host"

  printf 'tampered\n' >>"${out}/$(packaged_name tenkaictl "$platform")"
  expect_fail "FAILED" verify_checksums "$out"

  # check-glibc: the passing case is the CI release dry run, which builds the
  # real hosts. Here, refuse a missing asset, a non-ELF stub, and (on Linux)
  # this machine's shell when its glibc is newer than the floor.
  if command -v readelf >/dev/null 2>&1; then
    local linux="${tmp}/linux" name shell_glibc
    mkdir -p "$linux"
    expect_fail "missing Linux host asset" bash "$0" check-glibc --out "$linux"
    while IFS= read -r name; do
      printf 'stub\n' >"${linux}/${name}"
    done < <(linux_host_names)
    expect_fail "is not an ELF executable" bash "$0" check-glibc --out "$linux"
    shell_glibc="$(readelf -VW /bin/sh 2>/dev/null | grep -oE 'GLIBC_2\.(29|[3-9][0-9])' | head -n 1 || true)"
    if [[ "$platform" == linux-x86_64 && -n "$shell_glibc" ]]; then
      while IFS= read -r name; do
        cp /bin/sh "${linux}/${name}"
      done < <(linux_host_names)
      expect_fail "newer than the ${LINUX_GLIBC_FLOOR} floor" bash "$0" check-glibc --out "$linux"
    fi
  fi

  printf 'package-release-binaries self-test passed\n'
}

main() {
  local cmd="${1:-}"
  if [[ $# -gt 0 ]]; then
    shift
  fi
  case "$cmd" in
    package) cmd_package "$@" ;;
    package-hub) cmd_package_hub "$@" ;;
    checksums) cmd_checksums "$@" ;;
    check-glibc) cmd_check_glibc "$@" ;;
    install-script) cmd_install_script "$@" ;;
    names) complete_names ;;
    self-test) cmd_self_test "$@" ;;
    -h | --help | "") usage 0 ;;
    *) usage 1 ;;
  esac
}

main "$@"
