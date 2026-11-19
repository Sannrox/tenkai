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
#   scripts/package-release-binaries.sh check-glibc --out DIR [--platform ID]
#   scripts/package-release-binaries.sh compare --out DIR --against DIR
#   scripts/package-release-binaries.sh system-packages --out DIR --platform ID
#       --version X.Y.Z
#   scripts/package-release-binaries.sh names
#   scripts/package-release-binaries.sh self-test
#
# Community hosts: tenkaictl, tenkai-server, tenkai-executor-guard,
# tenkai-runtime, tenkai-runtime-guard, and on Linux only
# tenkai-host-applier. Hub host asset:
# tenkai-server-postgres-<platform> (built with --features postgres,ui).
# Platforms: linux-x86_64, linux-aarch64, darwin-aarch64. check-glibc refuses
# a Linux host that needs a glibc newer than LINUX_GLIBC_FLOOR (built by
# scripts/build-linux-release-hosts.sh). system-packages builds the tenkai
# .deb and .rpm of one Linux platform (tenkai-<platform>.deb and .rpm: the
# CLI, the server and its guard, and a server unit that is not enabled) from
# that platform's packaged hosts in --out, with the pinned nfpm.
# The HTTP API contract (api/tenkai-http-v1.schema.json), install.sh
# (scripts/install.sh with the release version baked in by install-script),
# and the host applier's systemd unit and polkit rule (copied by
# install-script from examples/host-applier-systemd) are attached and
# checksummed with them. These files are GitHub Release packaging, not
# Catalog artifacts. compare fails unless two independent builds packaged the
# same assets with byte-identical contents (reproducible builds, #1331).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOSTS=(tenkaictl tenkai-server tenkai-executor-guard tenkai-runtime tenkai-runtime-guard)
# Hosts published for Linux only: the applier needs systemd (#949).
LINUX_ONLY_HOSTS=(tenkai-host-applier)
HUB_SERVER_ASSET=tenkai-server-postgres
PLATFORMS=(linux-x86_64 linux-aarch64 darwin-aarch64)
LINUX_PLATFORMS=(linux-x86_64 linux-aarch64)
# The hosts in the tenkai .deb and .rpm, installed under /usr/bin.
SYSTEM_PACKAGE_HOSTS=(tenkaictl tenkai-server tenkai-executor-guard)
SYSTEM_PACKAGE_FORMATS=(deb rpm)
# nfpm builds both formats from packaging/nfpm.yaml. Pinned by release
# archive SHA-256 and cached like scripts/check-workflows.sh's tools.
NFPM_VERSION=2.48.0
NFPM_SHA256_X86_64=6d7f9a28b2f397934403950fcbba83f598b08d02edbe79a0815b3b4897341750
NFPM_SHA256_ARM64=a9a75213763783b7669719e505474c748c5ad7dc66591a195619deb50f85c2f4
CHECKSUMS_NAME=SHA256SUMS
# Release asset names of the host applier unit and polkit rule. GitHub may
# rename an asset with "@", so the unit's asset name drops it.
HOST_APPLY_UNIT=tenkai-host-apply.service
HOST_APPLY_RULES=tenkai-host-apply.rules
HOST_APPLY_UNIT_SRC=examples/host-applier-systemd/tenkai-host-apply@.service
HOST_APPLY_RULES_SRC=examples/host-applier-systemd/tenkai-host-apply.rules
ATTACHED_FILES=(tenkai-http-v1.schema.json install.sh "$HOST_APPLY_UNIT" "$HOST_APPLY_RULES")
INSTALL_SCRIPT=install.sh
# Oldest glibc a Linux host may require (RHEL 8). Keep in step with the
# build image in scripts/build-linux-release-hosts.sh and the package
# dependency in packaging/nfpm.yaml.
LINUX_GLIBC_FLOOR=2.28

usage() {
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
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
    Linux:aarch64 | Linux:arm64) printf '%s\n' linux-aarch64 ;;
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

# Set PLATFORM_HOSTS to the hosts packaged for platform $1.
set_platform_hosts() {
  PLATFORM_HOSTS=("${HOSTS[@]}")
  if [[ "$1" == linux-* ]]; then
    PLATFORM_HOSTS+=("${LINUX_ONLY_HOSTS[@]}")
  fi
}

packaged_name() {
  printf '%s-%s\n' "$1" "$2"
}

packaged_hub_name() {
  printf '%s-%s\n' "$HUB_SERVER_ASSET" "$1"
}

# tenkai-<platform>.<format>: version-free, like every other asset name.
system_package_name() {
  printf 'tenkai-%s.%s\n' "$1" "$2"
}

system_package_names() {
  local platform format
  for platform in "${LINUX_PLATFORMS[@]}"; do
    for format in "${SYSTEM_PACKAGE_FORMATS[@]}"; do
      system_package_name "$platform" "$format"
    done
  done
}

is_packaged_name() {
  local name="$1" host platform asset
  for asset in "${ATTACHED_FILES[@]}"; do
    if [[ "$name" == "$asset" ]]; then
      return 0
    fi
  done
  for platform in "${PLATFORMS[@]}"; do
    set_platform_hosts "$platform"
    for host in "${PLATFORM_HOSTS[@]}"; do
      if [[ "$name" == "$(packaged_name "$host" "$platform")" ]]; then
        return 0
      fi
    done
  done
  for platform in "${PLATFORMS[@]}"; do
    if [[ "$name" == "$(packaged_hub_name "$platform")" ]]; then
      return 0
    fi
  done
  grep -Fxq -- "$name" < <(system_package_names)
}

complete_names() {
  local host platform
  printf '%s\n' "${ATTACHED_FILES[@]}"
  for platform in "${PLATFORMS[@]}"; do
    set_platform_hosts "$platform"
    for host in "${PLATFORM_HOSTS[@]}"; do
      packaged_name "$host" "$platform"
    done
  done
  for platform in "${PLATFORMS[@]}"; do
    packaged_hub_name "$platform"
  done
  system_package_names
}

# The packaged host assets of Linux platform $1.
linux_host_names() {
  local host
  set_platform_hosts "$1"
  for host in "${PLATFORM_HOSTS[@]}"; do
    packaged_name "$host" "$1"
  done
  packaged_hub_name "$1"
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
  set_platform_hosts "$platform"
  for host in "${PLATFORM_HOSTS[@]}"; do
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
  cp "$src" "$dest"
  chmod 0755 "$dest"
  if $do_strip; then
    command -v strip >/dev/null 2>&1 || fail "strip is required with --strip"
    strip "$dest"
  fi
  # Compare the finished assets: the community asset may already be stripped,
  # so comparing it with the unstripped source would never match.
  if [[ -e "$community" ]] && cmp -s "$dest" "$community"; then
    rm -f "$dest"
    fail "hub tenkai-server matches community asset; rebuild with --features postgres,ui after packaging community hosts"
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

# Fail unless --out and --against hold the same packaged assets with the same
# SHA-256, naming each asset that is missing on one side or differs. CI runs
# it over two independent builds of one commit (#1331).
cmd_compare() {
  local out="" against=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --out)
        [[ $# -ge 2 ]] || fail "--out requires a directory"
        out="$2"
        shift 2
        ;;
      --against)
        [[ $# -ge 2 ]] || fail "--against requires a directory"
        against="$2"
        shift 2
        ;;
      -h | --help) usage 0 ;;
      *) fail "unknown compare argument: $1" ;;
    esac
  done
  [[ -n "$out" && -n "$against" ]] || fail "compare requires --out and --against"
  [[ -d "$out" ]] || fail "output directory does not exist: ${out}"
  [[ -d "$against" ]] || fail "comparison directory does not exist: ${against}"

  local names other name ours theirs differs=0
  names="$(list_packaged_files "$out")"
  other="$(list_packaged_files "$against")"
  [[ -n "$names" ]] || fail "no packaged host binaries in ${out}"
  if [[ "$names" != "$other" ]]; then
    diff <(printf '%s\n' "$names") <(printf '%s\n' "$other") >&2 || true
    fail "${out} and ${against} package different assets"
  fi
  while IFS= read -r name; do
    ours="$(checksum_file "${out}/${name}" | awk '{print $1}')"
    theirs="$(checksum_file "${against}/${name}" | awk '{print $1}')"
    if [[ "$ours" == "$theirs" ]]; then
      printf '%s  %s\n' "$ours" "$name"
    else
      printf 'differs: %s (%s vs %s)\n' "$name" "$ours" "$theirs" >&2
      differs=1
    fi
  done <<<"$names"
  [[ "$differs" -eq 0 ]] || fail "builds are not reproducible: assets differ"
}

# Fail unless every Linux host asset in --out (of --platform, else of every
# Linux platform) is an ELF executable for its CPU, linked to glibc, whose
# versioned glibc symbols are all at or below LINUX_GLIBC_FLOOR, so it starts
# on every supported distribution (#904).
cmd_check_glibc() {
  local out="" only=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --out)
        [[ $# -ge 2 ]] || fail "--out requires a directory"
        out="$2"
        shift 2
        ;;
      --platform)
        [[ $# -ge 2 ]] || fail "--platform requires an id"
        only="$2"
        shift 2
        ;;
      -h | --help) usage 0 ;;
      *) fail "unknown check-glibc argument: $1" ;;
    esac
  done
  [[ -n "$out" ]] || fail "check-glibc requires --out"
  command -v readelf >/dev/null 2>&1 || fail "readelf is required by check-glibc"
  local -a platforms=("${LINUX_PLATFORMS[@]}")
  if [[ -n "$only" ]]; then
    if [[ "$only" != linux-* ]] || ! is_platform "$only"; then
      fail "not a Linux platform: ${only}"
    fi
    platforms=("$only")
  fi

  local platform machine name path header newest
  for platform in "${platforms[@]}"; do
    case "$platform" in
      linux-x86_64) machine=X86-64 ;;
      linux-aarch64) machine=AArch64 ;;
    esac
    while IFS= read -r name; do
      path="${out}/${name}"
      [[ -f "$path" ]] || fail "missing Linux host asset: ${name}"
      header="$(readelf -hW "$path" 2>/dev/null)" || fail "${name} is not an ELF executable"
      grep -Eq 'Type:[[:space:]]+(EXEC|DYN)' <<<"$header" || fail "${name} is not an ELF executable"
      grep -Eq "Machine:.*${machine}" <<<"$header" || fail "${name} is not an ${machine} executable"
      newest="$(readelf -VW "$path" | { grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' || true; } | sed 's/^GLIBC_//' | sort -V | tail -n 1)"
      # Hosts dlopen system PKCS#11 modules, so they must link glibc.
      [[ -n "$newest" ]] || fail "${name} does not link glibc"
      if [[ "$(printf '%s\n%s\n' "$LINUX_GLIBC_FLOOR" "$newest" | sort -V | tail -n 1)" != "$LINUX_GLIBC_FLOOR" ]]; then
        fail "${name} requires glibc ${newest}, newer than the ${LINUX_GLIBC_FLOOR} floor"
      fi
    done < <(linux_host_names "$platform")
  done
}

# The pinned nfpm, downloaded once per version and checked against its
# release archive SHA-256.
nfpm_bin() {
  local asset sha cache archive
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) asset=Linux_x86_64 sha="$NFPM_SHA256_X86_64" ;;
    Linux-aarch64 | Linux-arm64) asset=Linux_arm64 sha="$NFPM_SHA256_ARM64" ;;
    *) fail "system-packages runs on Linux x86_64 or aarch64" ;;
  esac
  cache="${XDG_CACHE_HOME:-$HOME/.cache}/tenkai-nfpm/${NFPM_VERSION}"
  if [[ ! -x "${cache}/nfpm" ]]; then
    mkdir -p "$cache"
    archive="$(mktemp "${cache}/nfpm.$$.XXXXXX")"
    curl -fsSL -o "$archive" \
      "https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/nfpm_${NFPM_VERSION}_${asset}.tar.gz" \
      || { rm -f "$archive"; fail "cannot download nfpm ${NFPM_VERSION}"; }
    if [[ "$(checksum_file "$archive" | awk '{print $1}')" != "$sha" ]]; then
      rm -f "$archive"
      fail "nfpm ${NFPM_VERSION} archive does not match its pinned SHA-256"
    fi
    tar -xzf "$archive" -C "$cache" nfpm
    rm -f "$archive"
  fi
  printf '%s\n' "${cache}/nfpm"
}

# Build tenkai-<platform>.deb and .rpm into --out from the platform's packaged
# hosts already there. A pre-release X.Y.Z-rc.N becomes X.Y.Z~rc.N, which both
# formats sort before X.Y.Z.
cmd_system_packages() {
  local out="" platform="" version=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --out)
        [[ $# -ge 2 ]] || fail "--out requires a directory"
        out="$2"
        shift 2
        ;;
      --platform)
        [[ $# -ge 2 ]] || fail "--platform requires an id"
        platform="$2"
        shift 2
        ;;
      --version)
        [[ $# -ge 2 ]] || fail "--version requires a version"
        version="$2"
        shift 2
        ;;
      -h | --help) usage 0 ;;
      *) fail "unknown system-packages argument: $1" ;;
    esac
  done
  [[ -n "$out" ]] || fail "system-packages requires --out"
  if [[ "$platform" != linux-* ]] || ! is_platform "$platform"; then
    fail "system-packages requires a Linux --platform, got '${platform}'"
  fi
  [[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.[1-9][0-9]*)?$ ]] \
    || fail "system-packages requires --version X.Y.Z or X.Y.Z-rc.N, got '${version}'"
  local host
  for host in "${SYSTEM_PACKAGE_HOSTS[@]}"; do
    [[ -s "${out}/$(packaged_name "$host" "$platform")" ]] || fail "missing host asset: $(packaged_name "$host" "$platform")"
  done
  local nfpm arch format stage
  nfpm="$(nfpm_bin)"
  case "$platform" in
    linux-x86_64) arch=amd64 ;;
    linux-aarch64) arch=arm64 ;;
  esac
  out="$(cd "$out" && pwd)"
  # nfpm reads fixed source paths, so stage the hosts under their installed
  # names beside the packaging files.
  stage="$(mktemp -d "${TMPDIR:-/tmp}/tenkai-system-packages.$$.XXXXXX")"
  mkdir -p "${stage}/bin"
  for host in "${SYSTEM_PACKAGE_HOSTS[@]}"; do
    cp "${out}/$(packaged_name "$host" "$platform")" "${stage}/bin/${host}"
  done
  cp -R "${ROOT}/packaging" "${stage}/packaging"
  cp "${ROOT}/LICENSE" "${stage}/LICENSE"
  for format in "${SYSTEM_PACKAGE_FORMATS[@]}"; do
    if ! (cd "$stage" && TENKAI_ARCH="$arch" TENKAI_VERSION="${version/-/\~}" \
      TENKAI_GLIBC_FLOOR="$LINUX_GLIBC_FLOOR" \
      "$nfpm" package --config packaging/nfpm.yaml --packager "$format" \
      --target "${out}/$(system_package_name "$platform" "$format")" >/dev/null); then
      rm -rf "$stage"
      fail "nfpm could not build the ${format} for ${platform}"
    fi
  done
  rm -rf "$stage"
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
  if [[ "$platform" == linux-* ]]; then
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
  if [[ "$platform" == linux-* ]]; then
    [[ -f "${out}/$(packaged_name tenkai-host-applier "$platform")" ]] || fail "self-test missing tenkai-host-applier asset"
  else
    [[ ! -e "${out}/$(packaged_name tenkai-host-applier "$platform")" ]] || fail "self-test packaged tenkai-host-applier for ${platform}"
  fi
  local names
  names="$(complete_names)"
  local required
  for required in tenkai-host-applier-linux-x86_64 tenkai-host-applier-linux-aarch64 \
    tenkaictl-linux-aarch64 tenkai-linux-x86_64.deb tenkai-linux-x86_64.rpm \
    tenkai-linux-aarch64.deb tenkai-linux-aarch64.rpm; do
    grep -Fxq "$required" <<<"$names" || fail "self-test release set lacks ${required}"
  done
  if grep -Fxq tenkai-darwin-aarch64.deb <<<"$names"; then
    fail "self-test release set requires a darwin system package"
  fi
  expect_fail "system-packages requires a Linux --platform" \
    bash "$0" system-packages --out "$out" --platform darwin-aarch64 --version 1.2.3
  expect_fail "system-packages requires --version X.Y.Z" \
    bash "$0" system-packages --out "$out" --platform linux-x86_64 --version 1.2
  expect_fail "missing host asset: tenkaictl-linux-aarch64" \
    bash "$0" system-packages --out "${tmp}/empty-dist" --platform linux-aarch64 --version 1.2.3
  if grep -Fxq tenkai-host-applier-darwin-aarch64 <<<"$names"; then
    fail "self-test release set requires a darwin applier"
  fi

  expect_fail "hub tenkai-server matches community asset" \
    bash "$0" package-hub --out "$out" --bin-dir "$bin" --platform "$platform"
  [[ ! -e "${out}/$(packaged_hub_name "$platform")" ]] || fail "self-test kept a refused hub asset"
  # The release strips both assets; the guard must still see the duplicate.
  # Needs an unstripped binary, so it runs where a C compiler is present.
  if command -v strip >/dev/null 2>&1 && command -v cc >/dev/null 2>&1; then
    local stripped="${tmp}/stripped" stripped_bin="${tmp}/stripped-bin"
    mkdir -p "$stripped_bin"
    printf 'int main(void) { return 0; }\n' >"${tmp}/host.c"
    cc -g -o "${tmp}/host" "${tmp}/host.c"
    for host in "${HOSTS[@]}" "${LINUX_ONLY_HOSTS[@]}"; do
      cp "${tmp}/host" "${stripped_bin}/${host}"
    done
    bash "$0" package --out "$stripped" --bin-dir "$stripped_bin" --platform "$platform" --strip
    expect_fail "hub tenkai-server matches community asset" \
      bash "$0" package-hub --out "$stripped" --bin-dir "$stripped_bin" --platform "$platform" --strip
  fi
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
  # this machine's shell under the other CPU's names, and under its own
  # names when its glibc is newer than the floor.
  if command -v readelf >/dev/null 2>&1; then
    local linux="${tmp}/linux" name shell_glibc own foreign machine
    mkdir -p "$linux"
    expect_fail "missing Linux host asset" bash "$0" check-glibc --out "$linux"
    expect_fail "not a Linux platform: darwin-aarch64" \
      bash "$0" check-glibc --out "$linux" --platform darwin-aarch64
    while IFS= read -r name; do
      printf 'stub\n' >"${linux}/${name}"
    done < <(linux_host_names linux-x86_64)
    expect_fail "is not an ELF executable" bash "$0" check-glibc --out "$linux" --platform linux-x86_64
    if [[ "$platform" == linux-* ]]; then
      own="$platform"
      if [[ "$own" == linux-x86_64 ]]; then
        foreign=linux-aarch64 machine=AArch64
      else
        foreign=linux-x86_64 machine=X86-64
      fi
      while IFS= read -r name; do
        cp /bin/sh "${linux}/${name}"
      done < <(linux_host_names "$foreign")
      expect_fail "is not an ${machine} executable" bash "$0" check-glibc --out "$linux" --platform "$foreign"
      shell_glibc="$(readelf -VW /bin/sh 2>/dev/null | grep -oE 'GLIBC_2\.(29|[3-9][0-9])' | head -n 1 || true)"
      if [[ -n "$shell_glibc" ]]; then
        while IFS= read -r name; do
          cp /bin/sh "${linux}/${name}"
        done < <(linux_host_names "$own")
        expect_fail "newer than the ${LINUX_GLIBC_FLOOR} floor" bash "$0" check-glibc --out "$linux" --platform "$own"
      fi
    fi
  fi

  # compare: identical builds pass; one changed byte or a missing asset fails.
  local first="${tmp}/compare-a" second="${tmp}/compare-b" name
  mkdir -p "$first" "$second"
  bash "$0" package --out "$first" --bin-dir "$bin" --platform "$platform" >/dev/null
  bash "$0" package --out "$second" --bin-dir "$bin" --platform "$platform" >/dev/null
  bash "$0" compare --out "$first" --against "$second" >/dev/null
  name="$(packaged_name tenkaictl "$platform")"
  printf 'x' >>"${second}/${name}"
  expect_fail "differs: ${name}" bash "$0" compare --out "$first" --against "$second"
  rm "${second}/${name}"
  expect_fail "package different assets" bash "$0" compare --out "$first" --against "$second"

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
    compare) cmd_compare "$@" ;;
    install-script) cmd_install_script "$@" ;;
    system-packages) cmd_system_packages "$@" ;;
    names) complete_names ;;
    self-test) cmd_self_test "$@" ;;
    -h | --help | "") usage 0 ;;
    *) usage 1 ;;
  esac
}

main "$@"
