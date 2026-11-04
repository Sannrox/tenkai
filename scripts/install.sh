#!/bin/sh
# Install Tenkai hosts from a GitHub Release, verified against its SHA256SUMS.
# Attached to each release as install.sh with that release's version baked in
# by scripts/package-release-binaries.sh install-script. POSIX sh. Usage and
# options: see usage() below or run with --help.
#
# Every file is checked against the release's SHA256SUMS before anything is
# installed; a mismatch or a missing entry installs nothing. Each binary is
# renamed into place, so a reader sees the old file or the new one. A
# tenkaictl self-upgrade home is refused: self-upgrade owns those hosts.
set -eu

# Written by scripts/package-release-binaries.sh install-script when the
# script is attached to a release. Empty in the source tree.
RELEASE_VERSION=""
REPO=Sannrox/tenkai
GLIBC_FLOOR=2.28

die() {
  printf 'tenkai install: %s\n' "$1" >&2
  exit 1
}

say() {
  printf '%s\n' "$1"
}

usage() {
  cat <<EOF
Install Tenkai hosts from a GitHub Release, verified against its SHA256SUMS.

  curl -fsSL https://github.com/${REPO}/releases/download/vX.Y.Z/install.sh | sh -s -- --role server

Options:
  --role cli|server|runtime  cli: tenkaictl (default)
                             server: tenkaictl, tenkai-server, tenkai-executor-guard
                             runtime: tenkai-runtime, tenkai-runtime-guard
  --version X.Y.Z            release to install (default: ${RELEASE_VERSION:-none, required})
  --prefix DIR               install directory (default: /usr/local/bin as
                             root, ~/.local/bin otherwise)
  --base-url URL             release download root
                             (default: https://github.com/${REPO}/releases/download)

Supported: linux-x86_64 with glibc ${GLIBC_FLOOR} or newer, darwin-aarch64.
EOF
  exit "${1:-0}"
}

role=cli
version="$RELEASE_VERSION"
prefix=""
base_url="https://github.com/${REPO}/releases/download"
while [ $# -gt 0 ]; do
  case "$1" in
    --role | --version | --prefix | --base-url)
      [ $# -ge 2 ] || die "$1 needs a value"
      case "$1" in
        --role) role="$2" ;;
        --version) version="$2" ;;
        --prefix) prefix="$2" ;;
        --base-url) base_url="$2" ;;
      esac
      shift 2
      ;;
    -h | --help) usage 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

case "$role" in
  cli) binaries="tenkaictl" ;;
  # The guard is installed first, so a server never starts without it.
  server) binaries="tenkai-executor-guard tenkai-server tenkaictl" ;;
  runtime) binaries="tenkai-runtime-guard tenkai-runtime" ;;
  *) die "unknown role ${role}; use cli, server or runtime" ;;
esac

[ -n "$version" ] || die "no release version; pass --version X.Y.Z"
version="${version#v}"
printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.[1-9][0-9]*)?$' \
  || die "invalid version ${version}; expected X.Y.Z or X.Y.Z-rc.N"
tag="v${version}"

# Linux hosts link glibc (they load the system's PKCS#11 module), so a
# musl or older glibc system cannot run them.
check_glibc() {
  libc="$(getconf GNU_LIBC_VERSION 2>/dev/null || true)"
  if [ -z "$libc" ]; then
    if ls /lib/ld-musl-* >/dev/null 2>&1 || ldd --version 2>&1 | grep -qi musl; then
      die "musl libc is not supported; Tenkai Linux hosts need glibc ${GLIBC_FLOOR} or newer"
    fi
    die "cannot determine the glibc version; Tenkai Linux hosts need glibc ${GLIBC_FLOOR} or newer"
  fi
  found="${libc#glibc }"
  if ! printf '%s %s\n' "$found" "$GLIBC_FLOOR" | awk '{
    split($1, a, "."); split($2, b, ".")
    exit !((a[1] + 0 > b[1] + 0) || (a[1] + 0 == b[1] + 0 && a[2] + 0 >= b[2] + 0))
  }'; then
    die "glibc ${found} is too old; Tenkai Linux hosts need glibc ${GLIBC_FLOOR} or newer"
  fi
}

os="$(uname -s)"
arch="$(uname -m)"
# A shell under Rosetta reports x86_64 on Apple silicon.
if [ "$os" = Darwin ] && [ "$arch" = x86_64 ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then
  arch=arm64
fi
case "${os}:${arch}" in
  Linux:x86_64 | Linux:amd64)
    platform=linux-x86_64
    check_glibc
    ;;
  Darwin:arm64 | Darwin:aarch64) platform=darwin-aarch64 ;;
  *) die "no Tenkai hosts are published for ${os} ${arch}; supported: linux-x86_64, darwin-aarch64. Build from source instead." ;;
esac

if [ -z "$prefix" ]; then
  if [ "$(id -u)" = 0 ]; then
    prefix=/usr/local/bin
  else
    [ -n "${HOME:-}" ] || die "HOME is unset; pass --prefix"
    prefix="${HOME}/.local/bin"
  fi
fi

# A self-upgrade home (versions/, current -> versions/<digest>, upgrade.json)
# and links into one are owned by tenkaictl self-upgrade, whose store check,
# backup and rollback a plain replace would skip.
is_home() {
  [ -e "$1/upgrade.json" ] || { [ -d "$1/versions" ] && [ -L "$1/current" ]; }
}
for dir in "$prefix" "$prefix/.." "$prefix/../.."; do
  if [ -d "$dir" ] && is_home "$dir"; then
    die "${prefix} is in a tenkaictl self-upgrade home; upgrade it with tenkaictl self-upgrade (docs/release-binaries.md#upgrade-a-server-host)"
  fi
done
for binary in $binaries; do
  if [ -L "${prefix}/${binary}" ]; then
    die "${prefix}/${binary} is a symbolic link (to $(readlink "${prefix}/${binary}")); upgrade the host it points to with tenkaictl self-upgrade, or remove the link"
  fi
done

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --proto-redir =https -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  die "curl or wget is required"
fi
if command -v sha256sum >/dev/null 2>&1; then
  digest() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  digest() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  die "sha256sum or shasum is required"
fi

mkdir -p "$prefix" 2>/dev/null || die "cannot create ${prefix}; run as root or pass --prefix"
# Staged inside the prefix, so the final rename stays on one file system.
stage="$(mktemp -d "${prefix}/.tenkai-install.XXXXXX" 2>/dev/null)" \
  || die "cannot write to ${prefix}; run as root or pass --prefix"
trap 'rm -rf "$stage"' EXIT
trap 'exit 1' HUP INT TERM

url="${base_url%/}/${tag}"
say "Installing Tenkai ${tag} (${role}, ${platform}) into ${prefix}"
fetch "${url}/SHA256SUMS" "${stage}/SHA256SUMS" || die "cannot download ${url}/SHA256SUMS"

# Verify every file before installing any of them.
for binary in $binaries; do
  asset="${binary}-${platform}"
  fetch "${url}/${asset}" "${stage}/${asset}" || die "cannot download ${url}/${asset}"
  expected="$(awk -v name="$asset" '$2 == name || $2 == "*" name {print $1}' "${stage}/SHA256SUMS")"
  [ -n "$expected" ] || die "SHA256SUMS has no entry for ${asset}; refusing to install"
  [ "$(printf '%s\n' "$expected" | wc -l | tr -d ' ')" = 1 ] || die "SHA256SUMS lists ${asset} more than once; refusing to install"
  actual="$(digest "${stage}/${asset}")"
  [ "$actual" = "$expected" ] || die "checksum mismatch for ${asset}: expected ${expected}, got ${actual}; refusing to install"
done

for binary in $binaries; do
  asset="${binary}-${platform}"
  if [ "$binary" = tenkai-server ] && [ -e "${prefix}/tenkai-server" ]; then
    say "Replacing ${prefix}/tenkai-server: restart the service to run it. For upgrades with a store check, backup and rollback, use tenkaictl self-upgrade."
  fi
  chmod 0755 "${stage}/${asset}"
  mv -f "${stage}/${asset}" "${prefix}/${binary}"
  say "  ${prefix}/${binary}"
done

say ""
say "Checksums matched SHA256SUMS. To verify build provenance with the GitHub CLI:"
for binary in $binaries; do
  say "  gh attestation verify ${prefix}/${binary} --repo ${REPO} --signer-workflow ${REPO}/.github/workflows/release-binaries.yml --source-ref refs/tags/${tag}"
done
# A relative prefix (the quickstart's --prefix .) is used by path, not PATH.
case "$prefix" in
  /*) case ":${PATH:-}:" in
    *":${prefix}:"*) ;;
    *) say "" && say "${prefix} is not on PATH; add it to run the binaries by name." ;;
  esac ;;
esac
