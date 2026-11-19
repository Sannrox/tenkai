#!/usr/bin/env bash
# Build and package the Linux release hosts of one platform inside a RHEL 8
# image (glibc 2.28), so they start on every supported distribution (#904). A
# host built on a newer system links newer glibc symbols and fails to load
# there. The release workflow and the CI release dry run both call this.
#
# Usage: scripts/build-linux-release-hosts.sh --out DIR
#            [--platform linux-x86_64|linux-aarch64]
#
# Needs docker. The platform defaults to linux-x86_64; on a machine of the
# other CPU docker must emulate it, so the release builds each on its own
# runner. Build state (toolchain, registry, target) lives in
# ${CARGO_TARGET_DIR:-target}/linux-release-hosts[-aarch64], apart from
# native builds. Writes the platform's seven packaged hosts to DIR and checks
# them with scripts/package-release-binaries.sh check-glibc.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# UBI 8.10, a multi-architecture index. Its glibc is LINUX_GLIBC_FLOOR in
# package-release-binaries.sh.
IMAGE=registry.access.redhat.com/ubi8/ubi@sha256:c322aa68f2d630b36b9faab64094357f62720be2f56f7099376ca2d6c4fe389b
RUSTUP_VERSION=1.29.3
RUSTUP_SHA256_X86_64=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55
RUSTUP_SHA256_AARCH64=9f608c142e0e38a78957d0661ba1dfaf0b6fb37184cfaa4b9a0aa57af6184282

fail() {
  printf 'build-linux-release-hosts: %s\n' "$1" >&2
  exit 1
}

out=""
platform=linux-x86_64
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      [[ $# -ge 2 ]] || fail "--out requires a directory"
      out="$2"
      shift 2
      ;;
    --platform)
      [[ $# -ge 2 ]] || fail "--platform requires linux-x86_64 or linux-aarch64"
      platform="$2"
      shift 2
      ;;
    -h | --help)
      awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
      exit 0
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done
[[ -n "$out" ]] || fail "--out is required"
case "$platform" in
  linux-x86_64)
    docker_platform=linux/amd64 triple=x86_64-unknown-linux-gnu
    rustup_sha256="$RUSTUP_SHA256_X86_64" state_name=linux-release-hosts
    ;;
  linux-aarch64)
    docker_platform=linux/arm64 triple=aarch64-unknown-linux-gnu
    rustup_sha256="$RUSTUP_SHA256_AARCH64" state_name=linux-release-hosts-aarch64
    ;;
  *) fail "unknown platform ${platform}; use linux-x86_64 or linux-aarch64" ;;
esac
command -v docker >/dev/null 2>&1 || fail "docker is required"

mkdir -p "$out"
out="$(cd "$out" && pwd)"
state="${CARGO_TARGET_DIR:-${ROOT}/target}/${state_name}"
mkdir -p "$state"

# Runs as root to install the C toolchain, then hands written files back to
# the caller so later steps and cache tooling can read and remove them.
docker run --rm --platform "$docker_platform" \
  -v "${ROOT}:/src:ro" -v "${state}:/state" -v "${out}:/out" \
  -e RUSTUP_VERSION="$RUSTUP_VERSION" -e RUSTUP_SHA256="$rustup_sha256" \
  -e TRIPLE="$triple" -e PLATFORM="$platform" \
  -e OWNER="$(id -u):$(id -g)" \
  "$IMAGE" bash -euo pipefail -c '
    trap "chown -R \"\$OWNER\" /state /out" EXIT
    dnf -y -q install gcc binutils diffutils >/dev/null
    export RUSTUP_HOME=/state/rustup CARGO_HOME=/state/cargo CARGO_TARGET_DIR=/state/target
    if [[ ! -x "${CARGO_HOME}/bin/rustup" ]]; then
      curl -fsSL -o /tmp/rustup-init \
        "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${TRIPLE}/rustup-init"
      echo "${RUSTUP_SHA256}  /tmp/rustup-init" | sha256sum -c - >/dev/null
      chmod 0755 /tmp/rustup-init
      /tmp/rustup-init -y -q --profile minimal --default-toolchain none --no-modify-path >/dev/null
    fi
    export PATH="${CARGO_HOME}/bin:${PATH}"
    cd /src
    # sed reads all input; head would close the pipe and fail pipefail with SIGPIPE.
    ldd --version | sed -n 1p
    # The C toolchain is not pinned by the image digest; record it so a
    # rebuild of an older tag can tell a toolchain change from a real one.
    rpm -q gcc binutils glibc-devel
    # The macOS hosts in release-binaries.yml, plus the Linux-only
    # tenkai-host-applier.
    cargo build --release --locked --workspace --features tenkai-server/ui \
      --bin tenkaictl \
      --bin tenkai-server \
      --bin tenkai-executor-guard \
      --bin tenkai-runtime \
      --bin tenkai-runtime-guard \
      --bin tenkai-host-applier
    bash scripts/package-release-binaries.sh package \
      --out /out --bin-dir /state/target/release --platform "$PLATFORM" --strip
    cargo build --release --locked -p tenkai-server --features postgres,ui
    bash scripts/package-release-binaries.sh package-hub \
      --out /out --bin-dir /state/target/release --platform "$PLATFORM" --strip
    bash scripts/package-release-binaries.sh check-glibc --out /out --platform "$PLATFORM"
  '
printf '%s hosts in %s\n' "$platform" "$out"
