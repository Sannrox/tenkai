#!/usr/bin/env bash
# Download the pinned web-console zip into TENKAI_UI_BUNDLE, or verify a
# cached copy. GitHub release fetches sometimes answer 504; curl retries
# those. tenkai-http build.rs still checks the pin checksum.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN_FILE="${ROOT}/ui/console.pin"
dest="${TENKAI_UI_BUNDLE:-}"
if [[ -z "${dest}" ]]; then
  printf 'fetch-console-bundle: set TENKAI_UI_BUNDLE to the destination path\n' >&2
  exit 1
fi

read -r tag expected _ <"${PIN_FILE}"
url="https://github.com/Sannrox/tenkai-console/releases/download/${tag}/tenkai-console-${tag}.zip"
mkdir -p "$(dirname "${dest}")"
if [[ ! -f "${dest}" ]]; then
  curl --proto '=https' --tlsv1.2 --retry 10 --retry-all-errors --retry-delay 2 \
    --location --fail --show-error --output "${dest}" "${url}"
fi
actual="$(sha256sum "${dest}" | awk '{print $1}')"
if [[ "${actual}" != "${expected}" ]]; then
  printf 'fetch-console-bundle: checksum mismatch: pinned %s, got %s\n' \
    "${expected}" "${actual}" >&2
  exit 1
fi
printf 'fetch-console-bundle: %s (%s)\n' "${dest}" "${tag}"
