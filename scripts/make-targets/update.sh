#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

export LC_ALL=C

for updater in scripts/update-*.sh; do
  [[ -f "$updater" ]] || continue
  bash "$updater"
done
