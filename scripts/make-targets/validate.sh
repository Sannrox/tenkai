#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

export LC_ALL=C

for validator in scripts/validate-*.sh; do
  [[ -f "$validator" ]] || continue
  bash "$validator"
done
