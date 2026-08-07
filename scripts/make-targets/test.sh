#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ -n "${WHAT:-}" ]]; then
  cargo test --locked "$WHAT"
else
  cargo test --locked
fi
