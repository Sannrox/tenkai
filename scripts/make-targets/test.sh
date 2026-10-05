#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

cargo build --locked --bins --workspace
if [[ -n "${WHAT:-}" ]]; then
  cargo test --locked --workspace "$WHAT"
else
  cargo test --locked --workspace
fi
