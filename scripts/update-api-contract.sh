#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Regenerate api/tenkai-http-v1.schema.json from the HTTP route types (#471).
TENKAI_UPDATE_API_CONTRACT=1 cargo test --locked --lib server::contract --quiet
