#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Fail when api/tenkai-http-v1.schema.json no longer matches the route types.
cargo test --locked --lib server::contract --quiet
printf 'http api contract ok\n'
