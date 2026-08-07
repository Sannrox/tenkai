#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Refresh build-generated protobuf bindings under Cargo's target directory
# without changing the locked dependency graph.
cargo check --all-targets --locked
