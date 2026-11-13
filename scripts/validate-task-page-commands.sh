#!/usr/bin/env bash
# Fail when a copy-paste tenkaictl command in docs/tasks/ does not parse.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

cargo test --locked -p tenkaictl --bin tenkaictl task_page_commands_parse
