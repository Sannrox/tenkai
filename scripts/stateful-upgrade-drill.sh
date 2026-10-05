#!/usr/bin/env bash
# Signed stateful upgrade drill with executor crash recovery (#334).
# Requires: cargo, openssl, a POSIX sh. No cluster, Postgres, or live provider.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo build --locked --bin tenkaictl --bin tenkai-executor-guard
exec cargo test --locked -p tenkaictl --test stateful_upgrade_drill -- --nocapture "$@"
