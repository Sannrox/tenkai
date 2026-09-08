#!/usr/bin/env bash
# Signed stateful upgrade drill with executor crash recovery (#334).
# Requires: cargo, openssl, a POSIX sh. No cluster, Postgres, or live provider.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

exec cargo test --locked --test stateful_upgrade_drill -- --nocapture "$@"
