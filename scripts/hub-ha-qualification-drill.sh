#!/usr/bin/env bash
# Hub HA qualification drill (#903).
#
# One command against a two-replica PostgreSQL hub: multi-environment apply,
# kill the writer mid-step, takeover within the bound, exactly-once receipts,
# then replace the replica processes on the same store and repeat. A second
# test leaves the writer fence unset and must not qualify.
#
# Requires: cargo, TENKAI_POSTGRES_URL for a role that may CREATE DATABASE.
# Per-run databases include the process id; parallel runs do not collide.
# Product high_availability stays unclaimed; this drill is the gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "${1:-}" == "--verify" ]]; then
  # Offline: no Postgres. Verifies the named evidence with this run's public
  # key (written beside it as <file>.pub). The key is not a release-signing
  # key; it only binds this drill's statement bytes.
  file="${2:?usage: $0 --verify <evidence.json>}"
  pub="${file}.pub"
  [[ -f "$file" ]] || { printf 'missing evidence file: %s\n' "$file" >&2; exit 1; }
  [[ -f "$pub" ]] || { printf 'missing public key: %s\n' "$pub" >&2; exit 1; }
  cargo test --locked --lib hub_ha_qualification -- --nocapture
  TENKAI_HA_DRILL_EVIDENCE="$file" TENKAI_HA_DRILL_PUBKEY="$(cat "$pub")" \
    cargo test --locked --lib hub_ha_qualification::tests::verify_named_evidence \
    -- --exact --nocapture
  exit 0
fi

: "${TENKAI_POSTGRES_URL:?set TENKAI_POSTGRES_URL to a role that may CREATE DATABASE}"

out="${TENKAI_HA_DRILL_OUT:-}"
if [[ -z "$out" ]]; then
  out="$(mktemp "${TMPDIR:-/tmp}/tenkai-hub-ha-XXXXXX.json")"
  export TENKAI_HA_DRILL_OUT="$out"
fi

cargo test --locked -p tenkai-postgres --features postgres --lib -- \
  --ignored --nocapture live_ha_qualification

printf 'hub HA qualification evidence: %s\n' "$TENKAI_HA_DRILL_OUT"
