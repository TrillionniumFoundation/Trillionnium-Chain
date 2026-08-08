#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
MANIFEST="$ROOT/trillionnium/Cargo.toml"

run_unit_filter() {
  local package="$1"
  local filter="$2"
  local listed

  listed="$(cargo test --manifest-path "$MANIFEST" --locked \
    -p "$package" --lib "$filter" -- --list)"
  if ! grep -Fq -- "$filter" <<<"$listed"; then
    printf 'recovery smoke filter matched no test: package=%s filter=%s\n' \
      "$package" "$filter" >&2
    exit 2
  fi
  cargo test --manifest-path "$MANIFEST" --locked \
    -p "$package" --lib "$filter" -- --test-threads=1
}

run_unit_filter trnm-consensus-core \
  recovery_with_a_claimed_durable_validation_fails_closed_without_reopening_it
run_unit_filter trnm-consensus-core \
  persisted_sign_intent_is_re_requested_after_recovery
run_unit_filter trnm-consensus-core \
  durable_valid_fact_still_requires_body_and_context_readiness_after_recovery
run_unit_filter trnm-consensus-app \
  durable_reservation_is_unique_across_independent_stores_and_reopen
run_unit_filter trnm-consensus-app \
  native_validation_reservations_remain_source_local_across_snapshot_build_and_install

printf '%s\n' \
  'poco_bft_recovery_smoke=passed scope=core-sign-validation-reservation-snapshot'
