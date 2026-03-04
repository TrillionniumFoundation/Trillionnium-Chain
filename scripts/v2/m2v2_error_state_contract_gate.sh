#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUST_ROOT="$ROOT/trillionnium-rust"

if [[ ! -f "$RUST_ROOT/Cargo.toml" ]]; then
  echo "[FAIL] missing Rust workspace Cargo.toml: $RUST_ROOT/Cargo.toml" >&2
  exit 2
fi

run_test() {
  local package="$1"
  local test_name="$2"
  local log
  log="$(mktemp)"

  echo "[M2V2-GATE][RUN] cargo test -p $package $test_name"
  if ! cargo test \
    --manifest-path "$RUST_ROOT/Cargo.toml" \
    -p "$package" \
    "$test_name" | tee "$log"; then
    rm -f "$log"
    return 1
  fi

  if ! grep -Eq "running [1-9][0-9]* test" "$log"; then
    echo "[FAIL] test filter matched zero tests for package=$package filter=$test_name" >&2
    rm -f "$log"
    return 1
  fi

  rm -f "$log"
}

run_test "trnm-pouw" "m2v2_dispute_reason_maps_to_frozen_error_codes"
run_test "trnm-pouw" "m2v2_frozen_transition_matches_master_state_path"
run_test "trnm-worker-agent" "adapter_error_classification_maps_mv2_fail_closed_receipt_contract_codes"
run_test "trnm-worker-agent" "adapter_error_classification_enforces_contract_precedence_for_ambiguous_contexts"

echo "[PASS] M2↔V2 frozen error/state contract gate passed"
