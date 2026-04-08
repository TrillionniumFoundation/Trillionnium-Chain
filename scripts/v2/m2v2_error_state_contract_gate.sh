#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUST_ROOT="$ROOT/trillionnium"

if [[ ! -f "$RUST_ROOT/Cargo.toml" ]]; then
  echo "[FAIL] missing Rust workspace Cargo.toml: $RUST_ROOT/Cargo.toml" >&2
  exit 2
fi

run_test() {
  local package="$1"
  local test_name="$2"
  local log
  log="$(mktemp)"

  echo "[M2V2-GATE][RUN] cargo test --locked -p $package $test_name"
  if ! cargo test \
    --locked \
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

run_test "trnm-worker-agent" "adapter_error_classification_maps_mv2_fail_closed_receipt_contract_codes"
run_test "trnm-worker-agent" "adapter_error_classification_enforces_contract_precedence_for_ambiguous_contexts"
run_test "trnm-worker-agent" "transition_request_status_rejects_malformed_state_with_stable_diagnostic"

echo "[PASS] M2↔V2 frozen error/state contract gate passed"
