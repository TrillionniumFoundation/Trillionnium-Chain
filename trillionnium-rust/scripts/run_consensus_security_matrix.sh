#!/usr/bin/env bash
set -u -o pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-$ROOT/run/health/consensus-security-$TS}"
mkdir -p "$OUT_DIR"
SUMMARY="$OUT_DIR/summary.txt"

PASS=0
FAIL=0

run_step() {
  local name="$1"
  local cmd="$2"
  local log="$OUT_DIR/${name}.log"
  echo "[START] $name"
  {
    echo "# step=$name"
    echo "# cmd=$cmd"
    bash -lc "$cmd"
  } > >(tee "$log") 2>&1
  local rc=${PIPESTATUS[0]}
  if [[ $rc -eq 0 ]]; then
    echo "$name=PASS" >> "$SUMMARY"
    PASS=$((PASS+1))
    echo "[PASS]  $name"
  else
    echo "$name=FAIL(rc=$rc)" >> "$SUMMARY"
    FAIL=$((FAIL+1))
    echo "[FAIL]  $name rc=$rc"
  fi
}

echo "consensus_security.ts=$TS" > "$SUMMARY"
echo "consensus_security.out_dir=$OUT_DIR" >> "$SUMMARY"
echo "steps:" >> "$SUMMARY"

run_step "cargo_core_tests" "cargo test -p trnm-types -p trnm-worker-agent -p trnm-rpc -- --test-threads=1"
run_step "request_tx_binding" "OUT_DIR='$OUT_DIR' ./scripts/check_request_tx_binding.sh"
run_step "request_fault_injection" "OUT_DIR='$OUT_DIR' ./scripts/run_request_fault_injection.sh"
run_step "consensus_fault_matrix" "./scripts/run_consensus_fault_matrix.sh"
run_step "bft_restart_recovery" "./scripts/check_bft_restart_recovery.sh"
run_step "bft_round_change" "./scripts/check_bft_round_change.sh"
run_step "bft_message_auth" "./scripts/check_bft_message_auth.sh"
run_step "event_fields" "./scripts/check_event_fields.sh"
run_step "event_replay_smoke" "./scripts/check_event_replay_smoke.sh"

echo "pass_count=$PASS" >> "$SUMMARY"
echo "fail_count=$FAIL" >> "$SUMMARY"
if [[ $FAIL -eq 0 ]]; then
  echo "result=PASS" >> "$SUMMARY"
else
  echo "result=FAIL" >> "$SUMMARY"
fi

echo "summary=$SUMMARY"
if [[ $FAIL -eq 0 ]]; then
  exit 0
else
  exit 1
fi
