#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${LOG_DIR:-$ROOT/data/alpha-acceptance}"
mkdir -p "$LOG_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
REPORT="$LOG_DIR/report-$TS.txt"

run_step() {
  local name="$1" cmd="$2"
  echo "\n===== $name =====" | tee -a "$REPORT"
  set +e
  bash -lc "$cmd" >"$LOG_DIR/${TS}-${name}.log" 2>&1
  local rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    echo "PASS: $name" | tee -a "$REPORT"
  else
    echo "FAIL: $name (see $LOG_DIR/${TS}-${name}.log)" | tee -a "$REPORT"
  fi
  return 0
}

echo "Trillionnium Alpha Acceptance Run @ $TS" | tee "$REPORT"

a=0
run_step "A_happy_path" "cd '$ROOT' && ./scripts/scenario_A_happy.sh"
run_step "B_timeout" "cd '$ROOT' && WAIT_SEC=8 ./scripts/scenario_B_timeout.sh"
run_step "C_challenge" "cd '$ROOT' && ./scripts/scenario_C_challenge.sh"
run_step "D_auth_guards" "cd '$ROOT' && ./scripts/scenario_D_slash.sh"
run_step "E_unbonding" "cd '$ROOT' && MODE=unbonding ./scripts/demo_e2e.sh"

echo "\nNotes:" | tee -a "$REPORT"
echo "- D positive authority resolve/slash path is still pending governance/module-authority signing route." | tee -a "$REPORT"
echo "- Logs: $LOG_DIR" | tee -a "$REPORT"

echo "\nDone. Summary report: $REPORT" | tee -a "$REPORT"
