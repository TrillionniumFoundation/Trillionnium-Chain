#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-$ROOT/run/health}"
OUT="$OUT_DIR/consensus-fault-matrix-$TS.txt"
mkdir -p "$OUT_DIR"

pass=0
fail=0

run_case() {
  local name="$1"
  local cmd="$2"
  local log="$OUT_DIR/consensus-fault-${name}-${TS}.log"

  echo "=== case:$name ===" | tee -a "$OUT"
  echo "cmd=$cmd" | tee -a "$OUT"

  if bash -lc "$cmd" >"$log" 2>&1; then
    if grep -E '\[tx\] apply_error|rollback=true' "$log" >/dev/null; then
      echo "result=FAIL reason=apply_error_or_rollback log=$log" | tee -a "$OUT"
      fail=$((fail+1))
      return 0
    fi
    if ! grep -q '^\[consensus\] finality_p50_ms=' "$log"; then
      echo "result=FAIL reason=missing_consensus_metrics log=$log" | tee -a "$OUT"
      fail=$((fail+1))
      return 0
    fi
    echo "result=PASS log=$log" | tee -a "$OUT"
    pass=$((pass+1))
  else
    echo "result=FAIL reason=command_error log=$log" | tee -a "$OUT"
    fail=$((fail+1))
  fi
}

# 1) baseline
run_case "baseline" "cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 6 --demo-tasks 8 --demo-keys 3 --parallel-workers 4"

# 2) network-latency simulation via slower block cadence
run_case "slow_block" "cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 50 --max-blocks 6 --demo-tasks 8 --demo-keys 3 --parallel-workers 4"

# 3) restart-recovery simulation: partial run then restart
run_case "restart_recovery" "cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 3 --demo-tasks 8 --demo-keys 3 --parallel-workers 4 && cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 6 --demo-tasks 8 --demo-keys 3 --parallel-workers 4"

{
  echo
  echo "summary pass=$pass fail=$fail"
  if [[ "$fail" -eq 0 ]]; then
    echo "status=PASS"
  else
    echo "status=FAIL"
  fi
} | tee -a "$OUT"

if [[ "$fail" -ne 0 ]]; then
  echo "[FAIL] consensus fault matrix: $OUT" >&2
  exit 1
fi

echo "[OK] consensus fault matrix: $OUT"
