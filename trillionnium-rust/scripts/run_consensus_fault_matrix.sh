#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-$ROOT/run/health}"
OUT="$OUT_DIR/consensus-fault-matrix-$TS.txt"
mkdir -p "$OUT_DIR"

# Global defaults (can be overridden per-case below).
CONSENSUS_MAX_FINALITY_P95_MS="${CONSENSUS_MAX_FINALITY_P95_MS:-500}"
CONSENSUS_MAX_ROUND_CHANGE_TOTAL="${CONSENSUS_MAX_ROUND_CHANGE_TOTAL:-8}"
CONSENSUS_MIN_COMMITTED_HEIGHTS="${CONSENSUS_MIN_COMMITTED_HEIGHTS:-1}"

# Case-specific thresholds (fallback to global if unset).
BASELINE_MAX_FINALITY_P95_MS="${BASELINE_MAX_FINALITY_P95_MS:-$CONSENSUS_MAX_FINALITY_P95_MS}"
BASELINE_MAX_ROUND_CHANGE_TOTAL="${BASELINE_MAX_ROUND_CHANGE_TOTAL:-$CONSENSUS_MAX_ROUND_CHANGE_TOTAL}"
BASELINE_MIN_COMMITTED_HEIGHTS="${BASELINE_MIN_COMMITTED_HEIGHTS:-$CONSENSUS_MIN_COMMITTED_HEIGHTS}"

SLOW_BLOCK_MAX_FINALITY_P95_MS="${SLOW_BLOCK_MAX_FINALITY_P95_MS:-$CONSENSUS_MAX_FINALITY_P95_MS}"
SLOW_BLOCK_MAX_ROUND_CHANGE_TOTAL="${SLOW_BLOCK_MAX_ROUND_CHANGE_TOTAL:-$CONSENSUS_MAX_ROUND_CHANGE_TOTAL}"
SLOW_BLOCK_MIN_COMMITTED_HEIGHTS="${SLOW_BLOCK_MIN_COMMITTED_HEIGHTS:-$CONSENSUS_MIN_COMMITTED_HEIGHTS}"

RESTART_RECOVERY_MAX_FINALITY_P95_MS="${RESTART_RECOVERY_MAX_FINALITY_P95_MS:-$CONSENSUS_MAX_FINALITY_P95_MS}"
RESTART_RECOVERY_MAX_ROUND_CHANGE_TOTAL="${RESTART_RECOVERY_MAX_ROUND_CHANGE_TOTAL:-$CONSENSUS_MAX_ROUND_CHANGE_TOTAL}"
RESTART_RECOVERY_MIN_COMMITTED_HEIGHTS="${RESTART_RECOVERY_MIN_COMMITTED_HEIGHTS:-$CONSENSUS_MIN_COMMITTED_HEIGHTS}"

pass=0
fail=0

parse_metric() {
  local line="$1"
  local key="$2"
  sed -n "s/.*${key}=\([0-9][0-9]*\).*/\1/p" <<<"$line"
}

run_case() {
  local name="$1"
  local cmd="$2"
  local max_p95="$3"
  local max_round_change="$4"
  local min_committed="$5"
  local log="$OUT_DIR/consensus-fault-${name}-${TS}.log"

  echo "=== case:$name ===" | tee -a "$OUT"
  echo "cmd=$cmd" | tee -a "$OUT"
  echo "thresholds max_p95_ms=$max_p95 max_round_change=$max_round_change min_committed=$min_committed" | tee -a "$OUT"

  if bash -lc "$cmd" >"$log" 2>&1; then
    if grep -E '\[tx\] apply_error|rollback=true' "$log" >/dev/null; then
      echo "result=FAIL reason=apply_error_or_rollback log=$log" | tee -a "$OUT"
      fail=$((fail+1))
      return 0
    fi

    local consensus_line
    consensus_line="$(grep '^\[consensus\] finality_p50_ms=' "$log" | tail -n1 || true)"
    if [[ -z "$consensus_line" ]]; then
      echo "result=FAIL reason=missing_consensus_metrics log=$log" | tee -a "$OUT"
      fail=$((fail+1))
      return 0
    fi

    local p95 round_change committed
    p95="$(parse_metric "$consensus_line" "finality_p95_ms")"
    round_change="$(parse_metric "$consensus_line" "bft_round_change_total")"
    committed="$(parse_metric "$consensus_line" "bft_committed_heights")"

    if [[ -z "$p95" || -z "$round_change" || -z "$committed" ]]; then
      echo "result=FAIL reason=metrics_parse_error log=$log" | tee -a "$OUT"
      fail=$((fail+1))
      return 0
    fi

    if (( p95 > max_p95 )); then
      echo "result=FAIL reason=finality_p95_too_high p95=$p95 max=$max_p95 log=$log" | tee -a "$OUT"
      fail=$((fail+1))
      return 0
    fi

    if (( round_change > max_round_change )); then
      echo "result=FAIL reason=round_change_too_high round_change=$round_change max=$max_round_change log=$log" | tee -a "$OUT"
      fail=$((fail+1))
      return 0
    fi

    if (( committed < min_committed )); then
      echo "result=FAIL reason=insufficient_committed_heights committed=$committed min=$min_committed log=$log" | tee -a "$OUT"
      fail=$((fail+1))
      return 0
    fi

    echo "result=PASS p95=$p95 round_change=$round_change committed=$committed log=$log" | tee -a "$OUT"
    pass=$((pass+1))
  else
    echo "result=FAIL reason=command_error log=$log" | tee -a "$OUT"
    fail=$((fail+1))
  fi
}

# 1) baseline
run_case \
  "baseline" \
  "cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 6 --demo-tasks 8 --demo-keys 3 --parallel-workers 4" \
  "$BASELINE_MAX_FINALITY_P95_MS" \
  "$BASELINE_MAX_ROUND_CHANGE_TOTAL" \
  "$BASELINE_MIN_COMMITTED_HEIGHTS"

# 2) network-latency simulation via slower block cadence
run_case \
  "slow_block" \
  "cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 50 --max-blocks 6 --demo-tasks 8 --demo-keys 3 --parallel-workers 4" \
  "$SLOW_BLOCK_MAX_FINALITY_P95_MS" \
  "$SLOW_BLOCK_MAX_ROUND_CHANGE_TOTAL" \
  "$SLOW_BLOCK_MIN_COMMITTED_HEIGHTS"

# 3) restart-recovery simulation: partial run then restart
run_case \
  "restart_recovery" \
  "cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 3 --demo-tasks 8 --demo-keys 3 --parallel-workers 4 && cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 6 --demo-tasks 8 --demo-keys 3 --parallel-workers 4" \
  "$RESTART_RECOVERY_MAX_FINALITY_P95_MS" \
  "$RESTART_RECOVERY_MAX_ROUND_CHANGE_TOTAL" \
  "$RESTART_RECOVERY_MIN_COMMITTED_HEIGHTS"

{
  echo
  echo "global_thresholds finality_p95_ms<=$CONSENSUS_MAX_FINALITY_P95_MS round_change<=$CONSENSUS_MAX_ROUND_CHANGE_TOTAL committed>=$CONSENSUS_MIN_COMMITTED_HEIGHTS"
  echo "case_thresholds baseline(p95<=$BASELINE_MAX_FINALITY_P95_MS,rc<=$BASELINE_MAX_ROUND_CHANGE_TOTAL,commit>=$BASELINE_MIN_COMMITTED_HEIGHTS) slow_block(p95<=$SLOW_BLOCK_MAX_FINALITY_P95_MS,rc<=$SLOW_BLOCK_MAX_ROUND_CHANGE_TOTAL,commit>=$SLOW_BLOCK_MIN_COMMITTED_HEIGHTS) restart_recovery(p95<=$RESTART_RECOVERY_MAX_FINALITY_P95_MS,rc<=$RESTART_RECOVERY_MAX_ROUND_CHANGE_TOTAL,commit>=$RESTART_RECOVERY_MIN_COMMITTED_HEIGHTS)"
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