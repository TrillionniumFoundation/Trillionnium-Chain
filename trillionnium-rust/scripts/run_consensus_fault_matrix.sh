#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-$ROOT/run/health}"
OUT="${CONSENSUS_FAULT_MATRIX_OUT:-$OUT_DIR/consensus-fault-matrix-$TS.txt}"
OUT_DIR="$(dirname "$OUT")"
mkdir -p "$OUT_DIR"

# Global defaults (can be overridden per-case below).
CONSENSUS_MAX_FINALITY_P95_MS="${CONSENSUS_MAX_FINALITY_P95_MS:-500}"
CONSENSUS_MAX_ROUND_CHANGE_TOTAL="${CONSENSUS_MAX_ROUND_CHANGE_TOTAL:-12}"
CONSENSUS_MIN_COMMITTED_HEIGHTS="${CONSENSUS_MIN_COMMITTED_HEIGHTS:-1}"
CONSENSUS_MAX_RECOVERY_TIME_MS="${CONSENSUS_MAX_RECOVERY_TIME_MS:-120}"
CONSENSUS_MAX_FORK_DEPTH="${CONSENSUS_MAX_FORK_DEPTH:-12}"
CONSENSUS_REQUIRE_STATE_ROOT_CONSISTENT="${CONSENSUS_REQUIRE_STATE_ROOT_CONSISTENT:-1}"

# Case-specific thresholds (fallback to global if unset).
BASELINE_MAX_FINALITY_P95_MS="${BASELINE_MAX_FINALITY_P95_MS:-$CONSENSUS_MAX_FINALITY_P95_MS}"
BASELINE_MAX_ROUND_CHANGE_TOTAL="${BASELINE_MAX_ROUND_CHANGE_TOTAL:-$CONSENSUS_MAX_ROUND_CHANGE_TOTAL}"
BASELINE_MIN_COMMITTED_HEIGHTS="${BASELINE_MIN_COMMITTED_HEIGHTS:-$CONSENSUS_MIN_COMMITTED_HEIGHTS}"
BASELINE_MAX_RECOVERY_TIME_MS="${BASELINE_MAX_RECOVERY_TIME_MS:-$CONSENSUS_MAX_RECOVERY_TIME_MS}"
BASELINE_MAX_FORK_DEPTH="${BASELINE_MAX_FORK_DEPTH:-$CONSENSUS_MAX_FORK_DEPTH}"
BASELINE_REQUIRE_STATE_ROOT_CONSISTENT="${BASELINE_REQUIRE_STATE_ROOT_CONSISTENT:-$CONSENSUS_REQUIRE_STATE_ROOT_CONSISTENT}"

SLOW_BLOCK_MAX_FINALITY_P95_MS="${SLOW_BLOCK_MAX_FINALITY_P95_MS:-$CONSENSUS_MAX_FINALITY_P95_MS}"
SLOW_BLOCK_MAX_ROUND_CHANGE_TOTAL="${SLOW_BLOCK_MAX_ROUND_CHANGE_TOTAL:-$CONSENSUS_MAX_ROUND_CHANGE_TOTAL}"
SLOW_BLOCK_MIN_COMMITTED_HEIGHTS="${SLOW_BLOCK_MIN_COMMITTED_HEIGHTS:-$CONSENSUS_MIN_COMMITTED_HEIGHTS}"
SLOW_BLOCK_MAX_RECOVERY_TIME_MS="${SLOW_BLOCK_MAX_RECOVERY_TIME_MS:-$CONSENSUS_MAX_RECOVERY_TIME_MS}"
SLOW_BLOCK_MAX_FORK_DEPTH="${SLOW_BLOCK_MAX_FORK_DEPTH:-$CONSENSUS_MAX_FORK_DEPTH}"
SLOW_BLOCK_REQUIRE_STATE_ROOT_CONSISTENT="${SLOW_BLOCK_REQUIRE_STATE_ROOT_CONSISTENT:-$CONSENSUS_REQUIRE_STATE_ROOT_CONSISTENT}"

RESTART_RECOVERY_MAX_FINALITY_P95_MS="${RESTART_RECOVERY_MAX_FINALITY_P95_MS:-$CONSENSUS_MAX_FINALITY_P95_MS}"
RESTART_RECOVERY_MAX_ROUND_CHANGE_TOTAL="${RESTART_RECOVERY_MAX_ROUND_CHANGE_TOTAL:-$CONSENSUS_MAX_ROUND_CHANGE_TOTAL}"
RESTART_RECOVERY_MIN_COMMITTED_HEIGHTS="${RESTART_RECOVERY_MIN_COMMITTED_HEIGHTS:-$CONSENSUS_MIN_COMMITTED_HEIGHTS}"
RESTART_RECOVERY_MAX_RECOVERY_TIME_MS="${RESTART_RECOVERY_MAX_RECOVERY_TIME_MS:-$CONSENSUS_MAX_RECOVERY_TIME_MS}"
RESTART_RECOVERY_MAX_FORK_DEPTH="${RESTART_RECOVERY_MAX_FORK_DEPTH:-$CONSENSUS_MAX_FORK_DEPTH}"
RESTART_RECOVERY_REQUIRE_STATE_ROOT_CONSISTENT="${RESTART_RECOVERY_REQUIRE_STATE_ROOT_CONSISTENT:-$CONSENSUS_REQUIRE_STATE_ROOT_CONSISTENT}"

BYZANTINE_ROUNDS_MAX_FINALITY_P95_MS="${BYZANTINE_ROUNDS_MAX_FINALITY_P95_MS:-$CONSENSUS_MAX_FINALITY_P95_MS}"
BYZANTINE_ROUNDS_MAX_ROUND_CHANGE_TOTAL="${BYZANTINE_ROUNDS_MAX_ROUND_CHANGE_TOTAL:-$CONSENSUS_MAX_ROUND_CHANGE_TOTAL}"
BYZANTINE_ROUNDS_MIN_COMMITTED_HEIGHTS="${BYZANTINE_ROUNDS_MIN_COMMITTED_HEIGHTS:-$CONSENSUS_MIN_COMMITTED_HEIGHTS}"
BYZANTINE_ROUNDS_MAX_RECOVERY_TIME_MS="${BYZANTINE_ROUNDS_MAX_RECOVERY_TIME_MS:-$CONSENSUS_MAX_RECOVERY_TIME_MS}"
BYZANTINE_ROUNDS_MAX_FORK_DEPTH="${BYZANTINE_ROUNDS_MAX_FORK_DEPTH:-$CONSENSUS_MAX_FORK_DEPTH}"
BYZANTINE_ROUNDS_REQUIRE_STATE_ROOT_CONSISTENT="${BYZANTINE_ROUNDS_REQUIRE_STATE_ROOT_CONSISTENT:-$CONSENSUS_REQUIRE_STATE_ROOT_CONSISTENT}"

FAULTY_ROUND_BACKOFF_MAX_FINALITY_P95_MS="${FAULTY_ROUND_BACKOFF_MAX_FINALITY_P95_MS:-$CONSENSUS_MAX_FINALITY_P95_MS}"
FAULTY_ROUND_BACKOFF_MAX_ROUND_CHANGE_TOTAL="${FAULTY_ROUND_BACKOFF_MAX_ROUND_CHANGE_TOTAL:-$CONSENSUS_MAX_ROUND_CHANGE_TOTAL}"
FAULTY_ROUND_BACKOFF_MIN_COMMITTED_HEIGHTS="${FAULTY_ROUND_BACKOFF_MIN_COMMITTED_HEIGHTS:-$CONSENSUS_MIN_COMMITTED_HEIGHTS}"
FAULTY_ROUND_BACKOFF_MAX_RECOVERY_TIME_MS="${FAULTY_ROUND_BACKOFF_MAX_RECOVERY_TIME_MS:-$CONSENSUS_MAX_RECOVERY_TIME_MS}"
FAULTY_ROUND_BACKOFF_MAX_FORK_DEPTH="${FAULTY_ROUND_BACKOFF_MAX_FORK_DEPTH:-$CONSENSUS_MAX_FORK_DEPTH}"
FAULTY_ROUND_BACKOFF_REQUIRE_STATE_ROOT_CONSISTENT="${FAULTY_ROUND_BACKOFF_REQUIRE_STATE_ROOT_CONSISTENT:-$CONSENSUS_REQUIRE_STATE_ROOT_CONSISTENT}"

LEADER_JITTER_MAX_FINALITY_P95_MS="${LEADER_JITTER_MAX_FINALITY_P95_MS:-$CONSENSUS_MAX_FINALITY_P95_MS}"
LEADER_JITTER_MAX_ROUND_CHANGE_TOTAL="${LEADER_JITTER_MAX_ROUND_CHANGE_TOTAL:-$CONSENSUS_MAX_ROUND_CHANGE_TOTAL}"
LEADER_JITTER_MIN_COMMITTED_HEIGHTS="${LEADER_JITTER_MIN_COMMITTED_HEIGHTS:-$CONSENSUS_MIN_COMMITTED_HEIGHTS}"
LEADER_JITTER_MAX_RECOVERY_TIME_MS="${LEADER_JITTER_MAX_RECOVERY_TIME_MS:-$CONSENSUS_MAX_RECOVERY_TIME_MS}"
LEADER_JITTER_MAX_FORK_DEPTH="${LEADER_JITTER_MAX_FORK_DEPTH:-$CONSENSUS_MAX_FORK_DEPTH}"
LEADER_JITTER_REQUIRE_STATE_ROOT_CONSISTENT="${LEADER_JITTER_REQUIRE_STATE_ROOT_CONSISTENT:-$CONSENSUS_REQUIRE_STATE_ROOT_CONSISTENT}"

MESSAGE_REORDER_MAX_FINALITY_P95_MS="${MESSAGE_REORDER_MAX_FINALITY_P95_MS:-$CONSENSUS_MAX_FINALITY_P95_MS}"
MESSAGE_REORDER_MAX_ROUND_CHANGE_TOTAL="${MESSAGE_REORDER_MAX_ROUND_CHANGE_TOTAL:-$CONSENSUS_MAX_ROUND_CHANGE_TOTAL}"
MESSAGE_REORDER_MIN_COMMITTED_HEIGHTS="${MESSAGE_REORDER_MIN_COMMITTED_HEIGHTS:-$CONSENSUS_MIN_COMMITTED_HEIGHTS}"
MESSAGE_REORDER_MAX_RECOVERY_TIME_MS="${MESSAGE_REORDER_MAX_RECOVERY_TIME_MS:-$CONSENSUS_MAX_RECOVERY_TIME_MS}"
MESSAGE_REORDER_MAX_FORK_DEPTH="${MESSAGE_REORDER_MAX_FORK_DEPTH:-$CONSENSUS_MAX_FORK_DEPTH}"
MESSAGE_REORDER_REQUIRE_STATE_ROOT_CONSISTENT="${MESSAGE_REORDER_REQUIRE_STATE_ROOT_CONSISTENT:-$CONSENSUS_REQUIRE_STATE_ROOT_CONSISTENT}"

SLOW_VALIDATOR_MAX_FINALITY_P95_MS="${SLOW_VALIDATOR_MAX_FINALITY_P95_MS:-$CONSENSUS_MAX_FINALITY_P95_MS}"
SLOW_VALIDATOR_MAX_ROUND_CHANGE_TOTAL="${SLOW_VALIDATOR_MAX_ROUND_CHANGE_TOTAL:-$CONSENSUS_MAX_ROUND_CHANGE_TOTAL}"
SLOW_VALIDATOR_MIN_COMMITTED_HEIGHTS="${SLOW_VALIDATOR_MIN_COMMITTED_HEIGHTS:-$CONSENSUS_MIN_COMMITTED_HEIGHTS}"
SLOW_VALIDATOR_MAX_RECOVERY_TIME_MS="${SLOW_VALIDATOR_MAX_RECOVERY_TIME_MS:-$CONSENSUS_MAX_RECOVERY_TIME_MS}"
SLOW_VALIDATOR_MAX_FORK_DEPTH="${SLOW_VALIDATOR_MAX_FORK_DEPTH:-$CONSENSUS_MAX_FORK_DEPTH}"
SLOW_VALIDATOR_REQUIRE_STATE_ROOT_CONSISTENT="${SLOW_VALIDATOR_REQUIRE_STATE_ROOT_CONSISTENT:-$CONSENSUS_REQUIRE_STATE_ROOT_CONSISTENT}"

pass=0
fail=0

CASE_FILTER="${CASE_FILTER:-all}"   # all | comma-separated case names
# Canonicalize filter (strip all whitespace) so values like "baseline, slow_block" work as expected.
CASE_FILTER="$(printf '%s' "$CASE_FILTER" | tr -d '[:space:]')"
ALLOW_FAIL="${ALLOW_FAIL:-0}"       # 1 => always exit 0 (for soft-gate observation)
GATE_MODE="${GATE_MODE:-normal}"    # hard | soft | normal

ALL_CASES=(
  baseline slow_block restart_recovery byzantine_rounds
  faulty_round_backoff leader_jitter message_reorder slow_validator
)

known_case() {
  local name="$1"
  local c
  for c in "${ALL_CASES[@]}"; do
    if [[ "$c" == "$name" ]]; then
      return 0
    fi
  done
  return 1
}

validate_case_filter() {
  if [[ "$CASE_FILTER" == "all" || -z "$CASE_FILTER" ]]; then
    return 0
  fi

  local token
  local seen_tokens=","
  IFS=',' read -r -a _case_tokens <<< "$CASE_FILTER"
  for token in "${_case_tokens[@]}"; do
    if [[ -z "$token" ]]; then
      echo "[FAIL] consensus fault matrix invalid empty case name in CASE_FILTER=$CASE_FILTER" >&2
      exit 2
    fi
    if ! known_case "$token"; then
      echo "[FAIL] consensus fault matrix unknown case '$token' in CASE_FILTER=$CASE_FILTER" >&2
      exit 2
    fi
    if [[ "$seen_tokens" == *",$token,"* ]]; then
      echo "[FAIL] consensus fault matrix duplicate case '$token' in CASE_FILTER=$CASE_FILTER" >&2
      exit 2
    fi
    seen_tokens+="$token,"
  done
}

validate_case_filter

case_enabled() {
  local name="$1"
  if [[ "$CASE_FILTER" == "all" || -z "$CASE_FILTER" ]]; then
    return 0
  fi
  [[ ",$CASE_FILTER," == *",$name,"* ]]
}

selected_case_count() {
  local n=0
  local c
  for c in "${ALL_CASES[@]}"; do
    if case_enabled "$c"; then
      n=$((n+1))
    fi
  done
  echo "$n"
}

EXPECTED_CASES="${EXPECTED_CASES:-$(selected_case_count)}"

if [[ "$GATE_MODE" == "hard" && "$ALLOW_FAIL" != "0" ]]; then
  echo "[FAIL] hard gate forbids ALLOW_FAIL=$ALLOW_FAIL" >&2
  exit 2
fi

parse_metric() {
  local line="$1"
  local key="$2"
  sed -n "s/.*${key}=\([0-9][0-9]*\).*/\1/p" <<<"$line"
}

state_root_consistency() {
  local log="$1"
  awk '
    /^\[block\]/ {
      h=""; r="";
      for (i=1; i<=NF; i++) {
        if ($i ~ /^height=/) { split($i,a,"="); h=a[2] }
        if ($i ~ /^state_root=/) { split($i,a,"="); r=a[2] }
      }
      if (h != "" && r != "") {
        if (seen[h] == "") { seen[h] = r }
        else if (seen[h] != r) { conflict = 1 }
      }
    }
    END {
      if (conflict == 1) print "0"; else print "1";
    }
  ' "$log"
}

run_case() {
  local name="$1"
  local cmd="$2"
  local max_p95="$3"
  local max_round_change="$4"
  local min_committed="$5"
  local max_recovery_ms="$6"
  local max_fork_depth="$7"
  local require_state_root_consistent="$8"
  local log="$OUT_DIR/consensus-fault-${name}-${TS}.log"

  echo "=== case:$name ===" | tee -a "$OUT"
  echo "cmd=$cmd" | tee -a "$OUT"
  echo "thresholds max_p95_ms=$max_p95 max_round_change=$max_round_change min_committed=$min_committed max_recovery_ms=$max_recovery_ms max_fork_depth=$max_fork_depth state_root_consistent_required=$require_state_root_consistent" | tee -a "$OUT"

  if bash -lc "$cmd" >"$log" 2>&1; then
    if grep -E '\[tx\] apply_error|rollback=true' "$log" >/dev/null; then
      echo "result=FAIL reason=apply_error_or_rollback log=$log" | tee -a "$OUT"
      fail=$((fail+1))
      return 0
    fi

    local consensus_lines
    consensus_lines="$(grep '^\[consensus\] finality_p50_ms=' "$log" || true)"
    if [[ -z "$consensus_lines" ]]; then
      echo "result=FAIL reason=missing_consensus_metrics log=$log" | tee -a "$OUT"
      fail=$((fail+1))
      return 0
    fi

    local p95 round_change committed recovery_ms fork_depth state_root_ok
    local line lp95 lrc lcomm lrecovery
    p95=0
    round_change=0
    committed=999999999
    recovery_ms=0

    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      lp95="$(parse_metric "$line" "finality_p95_ms")"
      lrc="$(parse_metric "$line" "bft_round_change_total")"
      lcomm="$(parse_metric "$line" "bft_committed_heights")"
      lrecovery="$(parse_metric "$line" "bft_round_change_backoff_total_ms")"

      if [[ -z "$lp95" || -z "$lrc" || -z "$lcomm" || -z "$lrecovery" ]]; then
        echo "result=FAIL reason=metrics_parse_error log=$log" | tee -a "$OUT"
        fail=$((fail+1))
        return 0
      fi

      (( lp95 > p95 )) && p95="$lp95"
      (( lrc > round_change )) && round_change="$lrc"
      (( lcomm < committed )) && committed="$lcomm"
      (( lrecovery > recovery_ms )) && recovery_ms="$lrecovery"
    done <<< "$consensus_lines"

    # Derived metrics for 8-case matrix reporting.
    fork_depth="$round_change"                    # proxy for turbulence depth under single-node harness
    state_root_ok="$(state_root_consistency "$log")"

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

    if (( recovery_ms > max_recovery_ms )); then
      echo "result=FAIL reason=recovery_time_too_high recovery_ms=$recovery_ms max=$max_recovery_ms log=$log" | tee -a "$OUT"
      fail=$((fail+1))
      return 0
    fi

    if (( fork_depth > max_fork_depth )); then
      echo "result=FAIL reason=fork_depth_too_high fork_depth=$fork_depth max=$max_fork_depth log=$log" | tee -a "$OUT"
      fail=$((fail+1))
      return 0
    fi

    if [[ "$require_state_root_consistent" == "1" && "$state_root_ok" != "1" ]]; then
      echo "result=FAIL reason=state_root_inconsistent state_root_ok=$state_root_ok log=$log" | tee -a "$OUT"
      fail=$((fail+1))
      return 0
    fi

    echo "result=PASS p95=$p95 round_change=$round_change committed=$committed recovery_ms=$recovery_ms fork_depth=$fork_depth state_root_ok=$state_root_ok log=$log" | tee -a "$OUT"
    pass=$((pass+1))
  else
    echo "result=FAIL reason=command_error log=$log" | tee -a "$OUT"
    fail=$((fail+1))
  fi
}

# 1) baseline
if case_enabled "baseline"; then
run_case \
  "baseline" \
  "cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 6 --demo-tasks 8 --demo-keys 3 --parallel-workers 4" \
  "$BASELINE_MAX_FINALITY_P95_MS" \
  "$BASELINE_MAX_ROUND_CHANGE_TOTAL" \
  "$BASELINE_MIN_COMMITTED_HEIGHTS" \
  "$BASELINE_MAX_RECOVERY_TIME_MS" \
  "$BASELINE_MAX_FORK_DEPTH" \
  "$BASELINE_REQUIRE_STATE_ROOT_CONSISTENT"
fi

# 2) slow block cadence (latency)
if case_enabled "slow_block"; then
run_case \
  "slow_block" \
  "cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 50 --max-blocks 6 --demo-tasks 8 --demo-keys 3 --parallel-workers 4" \
  "$SLOW_BLOCK_MAX_FINALITY_P95_MS" \
  "$SLOW_BLOCK_MAX_ROUND_CHANGE_TOTAL" \
  "$SLOW_BLOCK_MIN_COMMITTED_HEIGHTS" \
  "$SLOW_BLOCK_MAX_RECOVERY_TIME_MS" \
  "$SLOW_BLOCK_MAX_FORK_DEPTH" \
  "$SLOW_BLOCK_REQUIRE_STATE_ROOT_CONSISTENT"
fi

# 3) restart + recovery
if case_enabled "restart_recovery"; then
run_case \
  "restart_recovery" \
  "cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 3 --demo-tasks 8 --demo-keys 3 --parallel-workers 4 && cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 6 --demo-tasks 8 --demo-keys 3 --parallel-workers 4" \
  "$RESTART_RECOVERY_MAX_FINALITY_P95_MS" \
  "$RESTART_RECOVERY_MAX_ROUND_CHANGE_TOTAL" \
  "$RESTART_RECOVERY_MIN_COMMITTED_HEIGHTS" \
  "$RESTART_RECOVERY_MAX_RECOVERY_TIME_MS" \
  "$RESTART_RECOVERY_MAX_FORK_DEPTH" \
  "$RESTART_RECOVERY_REQUIRE_STATE_ROOT_CONSISTENT"
fi

# 4) byzantine rounds
if case_enabled "byzantine_rounds"; then
run_case \
  "byzantine_rounds" \
  "cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 6 --demo-tasks 8 --demo-keys 3 --parallel-workers 4 --validators 4 --byzantine 1 --bft-max-rounds 4 --bft-fault-rounds 2" \
  "$BYZANTINE_ROUNDS_MAX_FINALITY_P95_MS" \
  "$BYZANTINE_ROUNDS_MAX_ROUND_CHANGE_TOTAL" \
  "$BYZANTINE_ROUNDS_MIN_COMMITTED_HEIGHTS" \
  "$BYZANTINE_ROUNDS_MAX_RECOVERY_TIME_MS" \
  "$BYZANTINE_ROUNDS_MAX_FORK_DEPTH" \
  "$BYZANTINE_ROUNDS_REQUIRE_STATE_ROOT_CONSISTENT"
fi

# 5) faulty round-change backoff pressure
if case_enabled "faulty_round_backoff"; then
run_case \
  "faulty_round_backoff" \
  "cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 6 --demo-tasks 8 --demo-keys 3 --parallel-workers 4 --validators 4 --byzantine 1 --bft-max-rounds 4 --bft-fault-rounds 2 --bft-round-change-backoff-ms 5 --bft-round-change-backoff-max-ms 20" \
  "$FAULTY_ROUND_BACKOFF_MAX_FINALITY_P95_MS" \
  "$FAULTY_ROUND_BACKOFF_MAX_ROUND_CHANGE_TOTAL" \
  "$FAULTY_ROUND_BACKOFF_MIN_COMMITTED_HEIGHTS" \
  "$FAULTY_ROUND_BACKOFF_MAX_RECOVERY_TIME_MS" \
  "$FAULTY_ROUND_BACKOFF_MAX_FORK_DEPTH" \
  "$FAULTY_ROUND_BACKOFF_REQUIRE_STATE_ROOT_CONSISTENT"
fi

# 6) leader jitter (proposal miss + penalty)
if case_enabled "leader_jitter"; then
run_case \
  "leader_jitter" \
  "cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 10 --max-blocks 6 --demo-tasks 8 --demo-keys 3 --parallel-workers 4 --validators 4 --byzantine 1 --bft-max-rounds 4 --bft-fault-rounds 2 --bft-missed-proposal-threshold 1 --bft-leader-penalty-rounds 2" \
  "$LEADER_JITTER_MAX_FINALITY_P95_MS" \
  "$LEADER_JITTER_MAX_ROUND_CHANGE_TOTAL" \
  "$LEADER_JITTER_MIN_COMMITTED_HEIGHTS" \
  "$LEADER_JITTER_MAX_RECOVERY_TIME_MS" \
  "$LEADER_JITTER_MAX_FORK_DEPTH" \
  "$LEADER_JITTER_REQUIRE_STATE_ROOT_CONSISTENT"
fi

# 7) message reorder / replay pressure proxy (fault rounds + tighter rounds)
if case_enabled "message_reorder"; then
run_case \
  "message_reorder" \
  "cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 8 --max-blocks 6 --demo-tasks 8 --demo-keys 3 --parallel-workers 4 --validators 4 --byzantine 1 --bft-max-rounds 3 --bft-fault-rounds 2 --bft-round-change-backoff-ms 3 --bft-round-change-backoff-max-ms 12" \
  "$MESSAGE_REORDER_MAX_FINALITY_P95_MS" \
  "$MESSAGE_REORDER_MAX_ROUND_CHANGE_TOTAL" \
  "$MESSAGE_REORDER_MIN_COMMITTED_HEIGHTS" \
  "$MESSAGE_REORDER_MAX_RECOVERY_TIME_MS" \
  "$MESSAGE_REORDER_MAX_FORK_DEPTH" \
  "$MESSAGE_REORDER_REQUIRE_STATE_ROOT_CONSISTENT"
fi

# 8) slow validator / lagging quorum proxy
if case_enabled "slow_validator"; then
run_case \
  "slow_validator" \
  "cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 20 --max-blocks 6 --demo-tasks 8 --demo-keys 3 --parallel-workers 4 --validators 4 --byzantine 1 --bft-max-rounds 4 --bft-fault-rounds 1" \
  "$SLOW_VALIDATOR_MAX_FINALITY_P95_MS" \
  "$SLOW_VALIDATOR_MAX_ROUND_CHANGE_TOTAL" \
  "$SLOW_VALIDATOR_MIN_COMMITTED_HEIGHTS" \
  "$SLOW_VALIDATOR_MAX_RECOVERY_TIME_MS" \
  "$SLOW_VALIDATOR_MAX_FORK_DEPTH" \
  "$SLOW_VALIDATOR_REQUIRE_STATE_ROOT_CONSISTENT"
fi

executed=$((pass+fail))
selection_ok=1
if [[ "$EXPECTED_CASES" -le 0 ]]; then
  selection_ok=0
fi
if [[ "$executed" -ne "$EXPECTED_CASES" ]]; then
  selection_ok=0
fi

{
  echo
  echo "global_thresholds p95<=${CONSENSUS_MAX_FINALITY_P95_MS} rc<=${CONSENSUS_MAX_ROUND_CHANGE_TOTAL} commit>=${CONSENSUS_MIN_COMMITTED_HEIGHTS} recovery_ms<=${CONSENSUS_MAX_RECOVERY_TIME_MS} fork_depth<=${CONSENSUS_MAX_FORK_DEPTH} state_root_consistent_required=${CONSENSUS_REQUIRE_STATE_ROOT_CONSISTENT}"
  echo "matrix_cases=baseline,slow_block,restart_recovery,byzantine_rounds,faulty_round_backoff,leader_jitter,message_reorder,slow_validator"
  echo "gate_mode=${GATE_MODE} allow_fail=${ALLOW_FAIL} case_filter=${CASE_FILTER} expected_cases=${EXPECTED_CASES} executed_cases=${executed}"
  echo "summary pass=$pass fail=$fail"
  if [[ "$fail" -eq 0 && "$selection_ok" -eq 1 ]]; then
    echo "status=PASS"
  else
    echo "status=FAIL"
  fi
} | tee -a "$OUT"

if [[ "$selection_ok" -ne 1 ]]; then
  echo "[FAIL] consensus fault matrix case selection mismatch: expected=${EXPECTED_CASES} executed=${executed}" >&2
  if [[ "$ALLOW_FAIL" == "1" ]]; then
    echo "[WARN] soft mode allows selection mismatch: $OUT"
    exit 0
  fi
  exit 1
fi

if [[ "$fail" -ne 0 ]]; then
  if [[ "$ALLOW_FAIL" == "1" ]]; then
    echo "[WARN] consensus fault matrix soft-fail allowed: $OUT"
    exit 0
  fi
  echo "[FAIL] consensus fault matrix: $OUT" >&2
  exit 1
fi

echo "[OK] consensus fault matrix: $OUT"