#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT/run/worker-agent"
OUT_LOG="$OUT_DIR/tx-adapter-$(date +%Y%m%d).jsonl"
mkdir -p "$OUT_DIR"

# mode:
# - mock (default): accept and persist local receipt
# - command: execute external CLI command and persist real/failed receipt
MODE="${TRNM_TX_ADAPTER_MODE:-mock}"
TX_CLI="${TRNM_TX_CLI:-}"

kind="${1:-}"
if [[ "$kind" != "commit" && "$kind" != "reveal" ]]; then
  echo "usage: $0 <commit|reveal> <task_id> <arg2> <arg3>" >&2
  exit 2
fi

ts=$(date +%s)

receipt_hash() {
  local payload="$1"
  printf "%s" "$payload" | shasum -a 256 | awk '{print $1}'
}

if [[ "$kind" == "commit" ]]; then
  task_id="${2:-}"
  worker="${3:-}"
  commit_hash="${4:-}"
  [[ -n "$task_id" && -n "$worker" && -n "$commit_hash" ]] || { echo "invalid commit args" >&2; exit 2; }

  cmd="${TX_CLI:-echo} tx commit-result $task_id $worker $commit_hash"

  if [[ "$MODE" == "command" ]]; then
    set +e
    output=$(sh -lc "$cmd" 2>&1)
    rc=$?
    set -e
    status="failed"
    [[ $rc -eq 0 ]] && status="accepted"
    tx_hash=$(receipt_hash "$kind|$task_id|$worker|$commit_hash|$ts|$output")
    printf '{"ts":%s,"mode":"%s","kind":"commit","task_id":%s,"worker":"%s","commit_hash":"%s","tx_hash":"%s","status":"%s","rc":%s}\n' \
      "$ts" "$MODE" "$task_id" "$worker" "$commit_hash" "$tx_hash" "$status" "$rc" >> "$OUT_LOG"
    if [[ $rc -ne 0 ]]; then
      echo "[adapter] commit failed task_id=$task_id rc=$rc" >&2
      echo "$output" >&2
      exit $rc
    fi
    echo "[adapter] commit accepted task_id=$task_id worker=$worker tx_hash=$tx_hash"
  else
    tx_hash=$(receipt_hash "$kind|$task_id|$worker|$commit_hash|$ts")
    printf '{"ts":%s,"mode":"%s","kind":"commit","task_id":%s,"worker":"%s","commit_hash":"%s","tx_hash":"%s","status":"accepted","rc":0}\n' \
      "$ts" "$MODE" "$task_id" "$worker" "$commit_hash" "$tx_hash" >> "$OUT_LOG"
    echo "[adapter] commit accepted task_id=$task_id worker=$worker tx_hash=$tx_hash"
  fi
else
  task_id="${2:-}"
  result_hash="${3:-}"
  salt_hex="${4:-}"
  [[ -n "$task_id" && -n "$result_hash" && -n "$salt_hex" ]] || { echo "invalid reveal args" >&2; exit 2; }

  cmd="${TX_CLI:-echo} tx reveal-result $task_id $result_hash $salt_hex"

  if [[ "$MODE" == "command" ]]; then
    set +e
    output=$(sh -lc "$cmd" 2>&1)
    rc=$?
    set -e
    status="failed"
    [[ $rc -eq 0 ]] && status="accepted"
    tx_hash=$(receipt_hash "$kind|$task_id|$result_hash|$salt_hex|$ts|$output")
    printf '{"ts":%s,"mode":"%s","kind":"reveal","task_id":%s,"result_hash":"%s","salt_hex":"%s","tx_hash":"%s","status":"%s","rc":%s}\n' \
      "$ts" "$MODE" "$task_id" "$result_hash" "$salt_hex" "$tx_hash" "$status" "$rc" >> "$OUT_LOG"
    if [[ $rc -ne 0 ]]; then
      echo "[adapter] reveal failed task_id=$task_id rc=$rc" >&2
      echo "$output" >&2
      exit $rc
    fi
    echo "[adapter] reveal accepted task_id=$task_id tx_hash=$tx_hash"
  else
    tx_hash=$(receipt_hash "$kind|$task_id|$result_hash|$salt_hex|$ts")
    printf '{"ts":%s,"mode":"%s","kind":"reveal","task_id":%s,"result_hash":"%s","salt_hex":"%s","tx_hash":"%s","status":"accepted","rc":0}\n' \
      "$ts" "$MODE" "$task_id" "$result_hash" "$salt_hex" "$tx_hash" >> "$OUT_LOG"
    echo "[adapter] reveal accepted task_id=$task_id tx_hash=$tx_hash"
  fi
fi
