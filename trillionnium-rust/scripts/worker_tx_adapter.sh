#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT/run/worker-agent"
OUT_LOG="$OUT_DIR/tx-adapter-$(date +%Y%m%d).jsonl"
mkdir -p "$OUT_DIR"

kind="${1:-}"
if [[ "$kind" != "commit" && "$kind" != "reveal" ]]; then
  echo "usage: $0 <commit|reveal> <task_id> <arg2> <arg3>" >&2
  exit 2
fi

ts=$(date +%s)
if [[ "$kind" == "commit" ]]; then
  task_id="${2:-}"
  worker="${3:-}"
  commit_hash="${4:-}"
  [[ -n "$task_id" && -n "$worker" && -n "$commit_hash" ]] || { echo "invalid commit args" >&2; exit 2; }
  printf '{"ts":%s,"kind":"commit","task_id":%s,"worker":"%s","commit_hash":"%s","status":"accepted"}\n' "$ts" "$task_id" "$worker" "$commit_hash" >> "$OUT_LOG"
  echo "[adapter] commit accepted task_id=$task_id worker=$worker"
else
  task_id="${2:-}"
  result_hash="${3:-}"
  salt_hex="${4:-}"
  [[ -n "$task_id" && -n "$result_hash" && -n "$salt_hex" ]] || { echo "invalid reveal args" >&2; exit 2; }
  printf '{"ts":%s,"kind":"reveal","task_id":%s,"result_hash":"%s","salt_hex":"%s","status":"accepted"}\n' "$ts" "$task_id" "$result_hash" "$salt_hex" >> "$OUT_LOG"
  echo "[adapter] reveal accepted task_id=$task_id"
fi
