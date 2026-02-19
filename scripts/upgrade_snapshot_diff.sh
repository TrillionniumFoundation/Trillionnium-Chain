#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/data/upgrade-diff}"
mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$OUT_DIR/$TS"
mkdir -p "$RUN_DIR"

BIN="${BIN:-$ROOT/build/chaind}"
HOME_DIR="${HOME_DIR:-/Users/qianqi/.chain}"
NODE="${NODE:-tcp://127.0.0.1:26657}"

PRE_PARAMS="${PRE_PARAMS:-$ROOT/data/upgrade-pre-params.json}"
PRE_TASK="${PRE_TASK:-$ROOT/data/upgrade-pre-task.json}"
PRE_CHALLENGE="${PRE_CHALLENGE:-$ROOT/data/upgrade-pre-challenge.json}"

POST_PARAMS="$RUN_DIR/post-params.json"
POST_TASK="$RUN_DIR/post-task.json"
POST_CHALLENGE="$RUN_DIR/post-challenge.json"
SUMMARY="$RUN_DIR/summary.txt"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1"; exit 1; }; }
need python3
need diff

$BIN query workload params -o json --home "$HOME_DIR" --node "$NODE" > "$POST_PARAMS"
$BIN query workload list-task -o json --home "$HOME_DIR" --node "$NODE" > "$POST_TASK"
$BIN query workload list-challenge -o json --home "$HOME_DIR" --node "$NODE" > "$POST_CHALLENGE"

normalize_json() {
  local f="$1"
  python3 - <<PY
import json
obj=json.load(open('$f'))
print(json.dumps(obj,sort_keys=True,ensure_ascii=False,indent=2))
PY
}

pp() {
  local src="$1" dst="$2"
  if [[ -f "$src" ]]; then
    normalize_json "$src" > "$dst"
  else
    echo "{}" > "$dst"
  fi
}

pp "$PRE_PARAMS" "$RUN_DIR/pre-params.pretty.json"
pp "$PRE_TASK" "$RUN_DIR/pre-task.pretty.json"
pp "$PRE_CHALLENGE" "$RUN_DIR/pre-challenge.pretty.json"
pp "$POST_PARAMS" "$RUN_DIR/post-params.pretty.json"
pp "$POST_TASK" "$RUN_DIR/post-task.pretty.json"
pp "$POST_CHALLENGE" "$RUN_DIR/post-challenge.pretty.json"

set +e
diff -u "$RUN_DIR/pre-params.pretty.json" "$RUN_DIR/post-params.pretty.json" > "$RUN_DIR/diff-params.patch"
rc_params=$?
diff -u "$RUN_DIR/pre-task.pretty.json" "$RUN_DIR/post-task.pretty.json" > "$RUN_DIR/diff-task.patch"
rc_task=$?
diff -u "$RUN_DIR/pre-challenge.pretty.json" "$RUN_DIR/post-challenge.pretty.json" > "$RUN_DIR/diff-challenge.patch"
rc_chal=$?
set -e

{
  echo "Upgrade snapshot diff @ $TS"
  echo "run_dir=$RUN_DIR"
  echo ""
  echo "params_diff_rc=$rc_params"
  echo "task_diff_rc=$rc_task"
  echo "challenge_diff_rc=$rc_chal"
  echo ""
  echo "Artifacts:"
  echo "- $RUN_DIR/diff-params.patch"
  echo "- $RUN_DIR/diff-task.patch"
  echo "- $RUN_DIR/diff-challenge.patch"
} | tee "$SUMMARY"

echo "SUMMARY=$SUMMARY"
