#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_DIR="${RUN_DIR:-$ROOT/run/pr7-topn/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$RUN_DIR"

EVENT_LOG="${EVENT_LOG:-$ROOT/trillionnium/run/event-field-check.log}"
TOP_N="${TOP_N:-5}"
OUT_MD="$RUN_DIR/topn-anomaly-summary.md"
GATE_REPORT="$RUN_DIR/summary.txt"

if [[ ! "$TOP_N" =~ ^[1-9][0-9]*$ ]]; then
  {
    echo "status=FAIL"
    echo "reason=invalid_top_n"
    echo "top_n=$TOP_N"
  } > "$GATE_REPORT"
  cat "$GATE_REPORT"
  exit 2
fi

latest_pr5_json="$(python3 - <<'PY' "$ROOT"
import glob
import os
import sys

root = sys.argv[1]
candidates = glob.glob(os.path.join(root, "run", "pr5-reconcile", "*", "reconcile.json"))
files = [p for p in candidates if os.path.isfile(p)]
if files:
    # Deterministic winner: newest mtime, then lexical path when mtimes tie.
    print(max(files, key=lambda p: (os.path.getmtime(p), p)))
PY
)"
if [[ -z "$latest_pr5_json" ]]; then
  latest_pr5_json="$ROOT/run/pr5-reconcile/latest/reconcile.json"
fi

python3 "$ROOT/scripts/v2/pr7_topn_anomaly_summary.py" \
  --event-log "$EVENT_LOG" \
  --pr5-reconcile-json "$latest_pr5_json" \
  --top-n "$TOP_N" \
  --out "$OUT_MD"

if [[ ! -s "$OUT_MD" ]]; then
  echo "status=FAIL" > "$GATE_REPORT"
  echo "reason=summary_not_generated" >> "$GATE_REPORT"
  echo "out=$OUT_MD" >> "$GATE_REPORT"
  cat "$GATE_REPORT"
  exit 2
fi

for section in "# PR-7 TopN Anomaly Summary" "## TopN Unresolved Tasks" "## TopN Forfeit Spikes (by UTC day)" "## TopN Escrow Lingering"; do
  if ! grep -Fq "$section" "$OUT_MD"; then
    echo "status=FAIL" > "$GATE_REPORT"
    echo "reason=missing_section" >> "$GATE_REPORT"
    echo "section=$section" >> "$GATE_REPORT"
    echo "out=$OUT_MD" >> "$GATE_REPORT"
    cat "$GATE_REPORT"
    exit 3
  fi
done

{
  echo "status=PASS"
  echo "event_log=$EVENT_LOG"
  echo "pr5_reconcile_json=$latest_pr5_json"
  echo "top_n=$TOP_N"
  echo "summary_md=$OUT_MD"
} > "$GATE_REPORT"

cat "$GATE_REPORT"
echo "[PR7][topn-summary-gate] status=PASS report=$GATE_REPORT"
