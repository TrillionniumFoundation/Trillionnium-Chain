#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr6-policy-binding.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

POLICY_FILE="$TMP_DIR/policy.json"
EVENT_LOG="$TMP_DIR/events.log"
RUN_DIR="$TMP_DIR/run"

python3 - "$ROOT/config/alert-policy/current.json" "$POLICY_FILE" <<'PY'
import json
import sys
from pathlib import Path

doc = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
thresholds = doc["profiles"]["default"]["thresholds"]
thresholds["unresolved_challenges"] = {"warn": 4, "fail": 6}
thresholds["forfeits_daily_increase"] = {"warn": 1000, "fail": 2000}
thresholds["escrow_nonzero_hours"] = {"warn": 1000.0, "fail": 2000.0}
Path(sys.argv[2]).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
PY

for task_id in 1 2 3 4 5; do
  printf '[event] event_type=challenge task_id=%s ts_unix_ms=0 block_height=%s challenger_delta=-1 bond_disposition=locked tx_hash=tx%s\n' \
    "$task_id" "$task_id" "$task_id" >>"$EVENT_LOG"
done

RUN_DIR="$RUN_DIR" \
EVENT_LOG="$EVENT_LOG" \
ALERT_POLICY_FILE="$POLICY_FILE" \
  "$ROOT/scripts/v2/pr6_alert_rules_gate.sh" >/dev/null

REPORT="$RUN_DIR/summary.txt"
grep -q '^status=WARN$' "$REPORT"
grep -q '^rule.unresolved_challenges.warn_threshold=4$' "$REPORT"
grep -q '^rule.unresolved_challenges.fail_threshold=6$' "$REPORT"

echo "[PASS] PR6 gate applies resolved canonical policy thresholds before evaluation"
