#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

LOG="$TMP_DIR/events.log"
OUT="$TMP_DIR/report.json"

cat > "$LOG" <<'LOGEOF'
2026-03-01T07:20:00Z [event] event_schema=v1 event_type=challenge challenger_delta=-6 treasury_delta=2 note="kv=a=b and quote=\"ok\""
2026-03-01T07:20:05Z [event] event_schema=v1 event_type=resolve challenger_delta=8 treasury_delta=-1 note="finalized"
LOGEOF

python3 "$ROOT/scripts/v2/audit_report_generator.py" "$LOG" > "$OUT"

python3 - "$OUT" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, 'r', encoding='utf-8') as f:
    report = json.load(f)

summary = report["summary"]
assert summary["total_audit_events"] == 2, summary
assert summary["financial_impact"]["challenger_delta_total"] == 2, summary
assert summary["financial_impact"]["treasury_delta_total"] == 1, summary

rows = report["audit_log"]
assert rows[0]["note"] == 'kv=a=b and quote="ok"', rows[0]
assert rows[0]["event_ts"] == "2026-03-01T07:20:00Z", rows[0]
print("[PASS] e2_audit_report_generator_note_equals_escape_test")
PY
