#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

LOG="$TMP_DIR/events.log"
OUT="$TMP_DIR/report.json"

cat > "$LOG" <<'LOGEOF'
2026-03-01T06:40:00Z [event] event_schema=v1 event_type=challenge challenger_delta=-5 treasury_delta=2 note="first dispute"
2026-03-01T06:40:01Z [event] event_schema=v1 event_type=resolve challenger_delta=10 treasury_delta=-1 note="resolved by committee"
2026-03-01T06:40:02Z [event] event_schema=v1 event_type=heartbeat challenger_delta=99 treasury_delta=99 note="non-audit event"
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
assert summary["event_counts"]["challenge"] == 1, summary
assert summary["event_counts"]["resolve"] == 1, summary
assert summary["financial_impact"]["challenger_delta_total"] == 5, summary
assert summary["financial_impact"]["treasury_delta_total"] == 1, summary

notes = [row.get("note") for row in report["audit_log"]]
assert notes == ["first dispute", "resolved by committee"], notes
print("[PASS] e2_audit_report_generator_quoted_values_test")
PY
