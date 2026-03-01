#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

LOG="$TMP_DIR/events.log"
OUT="$TMP_DIR/report.json"

cat > "$LOG" <<'LOGEOF'
2026-03-02T03:22:00Z [event] event_schema=v1 event_type=challenge challenger_delta=11 treasury_delta=-3
2026-03-02T03:22:01Z [event] event_schema=v1 event_type=resolve challenger_delta=oops treasury_delta=nan
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
# Non-numeric values must be ignored (fail-closed for arithmetic), preserving numeric rows.
assert summary["financial_impact"]["challenger_delta_total"] == 11, summary
assert summary["financial_impact"]["treasury_delta_total"] == -3, summary
print('[PASS] e2_audit_report_generator_ignore_non_numeric_financial_delta_test')
PY
