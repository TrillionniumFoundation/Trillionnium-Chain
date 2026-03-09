#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GEN="$ROOT/scripts/v2/audit_report_generator.py"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

LOG="$TMP_DIR/events.log"
cat >"$LOG" <<'LOGEOF'
2026-03-04T12:00:00Z [event] event_schema=v1 event_type=Resolve challenger_delta=5 treasury_delta=-5 note="mixed-case event type should be ignored"
2026-03-04T12:00:01Z [event] event_schema=v1 event_type=resolve challenger_delta=3 treasury_delta=-3 note="canonical lowercase event type"
LOGEOF

REPORT="$TMP_DIR/report.json"
python3 "$GEN" "$LOG" > "$REPORT"

python3 - "$REPORT" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text())
summary = report["summary"]
audit_log = report["audit_log"]
counts = summary["event_counts"]

if summary["total_audit_events"] != 1:
    print('[FAIL] expected exactly one canonical audit event after mixed-case event_type filtering', file=sys.stderr)
    sys.exit(1)

if counts.get("Resolve", 0) != 0:
    print('[FAIL] mixed-case event_type token must not be counted', file=sys.stderr)
    sys.exit(1)

if counts.get("resolve") != 1:
    print('[FAIL] expected lowercase resolve event to be counted', file=sys.stderr)
    sys.exit(1)

if len(audit_log) != 1 or audit_log[0].get("event_type") != "resolve":
    print('[FAIL] expected audit_log to contain only lowercase canonical resolve event', file=sys.stderr)
    sys.exit(1)

impact = summary["financial_impact"]
if impact.get("challenger_delta_total") != 3 or impact.get("treasury_delta_total") != -3:
    print('[FAIL] financial impact should include only canonical lowercase event_type entries', file=sys.stderr)
    sys.exit(1)

print('[PASS] e2_audit_report_generator_reject_mixedcase_event_type_test')
PY
