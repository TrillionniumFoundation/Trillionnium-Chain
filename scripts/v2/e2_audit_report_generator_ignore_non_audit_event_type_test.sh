#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

LOG="$TMP_DIR/events.log"
OUT="$TMP_DIR/report.json"

cat > "$LOG" <<'LOGEOF'
2026-03-02T02:10:00Z [event] event_schema=v1 event_type=heartbeat challenger_delta=-99 treasury_delta=99 note="non-audit operational heartbeat"
2026-03-02T02:10:01Z [event] event_schema=v1 event_type=resolve challenger_delta=5 treasury_delta=-2 note="audit-worthy"
LOGEOF

python3 "$ROOT/scripts/v2/audit_report_generator.py" "$LOG" > "$OUT"

python3 - "$OUT" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
summary = report.get('summary', {})
rows = report.get('audit_log', [])

if summary.get('total_audit_events') != 1:
    print('[FAIL] expected only audit allowlist event_type to be included', file=sys.stderr)
    sys.exit(1)

if rows[0].get('event_type') != 'resolve':
    print('[FAIL] expected resolve to be retained as audit event', file=sys.stderr)
    sys.exit(1)

impact = summary.get('financial_impact', {})
if impact.get('challenger_delta_total') != 5 or impact.get('treasury_delta_total') != -2:
    print('[FAIL] financial impact should only include audit allowlist event', file=sys.stderr)
    sys.exit(1)

print('[PASS] e2_audit_report_generator_ignore_non_audit_event_type_test')
PY
