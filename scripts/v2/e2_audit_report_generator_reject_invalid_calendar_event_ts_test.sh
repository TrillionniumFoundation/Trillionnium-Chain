#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
GEN="$ROOT/scripts/v2/audit_report_generator.py"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

LOG="$TMP_DIR/audit.log"
OUT="$TMP_DIR/report.json"

cat > "$LOG" <<'LOGEOF'
2026-02-30T10:11:12Z [event] event_schema=v1 event_type=resolve task_id=task-1
2026-02-28T10:11:12Z [event] event_schema=v1 event_type=resolve task_id=task-2
LOGEOF

python3 "$GEN" "$LOG" > "$OUT"

python3 - "$OUT" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
summary = report.get('summary', {})
rows = report.get('audit_log', [])

if summary.get('total_audit_events') != 1:
    print('[FAIL] expected only one valid calendar timestamp event', file=sys.stderr)
    sys.exit(1)

if len(rows) != 1 or rows[0].get('task_id') != 'task-2':
    print('[FAIL] expected only task-2 to remain after invalid calendar timestamp filtering', file=sys.stderr)
    sys.exit(1)

print('[PASS] e2_audit_report_generator_reject_invalid_calendar_event_ts_test')
PY
