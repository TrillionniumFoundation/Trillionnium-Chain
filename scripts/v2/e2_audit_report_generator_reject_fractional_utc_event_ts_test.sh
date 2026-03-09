#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

LOG="$TMP_DIR/audit.log"
OUT="$TMP_DIR/report.json"

cat > "$LOG" <<'LOGEOF'
2026-03-03T01:02:03.123Z [event] event_schema=v1 event_type=challenge challenger_delta=-2 treasury_delta=2 note="fractional seconds must fail-closed"
2026-03-03T01:02:04Z [event] event_schema=v1 event_type=resolve challenger_delta=2 treasury_delta=-2 note="canonical"
LOGEOF

python3 "$ROOT/scripts/v2/audit_report_generator.py" "$LOG" > "$OUT"

python3 - "$OUT" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
summary = report.get('summary', {})
counts = summary.get('event_counts', {})
rows = report.get('audit_log', [])

if summary.get('total_audit_events') != 1:
    print('[FAIL] expected exactly one canonical event after fractional UTC timestamp filtering', file=sys.stderr)
    sys.exit(1)

if counts.get('challenge', 0) != 0:
    print('[FAIL] fractional-seconds timestamp must not count as challenge event', file=sys.stderr)
    sys.exit(1)

if counts.get('resolve') != 1:
    print('[FAIL] canonical resolve event missing after fractional timestamp filtering', file=sys.stderr)
    sys.exit(1)

if rows[0].get('event_ts') != '2026-03-03T01:02:04Z':
    print('[FAIL] surviving event_ts must remain canonical RFC3339 UTC (seconds precision + Z)', file=sys.stderr)
    sys.exit(1)

print('[PASS] e2_audit_report_generator_reject_fractional_utc_event_ts_test')
PY
