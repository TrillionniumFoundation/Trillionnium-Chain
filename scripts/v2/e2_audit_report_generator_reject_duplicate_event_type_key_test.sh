#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

LOG="$TMP_DIR/audit.log"
OUT="$TMP_DIR/report.json"

cat > "$LOG" <<'EOF'
2026-03-04T05:00:00Z [event] event_schema=v1 event_type=slash challenger_delta=-5 treasury_delta=5
2026-03-04T05:00:01Z [event] event_schema=v1 event_type=slash event_type=challenge challenger_delta=-7 treasury_delta=7
EOF

python3 "$ROOT/scripts/v2/audit_report_generator.py" "$LOG" > "$OUT"

python3 - "$OUT" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
summary = report.get('summary', {})

if summary.get('total_audit_events') != 1:
    print('[FAIL] duplicate event_type key line must be rejected', file=sys.stderr)
    sys.exit(1)

counts = summary.get('event_counts', {})
if counts.get('slash') != 1 or len(counts) != 1:
    print('[FAIL] expected only canonical single-key slash event to remain', file=sys.stderr)
    sys.exit(1)

if summary.get('financial_impact', {}).get('challenger_delta_total') != -5:
    print('[FAIL] challenger_delta_total should exclude duplicate-key event', file=sys.stderr)
    sys.exit(1)

if summary.get('financial_impact', {}).get('treasury_delta_total') != 5:
    print('[FAIL] treasury_delta_total should exclude duplicate-key event', file=sys.stderr)
    sys.exit(1)

print('[PASS] e2_audit_report_generator_reject_duplicate_event_type_key_test')
PY
